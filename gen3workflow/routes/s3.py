from datetime import datetime, timezone
import hashlib
import traceback
import urllib.parse

import boto3
from fastapi import APIRouter, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials
from botocore.credentials import Credentials
import hmac
from starlette.datastructures import Headers
from starlette.responses import Response
from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
)

from gen3workflow import aws_utils, logger
from gen3workflow.auth import Auth
from gen3workflow.config import config
from gen3workflow.routes.system import get_status


s3_root_router = APIRouter(include_in_schema=False)
s3_router = APIRouter(prefix="/s3")


async def set_access_token_and_get_user_id(auth: Auth, headers: Headers) -> str:
    """
    Extract the user's access token and (in some cases) the user's ID, which should have been
    provided as the access key ID, from the Authorization header.
    Return the user's ID extracted from the key ID or from the decoded token.
    Also set the provided `auth` instance's `bearer_token` to the extracted access token.

    The Authorization header should be in one of the two following expected formats:
    1. Set by the python boto3 AWS client: `AWS4-HMAC-SHA256 Credential=<key ID>/<date>/
       <region>/<service>/aws4_request, SignedHeaders=<...>, Signature=<...>`
    2. Set by Funnel GenericS3 through the Minio-go client: `AWS <key ID>:<...>`

    The key ID should be in one of the two following expected formats:
    A. Request made by a user: `<user's access token>`
    B. Request made by a client on behalf of a user:
       `<client's `client_credentials` access token>;userId=<user ID>`

    Args:
        auth (Auth): Gen3Workflow auth instance
        headers (Headers): request headers

    Returns:
        str: the user's ID
    """
    auth_header = headers.get("authorization")
    if not auth_header:
        err_msg = "No Authorization header"
        logger.error(f"{err_msg}")
        raise HTTPException(HTTP_401_UNAUTHORIZED, err_msg)
    if auth_header.lower().startswith("bearer"):
        err_msg = f"Bearer tokens in the authorization header are not supported by this endpoint, which expects signed S3 requests. The recommended way to use this endpoint is to use an AWS library, SDK or CLI"
        logger.error(err_msg)
        raise HTTPException(HTTP_401_UNAUTHORIZED, err_msg)

    # extract the key ID from the authorization header
    try:
        if "Credential=" in auth_header:  # format 1 (see docstring)
            access_key_id = auth_header.split("Credential=")[1].split("/")[0]
        else:  # format 2 (see docstring)
            access_key_id = auth_header.split("AWS ")[1].split(":")[0]
    except Exception as e:
        err_msg = "Unexpected format; unable to extract access token from authorization header"
        logger.error(f"{err_msg}: {e}")
        raise HTTPException(HTTP_401_UNAUTHORIZED, err_msg)

    # extract the access token from the key ID
    is_user_token = ";userId=" not in access_key_id
    if is_user_token:  # format A (see docstring)
        access_token = access_key_id
    else:  # format B (see docstring)
        access_token, user_id = access_key_id.split(";userId=")

    # set the token so we can perform authn/authz checks on it
    auth.bearer_token = HTTPAuthorizationCredentials(
        scheme="bearer", credentials=access_token
    )

    # ensure token validity
    token_claims = await auth.get_token_claims()
    sub = token_claims.get("sub")
    if is_user_token:
        user_id = sub
    else:
        client_id = token_claims.get("azp")
        if not client_id:
            # Format B (see docstring) should only be used by clients acting on behalf of a user.
            # It is not a valid format if the token is not linked to a client.
            err_msg = f"No client ID in token"
            logger.error(f"{err_msg}. Debug: {token_claims=}")
            raise HTTPException(HTTP_401_UNAUTHORIZED, err_msg)
        if sub:
            # OIDC tokens linked to both a user and a client are supported in the case of a user
            # key ID (format A). In the case of a client key ID (format B), they are not:
            # - Ambiguity: we would need to decide which of `sub` (from token_claims) and `user_id`
            #   (from access_key_id) should be trusted as the user ID.
            # - There is no use case for it: format B was specifically designed for use cases where
            #   the token comes from a `client_credentials` flow and does not include a user ID
            #   (`sub`). In this flow, the client must declare the user they are acting on behalf of
            #   via the `;userId=` suffix in the key ID.
            err_msg = f"Expected a client token not linked to a user, but found {client_id=} and {sub=}"
            logger.error(err_msg)
            raise HTTPException(HTTP_401_UNAUTHORIZED, err_msg)
    if not user_id:
        err_msg = f"No user ID in token or key ID"
        logger.error(f"{err_msg}. Debug: {is_user_token=} {token_claims=}")
        raise HTTPException(HTTP_401_UNAUTHORIZED, err_msg)

    return user_id


def get_signature_key(key: str, date: str, region_name: str, service_name: str) -> str:
    """
    Create a signing key using the AWS Signature Version 4 algorithm.
    """
    key_date = hmac.new(
        f"AWS4{key}".encode("utf-8"), date.encode("utf-8"), hashlib.sha256
    ).digest()
    key_region = hmac.new(
        key_date, region_name.encode("utf-8"), hashlib.sha256
    ).digest()
    key_service = hmac.new(
        key_region, service_name.encode("utf-8"), hashlib.sha256
    ).digest()
    key_signing = hmac.new(key_service, b"aws4_request", hashlib.sha256).digest()
    return key_signing


def chunked_to_non_chunked_body(body: str, stream_type: str) -> str:
    """
    Turn a chunked body into a non-chunked body.

    Strip and return the data without the chunk signatures.
    """
    if stream_type == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD":
        # Each chunk is:
        #     <chunk-size-in-hex>;chunk-signature=<sig>\r\n
        #     <chunk-data>\r\n
        # Final chunk:
        #     0;chunk-signature=<sig>\r\n\r\n
        return b"".join(
            [e for e in body.split(b"\r\n") if b";chunk-signature=" not in e]
        )
    # elif stream_type == "STREAMING-UNSIGNED-PAYLOAD-TRAILER":
    #     # Each chunk is:
    #     #     <chunk-size-in-hex>\r\n
    #     #     <chunk-data>\r\n
    #     # Final chunk:
    #     #     0\r\n
    #     #     x-amz-checksum-<hash algorithm>:<checksum of entire payload>\r\n
    #     #     \r\n
    #     return b"".join(
    #         [e for e in body.split(b"\r\n") if e and b"x-amz-checksum" not in e][1::2]
    #     )
    else:
        return body


@s3_root_router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "HEAD"],
)
@s3_router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "HEAD"],
)
async def s3_endpoint(path: str, request: Request):
    """
    Receive incoming signed S3 requests, re-sign them (AWS Signature Version 4 algorithm) with the
    appropriate credentials to access the current user's AWS S3 bucket, and forward them to
    AWS S3. The recommended way to use this endpoint is to use an AWS library, SDK or CLI.

    The S3 endpoint is exposed at `/s3` as well as at the root `/` to support S3 clients that do
    not support S3 endpoints with a path, such as the Minio-go S3 client.
    """

    # because this endpoint is exposed at root, if the GET path is empty, assume the user is not
    # trying to reach the S3 endpoint and redirect to the status endpoint instead
    if request.method == "GET" and not path:
        return await get_status(request)

    # extract the caller's access token from the request headers, and ensure the caller (user, or
    # client acting on behalf of the user) has access to run workflows
    auth = Auth(api_request=request)
    user_id = await set_access_token_and_get_user_id(auth, request.headers)
    await auth.authorize("create", ["/services/workflow/gen3-workflow/tasks"])

    # get the name of the user's bucket and ensure the user is making a call to their own bucket
    logger.info(f"Incoming S3 request from user '{user_id}': '{request.method} {path}'")
    user_bucket = aws_utils.get_safe_name_from_hostname(user_id)
    request_bucket = path.split("?")[0].split("/")[0]
    if request_bucket != user_bucket:
        err_msg = f"'{path}' (bucket '{request_bucket}') not allowed. You can make calls to your personal bucket, '{user_bucket}'"
        logger.error(err_msg)
        raise HTTPException(HTTP_403_FORBIDDEN, err_msg)

    # extract the request path (used in the canonical request) and the API endpoint (used to make
    # the request to AWS).
    # Examples of use cases we need to handle:
    # - path = my-bucket//
    #   request_path = //
    #   api_endpoint = /
    # - path = my-bucket
    #   request_path = /
    #   api_endpoint =
    # - path = my-bucket/pre/fix/
    #   request_path = /pre/fix/
    #   api_endpoint = pre/fix/
    # - path = my-bucket/pre/fix/file.txt
    #   request_path = /pre/fix/file.txt
    #   api_endpoint = pre/fix/file.txt
    request_path = path.split(user_bucket)[1] or "/"
    api_endpoint = "/".join(request_path.split("/")[1:])

    region = config["USER_BUCKETS_REGION"]
    service = "s3"

    timestamp = request.headers.get("x-amz-date")
    if not timestamp and request.headers.get("date"):
        # assume RFC 1123 format, convert to ISO 8601 basic YYYYMMDD'T'HHMMSS'Z' format
        dt = datetime.strptime(request.headers["date"], "%a, %d %b %Y %H:%M:%S %Z")
        timestamp = dt.strftime("%Y%m%dT%H%M%SZ")
    if not timestamp:
        # no `x-amz-date` or `date` header, just generate it ourselves
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    date = timestamp[:8]  # the date portion (YYYYMMDD) of the timestamp

    # Generate the body hash and the request headers.
    # Overwrite the original `x-amz-content-sha256` header value with the body hash. When this
    # header is set to "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" in the original request (payload sent
    # over multiple chunks), we still replace it with the body hash and we strip the body of the
    # chunk signatures => protocol translation from a chunk-signed streaming request (SigV4
    # streaming HTTP PUT) into a single-payload request (Normal SigV4 HTTP PUT). We could also
    # implement chunked signing but it's not straightforward and likely unnecessary.
    # NOTE: Chunked uploads and multipart uploads are NOT the same thing. Python boto3 does not
    # generate chunked uploads, but the Minio-go S3 client used by Funnel does.
    # TODO update ^
    body = await request.body()
    body = chunked_to_non_chunked_body(
        body, request.headers.get("x-amz-content-sha256")
    )

    body_hash = (
        hashlib.sha256(body).hexdigest()
        if request.headers.get("x-amz-content-sha256")
        != "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
        else "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
    )
    headers = {
        "host": f"{user_bucket}.s3.{region}.amazonaws.com",
        "x-amz-content-sha256": body_hash,
        "x-amz-date": timestamp,
    }
    for h in ["x-amz-trailer", "content-encoding", "Content-Length"]:
        if request.headers.get(h):
            headers[h] = request.headers[h]

    # get AWS credentials from the configuration or the current assumed role session
    if config["S3_ENDPOINTS_AWS_ACCESS_KEY_ID"]:
        credentials = Credentials(
            access_key=config["S3_ENDPOINTS_AWS_ACCESS_KEY_ID"],
            secret_key=config["S3_ENDPOINTS_AWS_SECRET_ACCESS_KEY"],
        )
    else:  # assume the service is running in k8s: get credentials from the assumed role
        session = boto3.Session()
        credentials = session.get_credentials()
        assert credentials, "No AWS credentials found"
        headers["x-amz-security-token"] = credentials.token

    # if this is a PUT request, we need the KMS key ID to use for encryption
    if config["KMS_ENCRYPTION_ENABLED"] and request.method == "PUT":
        _, kms_key_arn = aws_utils.get_existing_kms_key_for_bucket(user_bucket)
        if not kms_key_arn:
            err_msg = "Bucket misconfigured. Hit the `GET /storage/info` endpoint and try again."
            logger.error(
                f"No existing KMS key found for bucket '{user_bucket}'. {err_msg}"
            )
            raise HTTPException(HTTP_400_BAD_REQUEST, err_msg)
        headers["x-amz-server-side-encryption"] = "aws:kms"
        headers["x-amz-server-side-encryption-aws-kms-key-id"] = kms_key_arn

    # construct the canonical request
    # lowercase_sorted_headers = sorted([k.lower() for k in headers.keys()])
    lowercase_sorted_headers = sorted([k for k in headers.keys()], key=str.casefold)
    canonical_headers = "".join(
        f"{key}:{headers[key]}\n" for key in lowercase_sorted_headers
    )
    signed_headers = ";".join(lowercase_sorted_headers)
    query_params = dict(request.query_params)
    # the query params in the canonical request have to be sorted:
    query_params_names = sorted(list(query_params.keys()))
    canonical_query_params = "&".join(
        f"{urllib.parse.quote_plus(key)}={urllib.parse.quote_plus(query_params[key])}"
        for key in query_params_names
    )
    canonical_request = (
        f"{request.method}\n"
        f"{request_path}\n"
        f"{canonical_query_params}\n"
        f"{canonical_headers}"
        f"\n"
        f"{signed_headers}\n"
        f"{body_hash}"
    )
    print("=============")
    print("canonical_request:", canonical_request)
    print("=============")

    # construct the string to sign based on the canonical request
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n"
        f"{timestamp}\n"
        f"{date}/{region}/{service}/aws4_request\n"  # credential scope
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"  # canonical request hash
    )

    # generate the signing key, and generate the signature by signing the string to sign with the
    # signing key
    signing_key = get_signature_key(credentials.secret_key, date, region, service)
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    # AWS is case sensitive about the Content-Length header, but v4 signing
    # requires lowercase headers (hence use of `lowercase_sorted_headers` var)
    # content_length = headers.get("content-length")
    # if content_length:
    #     headers.pop("content-length")
    #     headers["Content-Length"] = content_length

    # construct the Authorization header from the credentials and the signature, and forward the
    # call to AWS S3 with the new Authorization header
    print("=============")
    print("headers:")
    for k, v in headers.items():
        print(f"  {k}: {v}")
    print("=============")
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={credentials.access_key}/{date}/{region}/{service}/aws4_request, SignedHeaders={signed_headers}, Signature={signature}"
    )
    s3_api_url = f"https://{user_bucket}.s3.{region}.amazonaws.com/{api_endpoint}"
    logger.debug(f"Outgoing S3 request: '{request.method} {s3_api_url}'")

    # TODO: Enclose this with a retry if S3 response with a 500 error (which is possible! Failing
    # fast can break a whole nextflow workflow)
    response = await request.app.async_client.request(
        method=request.method,
        url=s3_api_url,
        headers=headers,
        params=query_params,
        data=body,
    )

    if response.status_code >= 300:
        logger.debug(f"Received a failure status code from AWS: {response.status_code}")
        # no need to log 404 errors except in debug mode: they are are expected when running
        # workflows (e.g. for Nextflow workflows, error output files may not be present when there
        # were no errors)
        if response.status_code != 404:
            logger.error(f"Error from AWS: {response.status_code} {response.text}")

    # return the response from AWS S3.
    # - mask the details of 403 errors from the end user: authentication is done internally by this
    # function, so 403 errors are internal service errors
    # - return all the headers from the AWS response, except `x-amz-bucket-region` which for some
    # reason causes this error for tasks ran through Nextflow: `The AWS Access Key Id you provided
    # does not exist in our records`
    return Response(
        content=(
            response.content if response.status_code != HTTP_403_FORBIDDEN else None
        ),
        status_code=response.status_code,
        headers={
            k: v for k, v in response.headers.items() if k != "x-amz-bucket-region"
        },
    )
