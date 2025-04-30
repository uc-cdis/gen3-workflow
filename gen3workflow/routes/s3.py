import hashlib
from typing import Tuple
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


root_router = APIRouter()
s3_router = APIRouter(prefix="/s3")


def get_access_token(headers: Headers) -> Tuple[str, str]:
    """
    Extract the user's access token and (in the case of a client token) the user's ID, which
    should have been provided as the key ID, from the Authorization header in one of the two
    following expected formats:
    1. Key ID set by the python boto3 AWS client: `AWS4-HMAC-SHA256 Credential=<key ID>/<date>/
    <region>/<service>/aws4_request, SignedHeaders=<>, Signature=<>`
    2. Key ID set by Funnel GenericS3 through the Minio-go client: `AWS <key ID>:<>`

    Args:
        headers (Headers): request headers

    Returns:
        (str, str): the user's access token or "" if not found, and the user's ID if the token is
        a client_credentials token
    """
    auth_header = headers.get("authorization")
    logger.info(f"DEBUG: auth_header = {auth_header}")
    if not auth_header:
        return "", ""
    if auth_header.lower().startswith("bearer"):
        err_msg = f"Bearer tokens in the authorization header are not supported by this endpoint, which expects signed S3 requests. The recommended way to use this endpoint is to use the AWS SDK or CLI"
        logger.error(err_msg)
        raise HTTPException(HTTP_401_UNAUTHORIZED, err_msg)
    try:
        if "Credential=" in auth_header:  # format 1 (see docstring)
            access_key_id = auth_header.split("Credential=")[1].split("/")[0]
        else:  # format 2 (see docstring)
            access_key_id = auth_header.split("AWS ")[1]
            access_key_id = ":".join(access_key_id.split(":")[:-1])
        logger.info(f"DEBUG: access_key_id = {access_key_id}")
        access_token, user_id = access_key_id.split(";userId=")
        logger.info(f"DEBUG: access_token = {access_token}")
        logger.info(f"DEBUG: user_id = {user_id}")
        return access_token, user_id
    except Exception as e:
        logger.error(
            f"Unexpected format; unable to extract access token from authorization header: {e}"
        )
        return "", ""


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


@root_router.api_route(
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
    AWS S3. The recommended way to use this endpoint is to use the AWS SDK or CLI.

    The S3 endpoint is exposed at `/s3` as well as at the root `/` because S3 clients like Minio do
    not support S3 endpoints with a path.
    """

    # because this endpoint is exposed at root, if the path is empty, assume the user is not trying
    # to reach the S3 endpoint and redirect to the status endpoint instead
    if request.method == "GET" and not path:
        return await get_status(request)

    # extract the user's access token from the request headers, and ensure the user has access
    # to run workflows
    auth = Auth(api_request=request)
    access_token, user_id = get_access_token(request.headers)
    if user_id:
        pass  # TODO assert it's a client token not linked to a user, and check authz
    else:
        auth.bearer_token = HTTPAuthorizationCredentials(
            scheme="bearer", credentials=access_token
        )
        await auth.authorize("create", ["/services/workflow/gen3-workflow/tasks"])
        token_claims = await auth.get_token_claims()
        user_id = token_claims.get("sub")

    # get the name of the user's bucket and ensure the user is making a call to their own bucket
    logger.info(f"Incoming S3 request from user '{user_id}': '{request.method} {path}'")
    user_bucket = aws_utils.get_safe_name_from_hostname(user_id)
    request_bucket = path.split("?")[0].split("/")[0]
    if request_bucket != user_bucket:
        err_msg = f"'{path}' not allowed. You can make calls to your personal bucket, '{user_bucket}'"
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

    body = await request.body()
    body_hash = hashlib.sha256(body).hexdigest()
    timestamp = request.headers["x-amz-date"]
    date = timestamp[:8]  # the date portion (YYYYMMDD) of the timestamp
    region = config["USER_BUCKETS_REGION"]
    service = "s3"

    # generate the request headers.
    # overwrite the original `x-amz-content-sha256` header value with the body hash. When this
    # header is set to "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" in the original request (payload sent
    # over multiple chunks), we still replace it with the body hash (because I couldn't get the
    # signing to work for "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" - I believe it requires using the signature from the previous chunk).
    # NOTE: This may cause issues when large files are _actually_ uploaded over multiple chunks.
    headers = {
        "host": f"{user_bucket}.s3.amazonaws.com",
        "x-amz-content-sha256": body_hash,
        "x-amz-date": timestamp,
    }

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
    canonical_headers = "".join(
        f"{key}:{headers[key]}\n" for key in sorted(list(headers.keys()))
    )
    signed_headers = ";".join(sorted([k.lower() for k in headers.keys()]))
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

    # construct the Authorization header from the credentials and the signature, and forward the
    # call to AWS S3 with the new Authorization header
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={credentials.access_key}/{date}/{region}/{service}/aws4_request, SignedHeaders={signed_headers}, Signature={signature}"
    )
    s3_api_url = f"https://{user_bucket}.s3.amazonaws.com/{api_endpoint}"
    logger.debug(f"Outgoing S3 request: '{request.method} {s3_api_url}'")
    response = await request.app.async_client.request(
        method=request.method,
        url=s3_api_url,
        headers=headers,
        params=query_params,
        data=body,
    )

    if response.status_code != 200:
        logger.debug(f"Received a non-200 status code from AWS: {response.status_code}")
        # no need to log 404 errors except in debug mode: they are are expected when running
        # workflows (e.g. for Nextflow workflows, error output files may not be present when there
        # were no errors)
        if response.status_code != 404:
            logger.error(f"Error from AWS: {response.status_code} {response.text}")

    # return the response from AWS S3.
    # mask the details of 403 errors from the end user: authentication is done internally by this
    # function, so 403 errors are internal service errors
    resp_contents = response.content if response.status_code != 403 else None
    if "Content-Type" in response.headers:
        return Response(
            content=resp_contents,
            status_code=response.status_code,
            media_type=response.headers["Content-Type"],
        )
    return Response(content=resp_contents, status_code=response.status_code)
