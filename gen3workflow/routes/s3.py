import asyncio
from datetime import datetime, timezone
import hashlib
import random
from typing import Tuple
import urllib.parse

from fastapi import APIRouter, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials
from botocore.credentials import Credentials
import hmac
from starlette.background import BackgroundTask
from starlette.datastructures import Headers
from starlette.requests import ClientDisconnect
from starlette.responses import Response, StreamingResponse
from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_408_REQUEST_TIMEOUT,
    HTTP_429_TOO_MANY_REQUESTS,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from gen3workflow import logger
from gen3workflow.auth import Auth
from gen3workflow.aws import aws_utils
from gen3workflow.aws.bucket import get_existing_kms_key_for_bucket
from gen3workflow.aws.clients import irsa_session
from gen3workflow.config import config

s3_root_router = APIRouter(include_in_schema=False)
s3_router = APIRouter(prefix="/s3")


S3_MAX_TRIES = 3
S3_RETRY_BASE_DELAY = 0.5
S3_RETRY_BACKOFF_FACTOR = 2

# Limit concurrent body-buffering + SHA256 operations to prevent CPU saturation under
# concurrent Funnel uploads. Each operation buffers up to 10 MB and runs CPU-bound hash
# computation in a thread pool; without a cap, 100 concurrent uploads exhaust the thread pool.
_PROXY_SEMAPHORE_LIMIT = 20
_proxy_semaphore: asyncio.Semaphore | None = None


def _get_proxy_semaphore() -> asyncio.Semaphore:
    global _proxy_semaphore
    if _proxy_semaphore is None:
        _proxy_semaphore = asyncio.Semaphore(_PROXY_SEMAPHORE_LIMIT)
    return _proxy_semaphore


async def set_access_token_and_get_user_id(
    auth: Auth, headers: Headers
) -> Tuple[str, str]:
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
        tuple(str, str): the user's ID and (if relevant) the client's ID
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
    client_id = token_claims.get("azp")
    if is_user_token:
        user_id = sub
    else:
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

    return user_id, client_id


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


def chunked_to_non_chunked_body(body: bytes) -> bytes:
    """
    Turn a chunked body into a non-chunked body.

    Each chunk has:
        <chunk-size-in-hex>;chunk-signature=<sig>\r\n
        <chunk-data>\r\n
    Final chunk:
        0;chunk-signature=<sig>\r\n\r\n

    Parse the chunks and return a non-chunked body.
    """
    result = []
    i = 0
    while i < len(body):
        # find the end of the chunk
        line_end = body.index(b"\r\n", i)
        line = body[i:line_end]
        i = line_end + 2  # skip the separator `\r\n`

        # strip chunk extensions (such as the signature) and extract the chunk size
        chunk_size_hex = line.split(b";")[0]
        chunk_size = int(chunk_size_hex, 16)

        if chunk_size == 0:
            break  # final chunk

        result.append(body[i : i + chunk_size])  # extract exactly `chunk_size` bytes
        i += chunk_size + 2  # skip chunk data + the separator `\r\n`

    return b"".join(result)


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

    # Because this endpoint is exposed at root, if the GET path is empty, the user may not be
    # trying to reach the S3 endpoint: suggest using the status endpoint.
    # "All buckets" listing requests also land here and are not supported, since users can only
    # access their own bucket.
    if request.method == "GET" and path in ("", "s3"):
        err_msg = f"'{request.method} /{path}': If you are using the S3 endpoint: 's3 ls' not supported, use 's3 ls s3://<your bucket>' instead. If you are trying to reach the Gen3-Workflow API, try '/_status'."
        logger.error(err_msg)
        raise HTTPException(HTTP_400_BAD_REQUEST, err_msg)

    # Extract the caller's access token from the request headers, and ensure the caller (user, or
    # client acting on behalf of the user) has access to the user's files.
    # Note: sharing task inputs/output is not supported. Currently, users can only access their own
    # S3 bucket. Sharing could be supported in the future by hitting the "GET task" endpoint to get
    # the list of files for a specific task.
    auth = Auth(api_request=request)
    in_headers = request.headers
    user_id, client_id = await set_access_token_and_get_user_id(auth, in_headers)
    auth_verb = {"GET": "read", "HEAD": "read", "DELETE": "delete"}.get(
        request.method, "create"
    )
    await auth.authorize(
        auth_verb, [f"/services/workflow/gen3-workflow/storage/{user_id}"]
    )

    # get the name of the user's bucket and ensure the user is making a call to their own bucket
    logger.info(
        f"Incoming S3 request from user '{user_id}'{f', client \'{client_id}\'' if client_id else ''}: '{request.method} {path}'"
    )
    user_bucket = aws_utils.get_safe_name_from_hostname(user_id)
    request_bucket = path.split("?")[0].split("/")[0]
    if request_bucket != user_bucket:
        err_msg = f"'{path}' (bucket '{request_bucket}') not allowed. You can make calls to your personal bucket, '{user_bucket}'"
        logger.error(err_msg)
        raise HTTPException(HTTP_403_FORBIDDEN, err_msg)

    # if a custom S3 endpoint is configured, assume it is non-AWS and uses path-style addressing
    # (as opposed to virtual-hosted style addressing)
    path_style = bool(config["S3_UPSTREAM_ENDPOINT"])

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
    if path_style:
        request_path = "/" + path.lstrip("/")
    else:
        request_path = path.split(user_bucket)[1] or "/"
    api_endpoint = "/".join(request_path.split("/")[1:])

    region = config["USER_BUCKETS_REGION"]
    service = "s3"

    if path_style:
        host = config["S3_UPSTREAM_ENDPOINT"].split("://")[1]  # remove the protocol
    else:
        host = f"{user_bucket}.s3.{region}.amazonaws.com"

    timestamp = in_headers.get("x-amz-date")
    if not timestamp and in_headers.get("date"):
        # assume RFC 1123 format, convert to ISO 8601 basic YYYYMMDD'T'HHMMSS'Z' format
        dt = datetime.strptime(in_headers["date"], "%a, %d %b %Y %H:%M:%S %Z")
        timestamp = dt.strftime("%Y%m%dT%H%M%SZ")
    if not timestamp:
        # no `x-amz-date` or `date` header, just generate it ourselves
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    date = timestamp[:8]  # the date portion (YYYYMMDD) of the timestamp

    # Generate the request headers
    out_headers = {
        "host": host,
    }

    # - Copy all relevant headers from the incoming request
    #   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html:
    #   "For the purpose of calculating an authorization signature, only the host and any x-amz-*
    #   headers are required; [...] Do not include hop-by-hop headers that are frequently altered
    #   during transit across a complex system."
    for h in in_headers:
        if h.lower().startswith("x-amz-") or h.lower() in {
            "range",
            "content-type",
            "content-md5",
            "content-length",
            "if-match",
            "if-none-match",
            "if-modified-since",
            "if-unmodified-since",
        }:
            out_headers[h] = in_headers[h]

    # - The Minio-go S3 client sets the `x-amz-server-side-encryption-context` header to
    #   `{"Context":{"Context":{"Context":{}}}}`, triggering this error: "The header
    #   'x-amz-server-side-encryption-context' shall be Base64-encoded UTF-8 string holding JSON
    #   which represents a string-string map". Band-aid fix: drop it
    #   See https://github.com/minio/minio-go/issues/2235
    # TODO: fixed in https://github.com/calypr/funnel/pull/1428 - to be tested
    out_headers.pop("x-amz-server-side-encryption-context", None)

    # - Add the `x-amz-date` header if it wasn't there
    out_headers["x-amz-date"] = timestamp

    # - Chunked payload support:
    #   - The AWS CLI uploads files with the STREAMING-UNSIGNED-PAYLOAD-TRAILER method.
    #     The body includes chunks and checksums. It can be forwarded to AWS without changes as long
    #     as the necessary headers are forwarded as well.
    #   - The Minio-go S3 client uploads files with the STREAMING-AWS4-HMAC-SHA256-PAYLOAD method.
    #     Funnel uses this client.
    #     We overwrite the original `x-amz-content-sha256` header value with the body hash and we
    #     strip the body of the chunk signatures => protocol translation from a chunk-signed
    #     streaming request (SigV4 streaming HTTP PUT) into a single-payload request (Normal SigV4
    #     HTTP PUT). We could also implement chunked signing but it's not straightforward and
    #     likely unnecessary.
    #   - aws-sdk-java used by Nextflow may use the STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER
    #     method, which is treated similarly to the above.
    #   Note: Chunked uploads != multipart uploads.
    try:
        body = await request.body()
    except ClientDisconnect:  # catch this to avoid throwing 500 errors
        raise HTTPException(
            499, "Client disconnected before request body was fully received"
        )
    if in_headers.get("x-amz-content-sha256") in [
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
    ]:
        # parse the body and hash it — both are CPU-bound and must run off the event loop.
        # sha256 of a 5-10 MB body takes ~30-50ms and would block the event loop if called inline.
        # the semaphore caps concurrent operations so 100 simultaneous uploads don't saturate the CPU.
        def _parse_and_hash(b):
            b = chunked_to_non_chunked_body(b)
            return b, hashlib.sha256(b).hexdigest()

        loop = asyncio.get_event_loop()
        async with _proxy_semaphore:
            body, body_sha256 = await loop.run_in_executor(None, _parse_and_hash, body)
        content_len = str(len(body))
        out_headers["x-amz-content-sha256"] = body_sha256
        for h in ["content-length", "x-amz-decoded-content-length"]:
            if h in in_headers:
                out_headers[h] = content_len
        # the outgoing body is no longer chunked, so there's no trailer/checksum in it anymore
        out_headers.pop("x-amz-trailer", None)
        out_headers.pop("x-amz-sdk-checksum-algorithm", None)

    # get AWS credentials from the configuration or the current assumed role session
    if config["S3_ENDPOINTS_AWS_ACCESS_KEY_ID"]:
        credentials = Credentials(
            access_key=config["S3_ENDPOINTS_AWS_ACCESS_KEY_ID"],
            secret_key=config["S3_ENDPOINTS_AWS_SECRET_ACCESS_KEY"],
        )
    else:  # assume the service is running in k8s: get credentials from the assumed role
        credentials = irsa_session.get_credentials()
        assert credentials, "No AWS credentials found"
        out_headers["x-amz-security-token"] = credentials.token

    # If this is a PUT or POST request, specify the KMS key to use for encryption.
    # For multipart uploads, the initial CreateMultipartUpload request includes the KMS
    # configuration, and the following UploadPart and CompleteMultipartUpload requests do not.
    # We know this is an UploadPart or CompleteMultipartUpload request if it includes the
    # uploadId query parameter.
    query_params = dict(request.query_params)
    if (
        config["KMS_ENCRYPTION_ENABLED"]
        and request.method in ["PUT", "POST"]
        and "uploadId" not in query_params
    ):
        _, kms_key_arn = get_existing_kms_key_for_bucket(user_bucket)
        if not kms_key_arn:
            err_msg = "Bucket misconfigured. Hit the `GET /storage/setup` endpoint and try again."
            logger.error(
                f"No existing KMS key found for bucket '{user_bucket}'. {err_msg}"
            )
            raise HTTPException(HTTP_400_BAD_REQUEST, err_msg)
        out_headers["x-amz-server-side-encryption"] = "aws:kms"
        out_headers["x-amz-server-side-encryption-aws-kms-key-id"] = kms_key_arn

    # construct the canonical request. All header keys must be lowercase
    logger.debug(f"Dropped headers: {[h for h in in_headers if h not in out_headers]}")
    sorted_headers = sorted(list(out_headers.keys()), key=str.casefold)
    canonical_headers = "".join(
        f"{key.lower()}:{out_headers[key]}\n" for key in sorted_headers
    )
    signed_headers = ";".join([k.lower() for k in sorted_headers])
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
        f"{out_headers.get('x-amz-content-sha256', '')}"
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

    # construct the Authorization header from the credentials and the signature
    out_headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={credentials.access_key}/{date}/{region}/{service}/aws4_request, SignedHeaders={signed_headers}, Signature={signature}"
    )
    if path_style:
        s3_api_url = f"{config['S3_UPSTREAM_ENDPOINT'].rstrip('/')}/{api_endpoint}"
    else:
        s3_api_url = f"https://{user_bucket}.s3.{region}.amazonaws.com/{api_endpoint}"
    logger.debug(f"Outgoing S3 request: '{request.method} {s3_api_url}'")

    # forward the call to the S3 server with the new Authorization header.
    # this call is retried with exponential backoff in case of unexpected error from S3.
    for attempt in range(1, S3_MAX_TRIES + 1):
        proceed = True
        exception = None
        try:
            response = await request.app.async_client.send(
                request.app.async_client.build_request(
                    method=request.method,
                    url=s3_api_url,
                    headers=out_headers,
                    params=query_params,
                    content=body,
                ),
                stream=True,
            )

            if response.status_code >= 300:
                # no need to log details (unless in debug mode) or retry in the case of a 404
                # error: 404s are are expected when running workflows (e.g. for Nextflow workflows,
                # stderr output files may not be present when there were no errors)
                if response.status_code != HTTP_404_NOT_FOUND:
                    logger.error(
                        f"Error from S3: {response.status_code} {response.text}"
                    )
                    # in the case of a client-side (4xx) error (except `408 Request  Timeout` and
                    # `429 Too Many Requests`), print debug logs and do not retry
                    if (
                        response.status_code >= HTTP_400_BAD_REQUEST
                        and response.status_code < HTTP_500_INTERNAL_SERVER_ERROR
                        and response.status_code
                        not in [HTTP_408_REQUEST_TIMEOUT, HTTP_429_TOO_MANY_REQUESTS]
                    ):
                        proceed = False
                        logger.debug(f"Incoming headers:\n{in_headers}")
                        logger.debug(f"Outgoing headers:\n{out_headers}")
                        logger.debug(f"Canonical request:\n{canonical_request}")
                        logger.debug(f"String to sign:\n{string_to_sign}")
                        logger.debug(f"Incoming query params:\n{request.query_params}")
                        logger.debug(f"Outgoing query params:\n{query_params}")
                        logger.debug(f"Outgoing body:\n{body}")
                else:
                    logger.debug(f"Error from S3: {response.status_code}")
        except Exception as e:
            logger.error(f"Exception while attempting to make a call to S3: {e}")
            proceed = False
            exception = e

        # exit if the call succeeded or should not be retried, or we reached the max number of
        # retries
        if proceed:
            break
        if attempt == S3_MAX_TRIES:
            logger.error(
                f"Outgoing S3 request failed (attempt {attempt}/{S3_MAX_TRIES}). Giving up"
            )
            if exception:
                raise exception
            break

        # retry with exponential backoff
        delay = S3_RETRY_BASE_DELAY * (S3_RETRY_BACKOFF_FACTOR**attempt)
        delay += delay * 0.1 * random.uniform(-1, 1)  # add jitter
        logger.warning(
            f"Outgoing S3 request failed (attempt {attempt}/{S3_MAX_TRIES}). Retrying in {delay:.2f} seconds"
        )
        await asyncio.sleep(delay)

    # Return the response from AWS S3.
    # Return all the headers from the AWS response, except:
    # - hop-by-hop headers (apply only to a single transport connection and should be stripped by
    #   proxies).
    # - `x-amz-bucket-region` which for some reason causes this error for tasks ran through
    #   Nextflow: `The AWS Access Key Id you provided does not exist in our records`.
    # - `x-amz-decoded-content-length`: request-direction header; should not appear on responses.
    filtered_headers = {
        h: v
        for h, v in response.headers.items()
        if h.lower()
        not in {
            "x-amz-bucket-region",
            "x-amz-decoded-content-length",
            # hop-by-hop headers:
            "connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "proxy-authenticate",
            "proxy-authorization",
        }
    }

    # mask the details of 403 errors from the end user: authentication is done internally by this
    # function, so 403 errors are internal service errors.
    if response.status_code == HTTP_403_FORBIDDEN:
        await response.aclose()  # discard the body we're not returning
        return Response(status_code=403, headers=filtered_headers)

    if response.headers.get("content-encoding", "").lower() == "gzip":
        # the backend compressed this response (e.g. Minio does this for small, compressible
        # bodies like XML listings), httpx decodes it for us
        filtered_headers = {
            h: v
            for h, v in filtered_headers.items()
            # Filter out more headers:
            # - `content-length`: when it is provided, Starlette's Response does not recompute it
            #   from the actual content bytes. Example case: if the S3 server is Minio, the
            #   `content-length` header for a HEAD request can describe what a GET on that object
            #   _would_ return. Recomputing it is safer.
            # - `content-encoding`: forwarding response headers that describe the original bytes
            #   returned by the S3 server can cause a mismatch, because our httpx client may not
            #   return those original bytes. Example case: here, httpx transparently decompresses
            #   gzip content. `response.content` contains the decoded bytes, while the
            #   `content-encoding` header still says gzip.
            if h.lower() not in {"content-length", "content-encoding"}
        }
        decoded = await response.aread()
        await response.aclose()
        return Response(
            content=decoded,
            status_code=response.status_code,
            headers=filtered_headers,
        )

    # the response is not compressed: stream the raw response bytes (skip the automatic httpx
    # post-handling)
    return StreamingResponse(
        response.aiter_raw(),
        status_code=response.status_code,
        headers=filtered_headers,
        background=BackgroundTask(response.aclose),
    )
