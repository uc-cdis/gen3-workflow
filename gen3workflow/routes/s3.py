from datetime import datetime
import hashlib
import json
import os
import urllib.parse

from fastapi import APIRouter, Request
from fastapi.security import HTTPAuthorizationCredentials
from botocore.credentials import Credentials
import hmac
import httpx
from starlette.datastructures import Headers
from starlette.responses import Response

from gen3workflow import aws_utils, logger
from gen3workflow.auth import Auth


# TODO Generate a presigned URL if the request is a GET request, see https://cdis.slack.com/archives/D01DMJWKVB5/p1733169741227879 - is that required?


router = APIRouter(prefix="/s3")


async def _log_request(request, path):
    # Read body as bytes, then decode it as string if necessary
    body_bytes = await request.body()
    try:
        body = body_bytes.decode()
    except UnicodeDecodeError:
        body = str(body_bytes)  # In case of binary data
    try:
        body = json.loads(body)
    except:
        pass  # Keep body as string if not JSON

    timestamp = datetime.now().isoformat()
    log_entry = {
        'timestamp': timestamp,
        'method': request.method,
        'path': path,
        'headers': dict(request.headers),
        'body': body,
    }
    logger.debug(f"Incoming request: {json.dumps(log_entry, indent=2)}")


def get_access_token(headers: Headers) -> str:
    """
    Extract the user's access token, which should have been provided as the key ID, from the
    Authorization header in the following expected format:
    `AWS4-HMAC-SHA256 Credential=<key ID>/<date>/<region>/<service>/aws4_request, SignedHeaders=<>, Signature=<>`

    Args:
        headers (Headers): request headers

    Returns:
        str: the user's access token or "" if not found
    """
    auth_header = headers.get("authorization")
    if not auth_header:
        return ""
    return auth_header.split("Credential=")[1].split("/")[0]


def get_signature_key(key: str, date_stamp: str, region_name: str, service_name: str) -> str:
    """
    Create a signing key using the AWS Signature Version 4 algorithm.
    """
    key_date = hmac.new(f"AWS4{key}".encode('utf-8'), date_stamp.encode('utf-8'), hashlib.sha256).digest()
    key_region = hmac.new(key_date, region_name.encode('utf-8'), hashlib.sha256).digest()
    key_service = hmac.new(key_region, service_name.encode('utf-8'), hashlib.sha256).digest()
    key_signing = hmac.new(key_service, b"aws4_request", hashlib.sha256).digest()
    return key_signing


@router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "HEAD"]
)
async def catch_all_v4(path: str, request: Request):
    """TODO

    Args:
        path (str): _description_
        request (Request): _description_

    Raises:
        Exception: _description_

    Returns:
        _type_: _description_
    """
    if "KEY" not in os.environ:
        raise Exception("No key")

    # await _log_request(request, path)

    # extract the user's access token from the request headers, and use it to get the name of
    # the user's bucket
    auth = Auth(api_request=request)
    auth.bearer_token = HTTPAuthorizationCredentials(scheme="bearer", credentials=get_access_token(request.headers))
    token_claims = await auth.get_token_claims()
    user_id = token_claims.get("sub")
    user_bucket = aws_utils.get_safe_name_from_user_id(user_id)
    user_bucket = "ga4ghtes-pauline-planx-pla-net" # TODO remove - for testing

    query_params = dict(request.query_params)
    query_params_names = sorted(list(query_params.keys())) # query params have to be sorted
    canonical_r_q_params = "&".join(f"{urllib.parse.quote_plus(key)}={urllib.parse.quote_plus(query_params[key])}" for key in query_params_names)

    # Example 1:
    # - path = my-bucket//
    # - request_path = //
    # - api_endpoint = /
    # Example 2:
    # - path = my-bucket/pre/fix/
    # - request_path = /pre/fix/
    # - api_endpoint = pre/fix/
    request_path = path.split(user_bucket)[1]
    api_endpoint = "/".join(request_path.split("/")[1:])

    # headers = dict(request.headers)
    # headers.pop("authorization")
    headers = {}
    # TODO try again to include all the headers
    # `x-amz-content-sha256` is sometimes set to "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" in
    # the original request, but i was not able to get the signing working when copying it

    # if "Content-Type" in request.headers:
    #     headers["content-type"] = request.headers["Content-Type"]
    headers['host'] = f'{user_bucket}.s3.amazonaws.com'

    # Hash the request body
    body = await request.body()
    body_hash = hashlib.sha256(body).hexdigest()
    headers['x-amz-content-sha256'] = body_hash
    # headers['x-amz-content-sha256'] = request.headers['x-amz-content-sha256']
    # if 'content-length' in request.headers:
    #     headers['content-length'] = request.headers['content-length']
    # if 'x-amz-decoded-content-length' in request.headers:
    #     headers['x-amz-decoded-content-length'] = request.headers['x-amz-decoded-content-length']
    
    # Ensure 'x-amz-date' is included in the headers (it's needed for signature calculation)
    amz_date = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    headers['x-amz-date'] = amz_date

    canon_headers = "".join(f"{key}:{headers[key]}\n" for key in sorted(list(headers.keys())))
    header_names = ";".join(sorted(list(headers.keys())))

    # Construct the canonical request (with cleaned-up path)
    canonical_request = (
        f"{request.method}\n"
        f"{request_path}\n"
        f"{canonical_r_q_params}\n"  # Query parameters
        f"{canon_headers}"
        f"\n"
        f"{header_names}\n"  # Signed headers
        f"{headers['x-amz-content-sha256']}"  # Final Body hash
    )
    # logger.debug(f"- Canonical Request:\n{canonical_request}")

    # AWS Credentials for signing
    # TODO support either AWS IAM key or service account
    credentials = Credentials(
        access_key=os.environ.get('KEY'),
        secret_key=os.environ.get('SECRET')
    )

    # Create the string to sign based on the canonical request
    region = 'us-east-1'
    service = 's3'
    date_stamp = headers['x-amz-date'][:8]  # The date portion (YYYYMMDD)
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n"
        f"{headers['x-amz-date']}\n"  # The timestamp in 'YYYYMMDDTHHMMSSZ' format
        f"{date_stamp}/{region}/{service}/aws4_request\n"  # Credential scope
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"  # Hash of the Canonical Request
    )
    # logger.debug(f"- String to Sign:\n{string_to_sign}")

    # Generate the signing key using our `get_signature_key` function
    signing_key = get_signature_key(credentials.secret_key, date_stamp, region, service)

    # Calculate the signature by signing the string to sign with the signing key
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    # logger.debug(f"- Signature: {signature}")

    # Ensure all headers that are in the request are included in the SignedHeaders
    signed_headers = ';'.join(sorted([k.lower() for k in headers.keys() if k != 'authorization']))

    # Log final headers before sending the request
    headers['authorization'] = f"AWS4-HMAC-SHA256 Credential={credentials.access_key}/{date_stamp}/{region}/{service}/aws4_request, SignedHeaders={signed_headers}, Signature={signature}"
    # logger.debug(f"- Signed Headers:\n{aws_request.headers}")

    # Perform the actual HTTP request
    s3_api_url = f"https://{user_bucket}.s3.amazonaws.com/{api_endpoint}"
    # logger.debug(f"- Making {request.method} request to {s3_api_url}")
    async with httpx.AsyncClient() as client:
        response = await client.request(
            method=request.method,
            url=s3_api_url,
            headers=headers,
            params=query_params,
            data=body,
        )
    if response.status_code != 200:
        logger.error(f"Error from AWS: {response.status_code} {response.text}")

    if "Content-Type" in response.headers:
        return Response(content=response.content, status_code=response.status_code, media_type=response.headers['Content-Type'])
    return Response(content=response.content, status_code=response.status_code)
