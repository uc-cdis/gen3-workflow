from datetime import datetime
import hashlib
import json
import os
import logging
import urllib.parse
import uuid

from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.auth import SigV4Auth
import boto3
import hmac

from fastapi import APIRouter, FastAPI, Request
import httpx
# import requests # TODO replace with httpx
import uvicorn

from starlette.responses import JSONResponse, Response, StreamingResponse
from io import BytesIO

# TODO Generate a presigned URL if the request is a GET request, see https://cdis.slack.com/archives/D01DMJWKVB5/p1733169741227879


# The base URL to forward requests to
bucket = "ga4ghtes-pauline-planx-pla-net"
FORWARD_TO_BASE_URL = f"https://{bucket}.s3.amazonaws.com"


# app = FastAPI()


logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        logging.FileHandler('server.log'),
        logging.StreamHandler()
    ]
)

router = APIRouter(prefix="/s3")


async def _log_request(request, path):
    # Get current timestamp
    timestamp = datetime.now().isoformat()
    
    # Reading body as bytes, then decode it as string if necessary
    body_bytes = await request.body()
    try:
        body = body_bytes.decode()
    except UnicodeDecodeError:
        body = str(body_bytes)  # In case of binary data
    try:
        body = json.loads(body)
    except:
        pass  # Keep body as string if not JSON
        
    # Create log entry
    log_entry = {
        'timestamp': timestamp,
        'method': request.method,
        'path': path,
        'headers': dict(request.headers),
        'body': body,
    }
    
    # Log as JSON for easier parsing
    logging.info(json.dumps(log_entry, indent=2))


def get_signature_key(key, date_stamp, region_name, service_name):
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
    if "KEY" not in os.environ:
        raise Exception("No key")
    await _log_request(request, path)
    query_params = dict(request.query_params)
    def url_enc(s):
        return urllib.parse.quote_plus(s) #, safe='/', encoding=None, errors=None)
    query_params_names = sorted(list(query_params.keys())) # query params have to be sorted
    canonical_r_q_params = "&".join(f"{url_enc(key)}={url_enc(query_params[key])}" for key in query_params_names)

    used_path = path.split(bucket)[1]
    used_url = "/".join(used_path.split("/")[1:])

    headers = {}
    # TODO try again to include all the headers
    # headers = dict(request.headers)
    # headers.pop("authorization")

    url = f"{FORWARD_TO_BASE_URL}/{used_url}"
    body = await request.body()

    # if "Content-Type" in request.headers:
    #     headers["content-type"] = request.headers["Content-Type"]
    headers['host'] = f'{bucket}.s3.amazonaws.com'

    # Hash the request body
    body_hash = hashlib.sha256(body).hexdigest()
    headers['x-amz-content-sha256'] = body_hash
    
    # Ensure 'x-amz-date' is included in the headers (it's needed for signature calculation)
    amz_date = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    headers['x-amz-date'] = amz_date

    # AWS request object
    aws_request = AWSRequest(
        method=request.method,
        url=url,
        data=body,
        headers=headers
    )

    canon_headers = "".join(f"{key}:{headers[key]}\n" for key in sorted(list(headers.keys())))
    header_names = ";".join(sorted(list(headers.keys())))

    # Construct the canonical request (with cleaned-up path)
    canonical_request = (
        f"{request.method}\n"
        f"{used_path}\n"
        f"{canonical_r_q_params}\n"  # Query parameters
        f"{canon_headers}"
        f"\n"
        f"{header_names}\n"  # Signed headers
        f"{headers['x-amz-content-sha256']}"  # Final Body hash
    )
    logging.info(f"- Canonical Request:\n{canonical_request}")

    # AWS Credentials for signing
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

    # Log String to Sign
    logging.info(f"- String to Sign:\n{string_to_sign}")

    # Generate the signing key using our `get_signature_key` function
    signing_key = get_signature_key(credentials.secret_key, date_stamp, region, service)

    # Calculate the signature by signing the string to sign with the signing key
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    # Log Signature
    logging.info(f"- Signature: {signature}")

    # Ensure all headers that are in the request are included in the SignedHeaders
    signed_headers = ';'.join(sorted([k.lower() for k in headers.keys() if k != 'authorization']))

    # Log final headers before sending the request
    aws_request.headers['Authorization'] = f"AWS4-HMAC-SHA256 Credential={credentials.access_key}/{date_stamp}/{region}/{service}/aws4_request, SignedHeaders={signed_headers}, Signature={signature}"

    logging.info(f"- Signed Headers:\n{aws_request.headers}")

    # Send the signed request to S3
    prepared_request = aws_request.prepare()
    logging.info(f"- Making {prepared_request.method} request to {prepared_request.url}")

    # Perform the actual HTTP request
    async with httpx.AsyncClient() as client:
        # print("request:", {"method": request.method, "url": url, "body": body, "headers": prepared_request.headers, "query param": query_params})
        response = await client.request(
            method=request.method,
            url=url,
            headers=prepared_request.headers,
            params=query_params,
            data=body,
        )

    # Check for errors
    if response.status_code != 200:
        logging.error(f"- Error from AWS: {response}")

    if "Content-Type" in response.headers:
        return Response(content=response.content, status_code=response.status_code, media_type=response.headers['Content-Type'])
    return Response(content=response.content, status_code=response.status_code)
