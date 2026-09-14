import traceback
import uuid

from fastapi import HTTPException
from httpx import AsyncClient, Response as HTTPXResponse
from starlette.responses import Response
from starlette.status import (
    HTTP_200_OK,
    HTTP_204_NO_CONTENT,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from gen3workflow import logger
from gen3workflow.config import config


async def make_tes_server_request(
    async_client: AsyncClient,
    method: str,
    url: str,
    json: dict = {},
    headers: dict = {},
    params: dict = {},
) -> HTTPXResponse:
    """
    Utility function to make a request to the external TES server and check the response
    """
    err_msg = f"TES server error at '{method.upper()} {url}'"
    http_func = getattr(async_client, method)
    http_func_args = {}
    if json:
        http_func_args["json"] = json
    if headers:
        http_func_args["headers"] = headers
    if params:
        http_func_args["params"] = params
    try:
        res = await http_func(url, **http_func_args)
    except Exception:
        traceback.print_exc()
        logger.error(err_msg)
        raise HTTPException(HTTP_500_INTERNAL_SERVER_ERROR, err_msg)
    if res.status_code != HTTP_200_OK:
        logger.error(f"{err_msg}: {res.status_code} {res.text}")
        raise HTTPException(res.status_code, res.text)
    return res


def use_debug_stub(endpoint: str) -> bool:
    """
    Whether to answer a request with a canned response instead of calling the external services
    the endpoint depends on. See `DEBUG_STUB_EXTERNAL_SERVICES`.

    The only place `DEBUG_STUB_EXTERNAL_SERVICES` is read, so that no stubbed response can be
    returned without the warning logged here: while stubbing is on, a successful response means
    the request got past authentication, and nothing more. No task runs and no object is stored.

    Args:
        endpoint (str): the endpoint being stubbed, as it appears in the logs

    Returns:
        bool: True when the caller should return a stubbed response
    """
    if not config["DEBUG_STUB_EXTERNAL_SERVICES"]:
        return False
    logger.warning(
        f"DEBUG MODE: returning a stubbed response for '{endpoint}' instead of contacting the "
        "TES server, AWS or S3. 'DEBUG_STUB_EXTERNAL_SERVICES' must NOT be enabled in production!"
    )
    return True


STUBBED_TES_SERVICE_INFO = {
    "id": "stubbed-tes-server",
    "name": "Stubbed TES server",
    "type": {"group": "org.ga4gh", "artifact": "tes", "version": "1.1"},
    "organization": {"name": "Gen3Workflow", "url": "https://gen3.org"},
    "version": "1.1",
}

STUBBED_TES_TASK_LIST = {"tasks": []}

STUBBED_TES_TASK_CANCELLATION = {}

STUBBED_LIST_BUCKET_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    "<Name>{bucket}</Name><Prefix></Prefix><Marker></Marker><MaxKeys>250</MaxKeys>"
    "<EncodingType>url</EncodingType><IsTruncated>false</IsTruncated>"
    "</ListBucketResult>"
)


def get_stubbed_tes_task_creation() -> dict:
    """
    Build the canned response to a TES task creation. See `DEBUG_STUB_EXTERNAL_SERVICES`.

    Returns:
        dict: a task ID no TES server ever issued, for a task that does not exist
    """
    return {"id": f"stubbed-task-{uuid.uuid4().hex[:8]}"}


def get_stubbed_tes_task(task_id: str) -> dict:
    """
    Build the canned response to a TES task lookup. See `DEBUG_STUB_EXTERNAL_SERVICES`.

    Args:
        task_id (str): the requested task ID, reflected back as-is

    Returns:
        dict: the requested task, always reported as complete
    """
    return {"id": task_id, "state": "COMPLETE"}


def get_stubbed_s3_response(method: str, path: str) -> Response:
    """
    Build a canned response for an S3 request. See `DEBUG_STUB_EXTERNAL_SERVICES`.

    Args:
        method (str): the HTTP method of the incoming request
        path (str): the requested path, in the `<bucket>[/<key>]` format

    Returns:
        Response: a response plausible enough for an S3 client to accept
    """
    if method == "DELETE":
        return Response(status_code=HTTP_204_NO_CONTENT)
    if method in ("PUT", "POST"):
        return Response(status_code=HTTP_200_OK, headers={"ETag": '"stubbed-etag"'})

    bucket_and_key = path.split("?")[0].strip("/")
    if "/" in bucket_and_key:  # the request is about a specific object
        return Response(status_code=HTTP_200_OK)
    return Response(
        content=STUBBED_LIST_BUCKET_XML.format(bucket=bucket_and_key),
        status_code=HTTP_200_OK,
        media_type="application/xml",
    )
