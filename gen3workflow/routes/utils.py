import traceback

from fastapi import HTTPException
from httpx import AsyncClient, Response
from starlette.status import HTTP_200_OK, HTTP_500_INTERNAL_SERVER_ERROR

from gen3workflow import logger


async def make_tes_server_request(
    async_client: AsyncClient,
    method: str,
    url: str,
    json: dict = {},
    headers: dict = {},
    params: dict = {},
) -> Response:
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
