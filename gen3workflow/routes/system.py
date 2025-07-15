from fastapi import APIRouter, HTTPException, Request
from httpx import ConnectError
from starlette.status import HTTP_200_OK, HTTP_500_INTERNAL_SERVER_ERROR

from gen3workflow import logger
from gen3workflow.config import config


router = APIRouter()


@router.get("/_version")
@router.get("/_version/", include_in_schema=False)
def get_version(request: Request) -> dict:
    return dict(version=request.app.version)


@router.get("/_status")
@router.get("/_status/", include_in_schema=False)
async def get_status(request: Request) -> dict:
    tes_status_url = f"{config['TES_SERVER_URL']}/service-info"
    try:
        res = await request.app.async_client.get(tes_status_url)
    except ConnectError as e:
        logger.error(f"Unable to reach '{tes_status_url}': {e}")
        raise HTTPException(HTTP_500_INTERNAL_SERVER_ERROR, "Unable to reach TES API")

    if res.status_code != HTTP_200_OK:
        logger.error(
            f"Expected status code {HTTP_200_OK} from '{tes_status_url}' and got {res.status_code}: {res.text}"
        )
        raise HTTPException(HTTP_500_INTERNAL_SERVER_ERROR, "Unable to reach TES API")
    return dict(status="OK")
