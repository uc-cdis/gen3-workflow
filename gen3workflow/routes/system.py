from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR

from gen3workflow import logger
from gen3workflow.config import config
from gen3workflow.routes.utils import make_tes_server_request


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
        await make_tes_server_request(request.app.async_client, "get", tes_status_url)
    except Exception:
        raise HTTPException(HTTP_500_INTERNAL_SERVER_ERROR, "Unable to reach TES API")
    return dict(status="OK")


@router.get("/metrics", include_in_schema=False)
async def redirect_metrics():
    return RedirectResponse(url="/metrics/")
