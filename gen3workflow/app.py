from fastapi import FastAPI
import httpx
from importlib.metadata import version
import os

from cdislogging import get_logger
from gen3authz.client.arborist.async_client import ArboristClient

from gen3workflow import logger
from gen3workflow.config import config
from gen3workflow.routes.ga4gh_tes import router as ga4gh_tes_router
from gen3workflow.routes.s3 import router as s3_router
from gen3workflow.routes.storage import router as storage_router
from gen3workflow.routes.system import router as system_router


def get_app(httpx_client=None) -> FastAPI:
    logger.info("Initializing app")
    config.validate()

    debug = config["APP_DEBUG"]
    log_level = "debug" if debug else "info"

    app = FastAPI(
        title="Gen3Workflow",
        version=version("gen3workflow"),
        debug=config["APP_DEBUG"],
        root_path=config["DOCS_URL_PREFIX"],
    )
    app.async_client = httpx_client or httpx.AsyncClient()
    app.include_router(ga4gh_tes_router, tags=["GA4GH TES"])
    app.include_router(s3_router, tags=["S3"])
    app.include_router(storage_router, tags=["Storage"])
    app.include_router(system_router, tags=["System"])

    # Following will update logger level, propagate, and handlers
    get_logger("gen3workflow", log_level=log_level)

    logger.info("Initializing Arborist client")
    if config["MOCK_AUTH"]:
        logger.warning(
            "Mock authentication and authorization are enabled! 'MOCK_AUTH' should NOT be enabled in production!"
        )
    custom_arborist_url = os.environ.get("ARBORIST_URL", config["ARBORIST_URL"])
    if custom_arborist_url:
        app.arborist_client = ArboristClient(
            arborist_base_url=custom_arborist_url,
            authz_provider="gen3-workflow",
            logger=get_logger("gen3workflow.gen3authz", log_level=log_level),
        )
    else:
        app.arborist_client = ArboristClient(
            authz_provider="gen3-workflow",
            logger=get_logger("gen3workflow.gen3authz", log_level=log_level),
        )

    return app


app = get_app()
