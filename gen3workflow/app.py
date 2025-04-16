from fastapi import FastAPI
from fastapi.security import HTTPAuthorizationCredentials
import httpx
from importlib.metadata import version
import os
import time

from cdislogging import get_logger
from gen3authz.client.arborist.async_client import ArboristClient
from fastapi import Request, HTTPException
from gen3workflow import logger
from gen3workflow.config import config
from gen3workflow.metrics import Metrics
from gen3workflow.routes.ga4gh_tes import router as ga4gh_tes_router
from gen3workflow.routes.s3 import router as s3_router
from gen3workflow.routes.storage import router as storage_router
from gen3workflow.routes.system import router as system_router
from gen3workflow.auth import Auth


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

    logger.info(
        f"Setting up Metrics with ENABLE_PROMETHEUS_METRICS flag set to {config['ENABLE_PROMETHEUS_METRICS']}"
    )
    app.metrics = Metrics(
        enabled=config["ENABLE_PROMETHEUS_METRICS"],
        prometheus_dir=config["PROMETHEUS_MULTIPROC_DIR"],
    )

    if app.metrics.enabled:
        app.mount("/metrics", app.metrics.get_asgi_app())

    @app.middleware("http")
    async def middleware_log_response_and_api_metric(
        request: Request, call_next
    ) -> None:
        """
        This FastAPI middleware effectively allows pre and post logic to a request.

        We are using this to log the response consistently across defined endpoints (including execution time).

        Args:
            request (Request): the incoming HTTP request
            call_next (Callable): function to call (this is handled by FastAPI's middleware support)
        """
        start_time = time.perf_counter()
        response = await call_next(request)
        response_time_seconds = time.perf_counter() - start_time

        path = request.url.path
        method = request.method
        if path not in config["ENDPOINTS_WITH_METRICS"]:
            return response

        try:
            # TODO: Add user_id to this metric
            metrics = app.metrics
            metrics.add_create_task_api_interaction(
                method=method,
                path=path,
                response_time_seconds=response_time_seconds,
                status_code=response.status_code,
            )
        except Exception as e:
            logger.warning(
                f"Metrics were not logged for the request with {method=}, {path=}, {response.status_code=}, {response_time_seconds=}. Failed due to {e}",
                exc_info=True,
            )
        return response

    return app


app = get_app()
