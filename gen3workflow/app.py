from fastapi import FastAPI
from fastapi.routing import APIRoute
import httpx
from importlib.metadata import version
import os
import time

from cdislogging import get_logger
from fastapi import Request
from gen3authz.client.arborist.async_client import ArboristClient

from gen3workflow import logger
from gen3workflow.config import config
from gen3workflow.metrics import Metrics
from gen3workflow.routes.ga4gh_tes import router as ga4gh_tes_router
from gen3workflow.routes.s3 import s3_root_router, s3_router
from gen3workflow.routes.storage import router as storage_router
from gen3workflow.routes.system import router as system_router


def get_app(httpx_client=None) -> FastAPI:
    existing_route_ids = set()

    def generate_unique_route_id(route: APIRoute) -> str:
        """
        The default operation ID format is `<function name>_<full route>_<method>`.
        A bug is causing the operation IDs for routes with multiple methods to not be
        generated properly (the method in the ID doesn't match the actual operation method).
        The OpenAPI docs generated currently have the error `Operations must have unique
        operationIds` for any route that has multiple methods. There isn't currently a way
        to generate an operation ID per method.
        See https://github.com/fastapi/fastapi/issues/13175 and
        https://github.com/fastapi/fastapi/pull/10694

        This function simplifies the operation IDs to just `<function name>`.
        It also adds a digit to operation IDs when there is more than 1 route with the same name.
        For example, the code below would result in 2 operation IDs `get_status` and `get_status_2`.
        @router.get("/status")
        @router.get("/_status")
        async def get_status():
            [...]
        """
        if not route.include_in_schema:
            return route.name
        route_id = route.name
        i = 2
        while route_id in existing_route_ids:
            route_id = f"{route.name}_{i}"
            i += 1
        existing_route_ids.add(route_id)
        return route_id

    logger.info("Initializing app")
    config.validate()

    debug = config["APP_DEBUG"]
    log_level = "debug" if debug else "info"

    app = FastAPI(
        title="Gen3Workflow",
        version=version("gen3workflow"),
        debug=config["APP_DEBUG"],
        root_path=config["DOCS_URL_PREFIX"],
        generate_unique_id_function=generate_unique_route_id,
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

    app.metrics = Metrics(
        enabled=config["ENABLE_PROMETHEUS_METRICS"],
        prometheus_dir=config["PROMETHEUS_MULTIPROC_DIR"],
    )

    if app.metrics.enabled:
        app.mount("/metrics", app.metrics.get_asgi_app())

    app.include_router(s3_root_router, tags=["S3"])

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

        # NOTE: If adding more endpoints to metrics, try making it configurable using a list of paths and methods in config.
        # For now, we are only interested in the "/ga4gh/tes/v1/tasks" endpoint for metrics.
        if method != "POST" or path.rstrip("/") != "/ga4gh/tes/v1/tasks":
            return response

        metrics = app.metrics
        metrics.add_create_task_api_interaction(
            method=method,
            path=path,
            response_time_seconds=response_time_seconds,
            status_code=response.status_code,
        )

        return response

    return app


app = get_app()
