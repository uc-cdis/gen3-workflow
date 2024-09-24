from fastapi import FastAPI
import httpx
from importlib.metadata import version
# import os
# from gen3authz.client.arborist.async_client import ArboristClient

from gen3workflow import logger
from gen3workflow.config import config
from gen3workflow.routes.system import router as system_router
from gen3workflow.routes.ga4gh_tes import router as ga4gh_tes_router


def get_app(httpx_client=None) -> FastAPI:
    logger.info("Initializing app")
    config.validate()

    debug = config["DEBUG"]
    app = FastAPI(
        title="Gen3Workflow",
        version=version("gen3workflow"),
        debug=debug,
        root_path=config["DOCS_URL_PREFIX"],
    )
    app.async_client = httpx_client or httpx.AsyncClient()
    app.include_router(system_router, tags=["System"])
    app.include_router(ga4gh_tes_router, tags=["GA4GH TES"])

    # Following will update logger level, propagate, and handlers
    # TODO test that
    # get_logger("gen3workflow", log_level="debug" if debug == True else "info")

    logger.info("Initializing Arborist client")
    # custom_arborist_url = os.environ.get("ARBORIST_URL", config["ARBORIST_URL"])
    # if custom_arborist_url:
    #     app.arborist_client = ArboristClient(
    #         arborist_base_url=custom_arborist_url,
    #         logger=get_logger("gen3workflow.gen3authz", log_level="debug"),
    #     )
    # else:
    #     app.arborist_client = ArboristClient(
    #         logger=get_logger("gen3workflow.gen3authz", log_level="debug"),
    #     )

    return app


app = get_app()
