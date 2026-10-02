"""
Tests for the debug stub routers. See `DEBUG_STUB_EXTERNAL_SERVICES`.
"""

from fastapi import APIRouter
from fastapi.routing import APIRoute
import pytest

from gen3workflow.routes.debug_stubs import (
    stubbed_ga4gh_tes_router,
    stubbed_s3_root_router,
    stubbed_s3_router,
    stubbed_status_router,
    stubbed_storage_router,
)
from gen3workflow.routes.ga4gh_tes import router as ga4gh_tes_router
from gen3workflow.routes.s3 import s3_root_router, s3_router
from gen3workflow.routes.storage import router as storage_router
from gen3workflow.routes.system import status_router


def get_route_signatures(router: APIRouter) -> set:
    """
    List the routes a router exposes.

    Args:
        router (APIRouter): the router

    Returns:
        set: one `(path, method, included in schema)` tuple per route and method
    """
    return {
        (route.path, method, route.include_in_schema)
        for route in router.routes
        if isinstance(route, APIRoute)
        for method in route.methods
    }


@pytest.mark.parametrize(
    "real_router,stubbed_router",
    [
        pytest.param(ga4gh_tes_router, stubbed_ga4gh_tes_router, id="ga4gh-tes"),
        pytest.param(s3_router, stubbed_s3_router, id="s3-prefix"),
        pytest.param(s3_root_router, stubbed_s3_root_router, id="s3-root"),
        pytest.param(status_router, stubbed_status_router, id="status"),
        pytest.param(storage_router, stubbed_storage_router, id="storage"),
    ],
)
def test_stubbed_router_exposes_the_same_routes_as_the_real_one(
    real_router, stubbed_router
):
    """
    A stubbed router exposes exactly the routes of the real router it replaces, so that no
    request can reach the real external services in debug stub mode.
    """
    assert get_route_signatures(stubbed_router) == get_route_signatures(real_router)
