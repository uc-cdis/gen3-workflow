import pytest
from unittest.mock import patch
from conftest import trailing_slash, TEST_USER_TOKEN


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["/", "/_status", "/ga4gh/tes/v1/tasks"])
async def test_metrics_collection(client, endpoint):
    """
    When metrics are enabled, metrics methods are called for endpoints present in `'/ga4gh/tes/v1/tasks'`.
    """

    # Metrics is currently enabled only for '/ga4gh/tes/v1/tasks' endpoint (hardcoded in the middleware)
    with patch(
        "gen3workflow.metrics.Metrics.add_create_task_api_interaction"
    ) as mock_metrics:
        if endpoint == "/ga4gh/tes/v1/tasks":
            await client.post(endpoint, json={"name": "test_task"})
            mock_metrics.assert_called_once()
        else:
            await client.get(endpoint)
            mock_metrics.assert_not_called()


@pytest.mark.asyncio
async def test_metrics_endpoint(client, trailing_slash):
    """
    Test hitting the metrics endpoint
    """
    res = await client.get(
        f"/metrics{'/' if trailing_slash else ''}",
        headers={"Authorization": f"bearer {TEST_USER_TOKEN}"},
    )

    # Metrics endpoint is mounted at /metrics/,
    # so when trying to access it without a trailing slash, it should redirect, returning a 307 status code.
    if trailing_slash:
        assert res.status_code == 200
    else:
        assert res.status_code == 307
        assert res.next_request.url == "http://test-gen3-wf/metrics/"
