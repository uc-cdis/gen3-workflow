import pytest
from unittest.mock import patch


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
