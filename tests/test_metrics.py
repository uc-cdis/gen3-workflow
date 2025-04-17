import pytest
from unittest.mock import patch
from gen3workflow.app import app
from gen3workflow.config import config


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["/", "/_status", "/ga4gh/tes/v1/tasks"])
async def test_metrics_collection(monkeypatch, client, endpoint):
    """
    When metrics are enabled, metrics methods are called for endpoints present in `'/ga4gh/tes/v1/tasks'`.
    """

    # Metrics is currently enabled only for '/ga4gh/tes/v1/tasks' endpoint (hardcoded in the middleware)
    with patch(
        "gen3workflow.metrics.Metrics.add_create_task_api_interaction"
    ) as mock_metrics:
        res = await client.get(endpoint)
        if endpoint == "/ga4gh/tes/v1/tasks":
            mock_metrics.assert_called_once()
        else:
            mock_metrics.assert_not_called()
