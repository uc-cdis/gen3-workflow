import pytest


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["/", "/_status"])
@pytest.mark.parametrize(
    "client",
    [{"status_code": 200}, {"status_code": 404}],
    ids=["success", "failure"],
    indirect=True,
)
async def test_status_endpoint(client, endpoint):
    """
    When the TES API is reachable, the gen3-workflow status endpoint returns 200. When it's
    not, it returns 500.
    """
    res = await client.get(endpoint)
    if client.status_code == 200:
        assert res.status_code == 200
    else:
        assert res.json() == {"detail": "Unable to reach TES API"}
        assert res.status_code == 500


@pytest.mark.asyncio
async def test_version_endpoint(client):
    res = await client.get("/_version")
    assert res.status_code == 200

    version = res.json().get("version")
    assert version
