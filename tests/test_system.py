import pytest


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["/", "/_status"])
async def test_status_endpoint(client, endpoint):
    res = await client.get(endpoint)
    assert res.status_code == 200
    # TODO check contents


@pytest.mark.asyncio
async def test_version_endpoint(client):
    res = await client.get("/_version")
    assert res.status_code == 200

    version = res.json().get("version")
    assert version
