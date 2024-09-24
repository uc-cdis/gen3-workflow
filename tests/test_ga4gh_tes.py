import pytest

from conftest import mock_tes_server_request


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [{"status_code": 200}, {"status_code": 500}],
    ids=["success", "failure"],
    indirect=True,
)
async def test_service_info_endpoint(client):
    """
    Calls to `GET /ga4gh-tes/v1/service-info` should be forwarded to the TES server.
    When the TES server returns an error, Gen3Workflow should return it as well.
    """
    res = await client.get("/ga4gh-tes/v1/service-info")
    assert res.status_code == client.status_code
    if client.status_code == 500:
        assert res.json() == {"detail": "TES server error"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [{"status_code": 200}, {"status_code": 500}],
    ids=["success", "failure"],
    indirect=True,
)
async def test_list_tasks(client):
    """
    Calls to `GET /ga4gh-tes/v1/tasks` should be forwarded to the TES server, and any
    unsupported query params should be filtered out.
    When the TES server returns an error, Gen3Workflow should return it as well.
    """
    res = await client.get("/ga4gh-tes/v1/tasks?state=COMPLETE&unsupported_param=value")
    assert res.status_code == client.status_code
    if client.status_code == 500:
        assert res.json() == {"detail": "TES server error"}
    mock_tes_server_request.assert_called_once_with(
        method="GET",
        path="/tasks",
        query_params="state=COMPLETE",
        body="",
        status_code=client.status_code,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [{"status_code": 200}, {"status_code": 500}],
    ids=["success", "failure"],
    indirect=True,
)
async def test_get_task(client):
    """
    Calls to `GET /ga4gh-tes/v1/tasks/<task ID>` should be forwarded to the TES server, and any
    unsupported query params should be filtered out.
    When the TES server returns an error, Gen3Workflow should return it as well.
    """
    res = await client.get(
        "/ga4gh-tes/v1/tasks/12345?view=BASIC&unsupported_param=value"
    )
    assert res.status_code == client.status_code
    if client.status_code == 500:
        assert res.json() == {"detail": "TES server error"}
    mock_tes_server_request.assert_called_once_with(
        method="GET",
        path="/tasks/12345",
        query_params="view=BASIC",
        body="",
        status_code=client.status_code,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [{"status_code": 200}, {"status_code": 500}],
    ids=["success", "failure"],
    indirect=True,
)
async def test_create_task(client):
    """
    Calls to `POST /ga4gh-tes/v1/tasks` should be forwarded to the TES server, along with the
    request body.
    When the TES server returns an error, Gen3Workflow should return it as well.
    """
    res = await client.post("/ga4gh-tes/v1/tasks", json={"name": "test-task"})
    assert res.status_code == client.status_code
    if client.status_code == 500:
        assert res.json() == {"detail": "TES server error"}
    mock_tes_server_request.assert_called_once_with(
        method="POST",
        path="/tasks",
        query_params="",
        body='{"name": "test-task"}',
        status_code=client.status_code,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [{"status_code": 200}, {"status_code": 500}],
    ids=["success", "failure"],
    indirect=True,
)
async def test_delete_task(client):
    """
    Calls to `POST /ga4gh-tes/v1/tasks/<task ID>:cancel` should be forwarded to the TES server,
    with no request body.
    When the TES server returns an error, Gen3Workflow should return it as well.
    """
    res = await client.post(
        "/ga4gh-tes/v1/tasks/12345:cancel", json={"unsupported_body": "value"}
    )
    assert res.status_code == client.status_code
    if client.status_code == 500:
        assert res.json() == {"detail": "TES server error"}
    mock_tes_server_request.assert_called_once_with(
        method="POST",
        path="/tasks/12345:cancel",
        query_params="",
        body="",
        status_code=client.status_code,
    )
