import pytest

from conftest import mock_tes_server_request, TEST_USER_ID


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [{"tes_resp_code": 200}, {"tes_resp_code": 500}],
    ids=["success", "failure"],
    indirect=True,
)
async def test_service_info_endpoint(client):
    """
    Calls to `GET /ga4gh-tes/v1/service-info` should be forwarded to the TES server.
    When the TES server returns an error, gen3-workflow should return it as well.
    """
    res = await client.get("/ga4gh-tes/v1/service-info")
    assert res.status_code == client.tes_resp_code
    if client.tes_resp_code == 500:
        assert res.json() == {"detail": "TES server error"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [{"tes_resp_code": 200}, {"tes_resp_code": 500}],
    ids=["success", "failure"],
    indirect=True,
)
async def test_list_tasks(client):
    """
    Calls to `GET /ga4gh-tes/v1/tasks` should be forwarded to the TES server, and any
    unsupported query params should be filtered out.
    When the TES server returns an error, gen3-workflow should return it as well.
    """
    res = await client.get("/ga4gh-tes/v1/tasks?state=COMPLETE&unsupported_param=value")
    assert res.status_code == client.tes_resp_code
    if client.tes_resp_code == 500:
        assert res.json() == {"detail": "TES server error"}
    mock_tes_server_request.assert_called_once_with(
        method="GET",
        path="/tasks",
        query_params="state=COMPLETE",
        body="",
        status_code=client.tes_resp_code,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [{"tes_resp_code": 200}, {"tes_resp_code": 500}],
    ids=["success", "failure"],
    indirect=True,
)
async def test_get_task(client):
    """
    Calls to `GET /ga4gh-tes/v1/tasks/<task ID>` should be forwarded to the TES server, and any
    unsupported query params should be filtered out.
    When the TES server returns an error, gen3-workflow should return it as well.
    """
    res = await client.get(
        "/ga4gh-tes/v1/tasks/12345?view=BASIC&unsupported_param=value"
    )
    assert res.status_code == client.tes_resp_code
    if client.tes_resp_code == 500:
        assert res.json() == {"detail": "TES server error"}
    mock_tes_server_request.assert_called_once_with(
        method="GET",
        path="/tasks/12345",
        query_params="view=BASIC",
        body="",
        status_code=client.tes_resp_code,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [{"authorized": False}, {"authorized": True, "tes_resp_code": 200}, {"authorized": True, "tes_resp_code": 500}],
    ids=["unauthorized", "success", "failure"],
    indirect=True,
)
async def test_create_task(client, access_token_patcher):
    """
    Calls to `POST /ga4gh-tes/v1/tasks` should be forwarded to the TES server, along with the
    request body. A tag containing the user ID should be added.
    When the TES server returns an error, gen3-workflow should return it as well.
    If the user is not authorized, we should get a 403 error and no TES server requests should
    be made.
    """
    res = await client.post("/ga4gh-tes/v1/tasks", json={"name": "test-task"}, headers={"Authorization": f"bearer 123"})
    if not client.authorized:
        assert res.status_code == 403
        mock_tes_server_request.assert_not_called()
    else:
        assert res.status_code == client.tes_resp_code
        if client.tes_resp_code == 500:
            assert res.json() == {"detail": "TES server error"}
        mock_tes_server_request.assert_called_once_with(
            method="POST",
            path="/tasks",
            query_params="",
            body=f'{{"name": "test-task", "tags": {{"USER_ID": "{TEST_USER_ID}"}}}}',
            status_code=client.tes_resp_code,
        )


@pytest.mark.asyncio
async def test_create_task_without_token(client):
    """
    Calls to `POST /ga4gh-tes/v1/tasks` without a token should return 401 error and no TES server requests should be made.
    """
    res = await client.post("/ga4gh-tes/v1/tasks", json={"name": "test-task"})
    assert res.status_code == 401
    mock_tes_server_request.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [{"tes_resp_code": 200}, {"tes_resp_code": 500}],
    ids=["success", "failure"],
    indirect=True,
)
async def test_delete_task(client):
    """
    Calls to `POST /ga4gh-tes/v1/tasks/<task ID>:cancel` should be forwarded to the TES server,
    with no request body.
    When the TES server returns an error, gen3-workflow should return it as well.
    """
    res = await client.post(
        "/ga4gh-tes/v1/tasks/12345:cancel", json={"unsupported_body": "value"}
    )
    assert res.status_code == client.tes_resp_code
    if client.tes_resp_code == 500:
        assert res.json() == {"detail": "TES server error"}
    mock_tes_server_request.assert_called_once_with(
        method="POST",
        path="/tasks/12345:cancel",
        query_params="",
        body="",
        status_code=client.tes_resp_code,
    )
