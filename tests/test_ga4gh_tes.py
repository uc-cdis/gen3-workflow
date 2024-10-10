import pytest

from conftest import mock_tes_server_request, TEST_USER_ID


client_parameters = [
    pytest.param({"authorized": True, "tes_resp_code": 200}, id="success"),
    pytest.param({"authorized": False, "tes_resp_code": 200}, id="unauthorized"),
    pytest.param({"authorized": True, "tes_resp_code": 500}, id="TES failure"),
    pytest.param(
        {"authorized": False, "tes_resp_code": 500}, id="unauthorized + TES failure"
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [
        pytest.param({"tes_resp_code": 200}, id="success"),
        pytest.param({"tes_resp_code": 500}, id="TES failure"),
    ],
    indirect=True,
)
async def test_service_info_endpoint(client):
    """
    Calls to `GET /ga4gh-tes/v1/service-info` should be forwarded to the TES server.
    When the TES server returns an error, gen3-workflow should return it as well.
    """
    res = await client.get("/ga4gh-tes/v1/service-info")
    assert res.status_code == client.tes_resp_code, res.text
    if client.tes_resp_code == 500:
        assert res.json() == {"detail": "TES server error"}


@pytest.mark.asyncio
@pytest.mark.parametrize("client", client_parameters, indirect=True)
async def test_get_task(client, access_token_patcher):
    """
    Calls to `GET /ga4gh-tes/v1/tasks/<task ID>` should be forwarded to the TES server, and any
    unsupported query params should be filtered out.
    When the TES server returns an error, gen3-workflow should return it as well.
    If the user is not authorized, we should get a 403 error.
    """
    res = await client.get(
        "/ga4gh-tes/v1/tasks/12345?view=BASIC&unsupported_param=value",
        headers={"Authorization": f"bearer 123"},
    )
    if client.tes_resp_code == 500:
        assert res.status_code == 500, res.text
        assert res.json() == {"detail": "TES server error"}
    elif not client.authorized:
        assert res.status_code == 403, res.text
        assert res.json() == {"detail": "Permission denied"}
    else:
        assert res.status_code == 200, res.text
        assert res.json() == {
            "id": "12345",
            "tags": {"AUTHZ": "/users/64/gen3-workflow/tasks/TASK_ID_PLACEHOLDER"},
        }
    mock_tes_server_request.assert_called_once_with(
        method="GET",
        path="/tasks/12345",
        query_params="view=BASIC",
        body="",
        status_code=client.tes_resp_code,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("client", client_parameters, indirect=True)
async def test_create_task(client, access_token_patcher):
    """
    Calls to `POST /ga4gh-tes/v1/tasks` should be forwarded to the TES server, along with the
    request body. A tag containing the user ID should be added.
    When the TES server returns an error, gen3-workflow should return it as well.
    If the user is not authorized, we should get a 403 error and no TES server requests should
    be made.
    """
    res = await client.post(
        "/ga4gh-tes/v1/tasks",
        json={"name": "test-task"},
        headers={"Authorization": f"bearer 123"},
    )
    if not client.authorized:
        assert res.status_code == 403, res.text
        mock_tes_server_request.assert_not_called()
        assert res.json() == {"detail": "Permission denied"}
    else:
        assert res.status_code == client.tes_resp_code, res.text
        if client.tes_resp_code == 500:
            assert res.json() == {"detail": "TES server error"}
        else:
            assert res.json() == {"id": "12345"}
        mock_tes_server_request.assert_called_once_with(
            method="POST",
            path="/tasks",
            query_params="",
            body=f'{{"name": "test-task", "tags": {{"AUTHZ": "/users/{TEST_USER_ID}/gen3-workflow/tasks/TASK_ID_PLACEHOLDER"}}}}',
            status_code=client.tes_resp_code,
        )


@pytest.mark.asyncio
async def test_create_task_without_token(client):
    """
    Calls to `POST /ga4gh-tes/v1/tasks` without a token should return 401 error and no TES server requests should be made.
    """
    res = await client.post("/ga4gh-tes/v1/tasks", json={"name": "test-task"})
    assert res.status_code == 401, res.text
    assert res.json() == {"detail": "Must provide an access token"}
    mock_tes_server_request.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("client", client_parameters, indirect=True)
async def test_list_tasks(client, access_token_patcher):
    """
    Calls to `GET /ga4gh-tes/v1/tasks` should be forwarded to the TES server, and any
    unsupported query params should be filtered out. The USER_ID tag should be added.
    When the TES server returns an error, gen3-workflow should return it as well.
    """
    res = await client.get(
        "/ga4gh-tes/v1/tasks?state=COMPLETE&unsupported_param=value",
        headers={"Authorization": f"bearer 123"},
    )
    if client.tes_resp_code == 500:
        assert res.status_code == 500, res.text
        assert res.json() == {"detail": "TES server error"}
    else:
        assert res.status_code == 200, res.text
        if not client.authorized:
            assert res.json() == {"tasks": []}
        else:
            assert res.json() == {
                "tasks": [
                    {
                        "id": "123",
                        "tags": {
                            "AUTHZ": f"/users/{TEST_USER_ID}/gen3-workflow/tasks/TASK_ID_PLACEHOLDER"
                        },
                    }
                ]
            }
    mock_tes_server_request.assert_called_once_with(
        method="GET",
        path="/tasks",
        query_params=f"state=COMPLETE",
        body="",
        status_code=client.tes_resp_code,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("client", client_parameters, indirect=True)
async def test_delete_task(client, access_token_patcher):
    """
    Calls to `POST /ga4gh-tes/v1/tasks/<task ID>:cancel` should be forwarded to the TES server,
    with no request body.
    When the TES server returns an error, gen3-workflow should return it as well.
    """
    res = await client.post(
        "/ga4gh-tes/v1/tasks/12345:cancel",
        json={"unsupported_body": "value"},
        headers={"Authorization": f"bearer 123"},
    )
    if client.tes_resp_code == 500:
        assert res.status_code == 500, res.text
        assert res.json() == {"detail": "TES server error"}
    elif not client.authorized:
        assert res.status_code == 403, res.text
        assert res.json() == {"detail": "Permission denied"}
    else:
        assert res.status_code == 200, res.text
        assert res.json() == {}
        mock_tes_server_request.assert_called_with(
            method="POST",
            path="/tasks/12345:cancel",
            query_params="",
            body="",
            status_code=client.tes_resp_code,
        )

    mock_tes_server_request.assert_any_call(
        method="GET",
        path="/tasks/12345",
        query_params="",
        body="",
        status_code=client.tes_resp_code,
    )
