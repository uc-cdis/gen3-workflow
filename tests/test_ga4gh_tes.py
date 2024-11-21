from datetime import datetime, timedelta
import json

import boto3
from moto import mock_aws
import pytest
from sqlalchemy.future import select

from conftest import (
    mock_arborist_request,
    mock_tes_server_request,
    TEST_USER_ID,
    NEW_TEST_USER_ID,
)
from gen3workflow import aws_utils
from gen3workflow.models import SystemKey
from gen3workflow.routes.ga4gh_tes import get_system_key


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
    Calls to `GET /ga4gh/tes/v1/service-info` should be forwarded to the TES server.
    When the TES server returns an error, gen3-workflow should return it as well.
    """
    res = await client.get("/ga4gh/tes/v1/service-info")
    assert res.status_code == client.tes_resp_code, res.text
    if client.tes_resp_code == 500:
        assert res.json() == {"detail": "TES server error"}


@pytest.mark.asyncio
@pytest.mark.parametrize("client", client_parameters, indirect=True)
@pytest.mark.parametrize("view", ["BASIC", "MINIMAL", "FULL", None])
async def test_get_task(client, access_token_patcher, view):
    """
    Calls to `GET /ga4gh/tes/v1/tasks/<task ID>` should be forwarded to the TES server, and any
    unsupported query params should be filtered out. If the user is not authorized, we should get
    a 403 error.
    When the TES server returns an error, gen3-workflow should return it as well.
    """
    url = f"/ga4gh/tes/v1/tasks/123?unsupported_param=value"
    if view:
        url += f"&view={view}"
    res = await client.get(url, headers={"Authorization": "bearer 123"})

    # the call to the TES server always has `view=FULL` so we get the AUTHZ tag
    mock_tes_server_request.assert_called_once_with(
        method="GET",
        path="/tasks/123",
        query_params={"view": "FULL"},
        body="",
        status_code=client.tes_resp_code,
    )

    if client.tes_resp_code == 500:
        assert res.status_code == 500, res.text
        assert res.json() == {"detail": "TES server error"}
    elif not client.authorized:
        assert res.status_code == 403, res.text
        assert res.json() == {"detail": "Permission denied"}
    else:
        assert res.status_code == 200, res.text
        # check that the view was applied:
        if view == "BASIC":
            assert res.json() == {"id": "123", "state": "COMPLETE"}
        elif view == "FULL":
            assert res.json() == {
                "id": "123",
                "state": "COMPLETE",
                "logs": [{"system_logs": ["blah"]}],
                "tags": {"AUTHZ": f"/users/{TEST_USER_ID}/gen3-workflow/tasks/123"},
            }
        else:  # view == None or "MINIMAL"
            assert res.json() == {
                "id": "123",
                "state": "COMPLETE",
                "logs": [{}],
                "tags": {"AUTHZ": f"/users/{TEST_USER_ID}/gen3-workflow/tasks/123"},
            }

    # check that the appropriate authorization checks were made
    if client.tes_resp_code != 500:
        mock_arborist_request.assert_called_with(
            method="POST",
            path=f"/auth/request",
            body=f'{{"requests": [{{"resource": "/users/{TEST_USER_ID}/gen3-workflow/tasks/123", "action": {{"service": "gen3-workflow", "method": "read"}}}}], "user": {{"token": "123"}}}}',
            authorized=client.authorized,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("client", client_parameters, indirect=True)
async def test_create_task(client, access_token_patcher):
    """
    Calls to `POST /ga4gh/tes/v1/tasks` should be forwarded to the TES server, along with the
    request body. A tag containing the user ID should be added.
    When the TES server returns an error, gen3-workflow should return it as well.
    If the user is not authorized, we should get a 403 error and no TES server requests should
    be made.
    """
    with mock_aws():
        aws_utils.iam_client = boto3.client("iam")

        res = await client.post(
            "/ga4gh/tes/v1/tasks",
            json={"name": "test-task"},
            headers={"Authorization": "bearer 123"},
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
            assert res.json() == {"id": "123"}
        mock_tes_server_request.assert_called_once_with(
            method="POST",
            path="/tasks",
            query_params={},
            body=f'{{"name": "test-task", "tags": {{"AUTHZ": "/users/{TEST_USER_ID}/gen3-workflow/tasks/TASK_ID_PLACEHOLDER"}}}}',
            status_code=client.tes_resp_code,
        )

    # check that the appropriate authorization checks were made
    mock_arborist_request.assert_any_call(
        method="POST",
        path=f"/auth/request",
        body=f'{{"requests": [{{"resource": "/services/workflow/gen3-workflow/tasks", "action": {{"service": "gen3-workflow", "method": "create"}}}}], "user": {{"token": "123"}}}}',
        authorized=client.authorized,
    )
    if client.authorized and client.tes_resp_code != 500:
        mock_arborist_request.assert_any_call(
            method="POST",
            path=f"/auth/request",
            body=f'{{"requests": [{{"resource": "/users/{TEST_USER_ID}/gen3-workflow/tasks", "action": {{"service": "gen3-workflow", "method": "read"}}}}], "user": {{"token": "123"}}}}',
            authorized=client.authorized,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "access_token_patcher", [{"user_id": NEW_TEST_USER_ID}], indirect=True
)
async def test_create_task_new_user(client, access_token_patcher):
    """
    When a user who does not yet have access to their own tasks creates a task, calls to Arborist
    should be made to create a resource, role, policy and user, and to grant the user access.
    """
    with mock_aws():
        aws_utils.iam_client = boto3.client("iam")

        res = await client.post(
            "/ga4gh/tes/v1/tasks",
            json={"name": "test-task"},
            headers={"Authorization": "bearer 123"},
        )

    assert res.status_code == 200, res.text
    assert res.json() == {"id": "123"}
    mock_tes_server_request.assert_called_once_with(
        method="POST",
        path="/tasks",
        query_params={},
        body=f'{{"name": "test-task", "tags": {{"AUTHZ": "/users/{NEW_TEST_USER_ID}/gen3-workflow/tasks/TASK_ID_PLACEHOLDER"}}}}',
        status_code=200,
    )

    # check arborist calls
    mock_arborist_request.assert_any_call(
        method="POST",
        path=f"/resource/users/{NEW_TEST_USER_ID}/gen3-workflow",
        body=f'{{"name": "tasks", "description": "Represents workflow tasks owned by user \'test-username-{NEW_TEST_USER_ID}\'"}}',
        authorized=True,
    )
    mock_arborist_request.assert_any_call(
        method="POST",
        path="/role",
        body='{"id": "gen3-workflow_task_owner", "permissions": [{"id": "gen3-workflow-reader", "action": {"service": "gen3-workflow", "method": "read"}}, {"id": "gen3-workflow-deleter", "action": {"service": "gen3-workflow", "method": "delete"}}]}',
        authorized=True,
    )
    mock_arborist_request.assert_any_call(
        method="POST",
        path="/policy",
        body=f'{{"id": "gen3-workflow_task_owner_sub-{NEW_TEST_USER_ID}", "description": "policy created by gen3-workflow for user \'test-username-{NEW_TEST_USER_ID}\'", "role_ids": ["gen3-workflow_task_owner"], "resource_paths": ["/users/{NEW_TEST_USER_ID}/gen3-workflow/tasks"]}}',
        authorized=True,
    )
    mock_arborist_request.assert_any_call(
        method="POST",
        path="/user",
        body=f'{{"name": "test-username-{NEW_TEST_USER_ID}"}}',
        authorized=True,
    )
    mock_arborist_request.assert_any_call(
        method="POST",
        path=f"/user/test-username-{NEW_TEST_USER_ID}/policy",
        body=f'{{"policy": "gen3-workflow_task_owner_sub-{NEW_TEST_USER_ID}"}}',
        authorized=True,
    )


@pytest.mark.asyncio
async def test_create_task_without_token(client):
    """
    Calls to `POST /ga4gh/tes/v1/tasks` without a token should return 401 error and no TES server requests should be made.
    """
    res = await client.post("/ga4gh/tes/v1/tasks", json={"name": "test-task"})
    assert res.status_code == 401, res.text
    assert res.json() == {"detail": "Must provide an access token"}
    mock_tes_server_request.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "req_body,status_code, error_message",
    [
        (
            {"executors": []},
            200,  # Forward the request to TES server, even if no images are found.
            "",
        ),
        (
            {"executors": [{}]},
            200,  # Forward the request to TES server, even if no images are found.
            "",
        ),
        (
            {
                "executors": [
                    {
                        "image": "public.ecr.aws/random/malicious/public:latest",  # not whitelisted
                    }
                ]
            },
            403,
            "The specified images are not allowed: ['public.ecr.aws/random/malicious/public:latest']",
        ),
        (
            {
                "executors": [
                    {
                        "image": "public.ecr.aws/random/approved/public:latest",  # whitelisted
                    }
                ]
            },
            200,
            "",
        ),
        (
            {
                "executors": [
                    {
                        "image": "quay.io/nextflow/bash",  # whitelisted
                    },
                    {
                        "image": "public.ecr.aws/random/approved/public:latest",  # whitelisted
                    },
                ]
            },
            200,
            "",
        ),
        (
            {
                "executors": [
                    {
                        "image": "quay.io/nextflow/bash",  # whitelisted
                    },
                    {
                        "image": "public.ecr.aws/random/malicious/public:latest",  # not whitelisted
                    },
                ]
            },
            403,
            "The specified images are not allowed: ['public.ecr.aws/random/malicious/public:latest']",
        ),
        (
            {
                "executors": [
                    {
                        "image": "public.ecr.aws/random/approved/public:abc",  # whitelisted with image name
                    },
                ]
            },
            200,
            "",
        ),
        (
            {
                "executors": [
                    {
                        "image": f"9876543210.dkr.ecr.us-east-1.amazonaws.com/approved/test-username-{TEST_USER_ID}:abc",  # whitelisted with username and image name
                    },
                ]
            },
            200,
            "",
        ),
        (
            {
                "executors": [
                    {
                        "image": f"9876543210.dkr.ecr.us-east-1.amazonaws.com/approved/test-username-{TEST_USER_ID}:xyz",  # not whitelisted with username and image name
                    },
                ]
            },
            403,
            f"The specified images are not allowed: ['9876543210.dkr.ecr.us-east-1.amazonaws.com/approved/test-username-{TEST_USER_ID}:xyz']",
        ),
        (
            {
                "executors": [
                    {
                        "image": f"9876543210.dkr.ecr.us-east-1.amazonaws.com/approved/test-username-{TEST_USER_ID}:xyz",  # not whitelisted with image name
                    },
                    {
                        "image": f"*.dkr.ecr.us-east-1.amazonaws.com/approved/test-username-{TEST_USER_ID}:test",  # whitelisted with image name and wildcard
                    },
                ]
            },
            403,
            f"The specified images are not allowed: ['9876543210.dkr.ecr.us-east-1.amazonaws.com/approved/test-username-{TEST_USER_ID}:xyz']",
        ),
    ],
)
async def test_create_task_with_whitelist_images(
    client, access_token_patcher, req_body, status_code, error_message
):
    """
    Requests to `POST /ga4gh-tes/v1/tasks` should be forwarded to the TES server along with the request body.
    Ensure that any image sent to the TES server belongs exclusively to whitelisted repositories specified in the configuration.
    """
    res = await client.post(
        "/ga4gh/tes/v1/tasks",
        json=req_body,
        headers={"Authorization": f"bearer 123"},
    )

    assert status_code == res.status_code, res.text
    if status_code == 403:
        assert error_message == json.loads(res.text).get("detail"), res.text
    elif status_code == 200:
        result_body = {
            "executors": req_body["executors"],
            "tags": {
                "AUTHZ": f"/users/{TEST_USER_ID}/gen3-workflow/tasks/TASK_ID_PLACEHOLDER"
            },
        }
        mock_tes_server_request.assert_called_once_with(
            method="POST",
            path="/tasks",
            query_params={},
            body=json.dumps(result_body),
            status_code=200,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("client", client_parameters, indirect=True)
@pytest.mark.parametrize("view", ["BASIC", "MINIMAL", "FULL", None])
async def test_list_tasks(client, access_token_patcher, view):
    """
    Calls to `GET /ga4gh/tes/v1/tasks` should be forwarded to the TES server, and any
    unsupported query params should be filtered out. Tasks the user does not have access
    to should be filtered out.
    When the TES server returns an error, gen3-workflow should return it as well.
    """
    url = f"/ga4gh/tes/v1/tasks?state=COMPLETE&unsupported_param=value"
    if view:
        url += f"&view={view}"
    res = await client.get(url, headers={"Authorization": "bearer 123"})

    # the call to the TES server always has `view=FULL` so we get the AUTHZ tag
    mock_tes_server_request.assert_called_once_with(
        method="GET",
        path="/tasks",
        query_params={"state": "COMPLETE", "view": "FULL"},
        body="",
        status_code=client.tes_resp_code,
    )

    if client.tes_resp_code == 500:
        assert res.status_code == 500, res.text
        assert res.json() == {"detail": "TES server error"}
    else:
        assert res.status_code == 200, res.text
        if not client.authorized:
            assert res.json() == {"tasks": []}
        else:
            # check that the view was applied:
            if view == "BASIC":
                assert res.json() == {"tasks": [{"id": "123", "state": "COMPLETE"}]}
            elif view == "FULL":
                assert res.json() == {
                    "tasks": [
                        {
                            "id": "123",
                            "state": "COMPLETE",
                            "logs": [{"system_logs": ["blah"]}],
                            "tags": {
                                "AUTHZ": f"/users/{TEST_USER_ID}/gen3-workflow/tasks/123"
                            },
                        }
                    ]
                }
            else:  # view == None or "MINIMAL"
                assert res.json() == {
                    "tasks": [
                        {
                            "id": "123",
                            "state": "COMPLETE",
                            "logs": [{}],
                            "tags": {
                                "AUTHZ": f"/users/{TEST_USER_ID}/gen3-workflow/tasks/123"
                            },
                        }
                    ]
                }

    # check that the appropriate authorization checks were made
    if client.tes_resp_code != 500:
        mock_arborist_request.assert_called_with(
            method="POST",
            path="/auth/mapping",
            body="",
            authorized=client.authorized,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("client", client_parameters, indirect=True)
async def test_delete_task(client, access_token_patcher):
    """
    Calls to `POST /ga4gh/tes/v1/tasks/<task ID>:cancel` should be forwarded to the TES server,
    with no request body.
    When the TES server returns an error, gen3-workflow should return it as well.
    """
    res = await client.post(
        "/ga4gh/tes/v1/tasks/123:cancel",
        json={"unsupported_body": "value"},
        headers={"Authorization": "bearer 123"},
    )

    # there is always a 1st call with view=FULL to get the AUTHZ tag
    mock_tes_server_request.assert_any_call(
        method="GET",
        path="/tasks/123",
        query_params={"view": "FULL"},
        body="",
        status_code=client.tes_resp_code,
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

        # if the 1st call is successful, an additional call is made to cancel the task
        mock_tes_server_request.assert_called_with(
            method="POST",
            path="/tasks/123:cancel",
            query_params={},
            body="",
            status_code=client.tes_resp_code,
        )

    # check that the appropriate authorization checks were made
    if client.tes_resp_code != 500:
        mock_arborist_request.assert_called_with(
            method="POST",
            path=f"/auth/request",
            body=f'{{"requests": [{{"resource": "/users/{TEST_USER_ID}/gen3-workflow/tasks/123", "action": {{"service": "gen3-workflow", "method": "delete"}}}}], "user": {{"token": "123"}}}}',
            authorized=client.authorized,
        )


@pytest.mark.asyncio
async def test_system_keys(reset_database, client, access_token_patcher, session):
    """
    TODO
    Calls to `POST /ga4gh/tes/v1/tasks` should be forwarded to the TES server, along with the
    request body. A tag containing the user ID should be added.
    When the TES server returns an error, gen3-workflow should return it as well.
    If the user is not authorized, we should get a 403 error and no TES server requests should
    be made.
    """
    # the database contains no system keys at first
    query = select(SystemKey)
    result = await session.execute(query)
    assert len(result.scalars().all()) == 0

    # call `get_system_key()` - since there are no existing keys, it should generate one
    with mock_aws():
        aws_utils.iam_client = boto3.client("iam")
        key_id, key_secret = await get_system_key(TEST_USER_ID)

    # check that the generated key is in the database
    query = select(SystemKey).where(SystemKey.user_id == TEST_USER_ID)
    result = await session.execute(query)
    all_keys = result.scalars().all()
    assert len(all_keys) == 1
    oldest_key = all_keys[0]
    assert oldest_key.user_id == TEST_USER_ID, oldest_key
    assert oldest_key.created_time, oldest_key  # should be generated automatically
    assert oldest_key.key_id == key_id, oldest_key

    # the key secret should be encrypted in the database
    # assert oldest_key.key_secret != key_secret, oldest_key

    # add a 2nd key to the database, set its creation date to tomorrow. it's now the newest key
    # in the database
    newest_key = SystemKey(
        key_id="abcd",
        key_secret="xyz",
        user_id=TEST_USER_ID,
        created_time=datetime.now() + timedelta(days=1),
    )
    session.add(newest_key)
    await session.commit()

    # check that both keys are in the database
    query = select(SystemKey).where(SystemKey.user_id == TEST_USER_ID)
    result = await session.execute(query)
    all_keys = result.scalars().all()
    assert len(all_keys) == 2
    assert all_keys[0].key_id == oldest_key.key_id
    assert all_keys[1].key_id == newest_key.key_id

    # call `get_system_key()` - it should return the newest key of the 2
    key_id, key_secret = await get_system_key(TEST_USER_ID)
    assert key_id == newest_key.key_id
    # assert key_secret =
