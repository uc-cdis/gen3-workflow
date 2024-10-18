import json
import os
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qsl, urlparse

from fastapi import Request
import httpx
import pytest
import pytest_asyncio
from starlette.config import environ

# Set GEN3WORKFLOW_CONFIG_PATH *before* loading the app which loads the configuration
CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
environ["GEN3WORKFLOW_CONFIG_PATH"] = os.path.join(
    CURRENT_DIR, "test-gen3workflow-config.yaml"
)

from gen3workflow.app import get_app
from gen3workflow.config import config


TEST_USER_ID = "64"
NEW_TEST_USER_ID = "784"  # a new user that does not already exist in arborist


@pytest.fixture(scope="function")
def access_token_patcher(client, request):
    """
    The `access_token` function will return a token linked to a test user.
    This fixture should be used explicitely instead of the automatic
    `access_token_user_client_patcher` fixture for endpoints that do not
    support client tokens.
    """
    user_id = TEST_USER_ID
    if hasattr(request, "param"):
        user_id = request.param.get("user_id", user_id)

    async def get_access_token(*args, **kwargs):
        return {
            "sub": user_id,
            "context": {"user": {"name": f"test-username-{user_id}"}},
        }

    access_token_mock = MagicMock()
    access_token_mock.return_value = get_access_token

    access_token_patch = patch("gen3workflow.auth.access_token", access_token_mock)
    access_token_patch.start()

    yield access_token_mock

    access_token_patch.stop()


def mock_arborist_request_function(method: str, path: str, body: str, authorized: bool):
    # paths to reponses: { URL: { METHOD: response body } }
    paths_to_responses = {
        # access check:
        "/auth/request": {"POST": (200, {"auth": authorized})},
        # list of things the user has access to:
        "/auth/mapping": {
            "POST": (
                200,
                (
                    {
                        f"/users/{TEST_USER_ID}/gen3-workflow/tasks/TASK_ID_PLACEHOLDER": [
                            {"service": "gen3-workflow", "method": "read"}
                        ],
                    }
                    if authorized
                    else {}
                ),
            ),
        },
        # resource, role, policy and user creation:
        f"/resource/users/{NEW_TEST_USER_ID}/gen3-workflow": {"POST": (200, {})},
        "/role": {"POST": (200, {})},
        "/policy": {"POST": (200, {})},
        "/user": {"POST": (200, {})},
        # grant user access to a policy:
        f"/user/test-username-{NEW_TEST_USER_ID}/policy": {"POST": (204, {})},
    }
    text, out = None, None
    if path not in paths_to_responses:
        print(
            f"Unable to mock Arborist request: '{path}' is not in `urls_to_responses`."
        )
        status_code = 404
        text = "NOT FOUND"
    elif method not in paths_to_responses[path]:
        status_code = 405
        text = "METHOD NOT ALLOWED"
    else:
        status_code, content = paths_to_responses[path][method]
        try:
            body = json.loads(body)
        except Exception:
            body = {}
        # exception to mock a user with access to create tasks, but no existing access to their own
        # tasks in arborist
        if (
            path == "/auth/request"
            and body["requests"][0]["resource"]
            == f"/users/{NEW_TEST_USER_ID}/gen3-workflow/tasks"
        ):
            content["auth"] = False

        if isinstance(content, dict):
            out = content
        else:
            text = content

    return httpx.Response(status_code=status_code, json=out, text=text)


def mock_tes_server_request_function(
    method: str, path: str, query_params: dict, body: str, status_code: int
):
    # paths to reponses: { URL: { METHOD: response body } }
    paths_to_responses = {
        "/service-info": {"GET": {"name": "TES server"}},
        "/tasks": {
            "GET": {
                "tasks": [
                    {
                        "id": "123",
                        "tags": {
                            "AUTHZ": f"/users/{TEST_USER_ID}/gen3-workflow/tasks/TASK_ID_PLACEHOLDER"
                        },
                    },
                    {"id": "456"},
                    {
                        "id": "789",
                        "tags": {
                            "AUTHZ": f"/users/OTHER_USER/gen3-workflow/tasks/TASK_ID_PLACEHOLDER"
                        },
                    },
                ]
            },
            "POST": {"id": "12345"},
        },
        "/tasks/12345": {
            "GET": (
                {
                    "id": "12345",
                    "tags": {
                        "AUTHZ": f"/users/{TEST_USER_ID}/gen3-workflow/tasks/TASK_ID_PLACEHOLDER"
                    },
                }
                if query_params.get("view") == "FULL"
                else {"id": "12345"}
            )
        },
        "/tasks/12345:cancel": {"POST": {}},
    }
    text, out = None, None
    if path not in paths_to_responses:
        print(
            f"Unable to mock TES server request: '{path}' is not in `paths_to_responses`."
        )
        status_code = 404
        text = "NOT FOUND"
    elif method not in paths_to_responses[path]:
        status_code = 405
        text = "METHOD NOT ALLOWED"
    else:
        content = paths_to_responses[path][method]
        if status_code != 200:
            text = "TES server error"
        elif isinstance(content, dict):
            out = content
        else:
            text = content
    return httpx.Response(status_code=status_code, json=out, text=text)


# making these functions into mocks allows tests to check the requests that were made, for
# example: `mock_tes_server_request.assert_called_with(...)`
mock_tes_server_request = MagicMock(side_effect=mock_tes_server_request_function)
mock_arborist_request = MagicMock(side_effect=mock_arborist_request_function)


@pytest_asyncio.fixture(scope="function", autouse=True)
async def reset_requests_mocks():
    """
    Before each test, reset `mock_tes_server_request` and `mock_arborist_request` to forget
    previous function calls.
    """
    global mock_tes_server_request
    global mock_arborist_request
    mock_tes_server_request.reset_mock()
    mock_arborist_request.reset_mock()


@pytest_asyncio.fixture(scope="session")
async def client(request):
    """
    Requests made by the tests to the app use a real HTTPX client.
    Requests made by the app to external services (such as the TES server and Arborist) use
    a mocked client.
    """
    tes_resp_code = 200
    authorized = True
    if hasattr(request, "param"):
        tes_resp_code = request.param.get("tes_resp_code", 200)
        authorized = request.param.get("authorized", True)

    async def handle_request(request: Request):
        url = str(request.url)
        parsed_url = urlparse(url)
        mocked_response = None
        if url.startswith(config["TES_SERVER_URL"]):
            path = url[len(config["TES_SERVER_URL"]) :].split("?")[0].rstrip("/")
            mocked_response = mock_tes_server_request(
                method=request.method,
                path=path,
                query_params=dict(parse_qsl(parsed_url.query)),
                body=request.content.decode(),
                status_code=tes_resp_code,
            )
        elif url.startswith(config["ARBORIST_URL"]):
            path = url[len(config["ARBORIST_URL"]) :].split("?")[0].rstrip("/")
            mocked_response = mock_arborist_request(
                method=request.method,
                path=path,
                body=request.content.decode(),
                authorized=authorized,
            )

        if mocked_response is not None:
            print(f"Mocking request '{request.method} {url}'")
            return mocked_response
        else:
            print(f"Not mocking request '{request.method} {url}'")
            httpx_client_function = getattr(httpx.AsyncClient(), request.method.lower())
            return await httpx_client_function(url)

    # set the httpx clients used by the app and by the Arborist client to mock clients that
    # call `handle_request`
    mock_httpx_client = httpx.AsyncClient(transport=httpx.MockTransport(handle_request))
    app = get_app(httpx_client=mock_httpx_client)
    app.arborist_client.client_cls = lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(handle_request)
    )

    # the tests use a real httpx client that forwards requests to the app
    async with httpx.AsyncClient(
        app=app, base_url="http://test-gen3-wf"
    ) as real_httpx_client:
        # for easier access to the param in the tests
        real_httpx_client.tes_resp_code = tes_resp_code
        real_httpx_client.authorized = authorized
        yield real_httpx_client
