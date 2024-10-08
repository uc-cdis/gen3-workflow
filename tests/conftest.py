import os
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

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


@pytest.fixture(scope="function")
def access_token_patcher(client, request):
    """
    The `access_token` function will return a token linked to a test user.
    This fixture should be used explicitely instead of the automatic
    `access_token_user_client_patcher` fixture for endpoints that do not
    support client tokens.
    """

    async def get_access_token(*args, **kwargs):
        return {"sub": TEST_USER_ID}

    access_token_mock = MagicMock()
    access_token_mock.return_value = get_access_token

    access_token_patch = patch("gen3workflow.auth.access_token", access_token_mock)
    access_token_patch.start()

    yield access_token_mock

    access_token_patch.stop()


def mock_tes_server_request_function(
    method: str, path: str, query_params: str, body: str, status_code: int
):
    # paths to reponses: { URL: { METHOD: response body } }
    paths_to_responses = {
        "/service-info": {"GET": {"name": "TES server"}},
        "/tasks": {"GET": {"tasks": [{"id": "12345"}]}, "POST": {"id": "12345"}},
        "/tasks/12345": {"GET": {"id": "12345"}},
        "/tasks/12345:cancel": {"POST": {}},
    }
    text, body = None, None
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
            body = content
        else:
            text = content
    return httpx.Response(status_code=status_code, json=body, text=text)


# making this function a mock allows tests to check the requests that were made, for
# example: `mock_tes_server_request.assert_called_with(...)`
mock_tes_server_request = MagicMock(side_effect=mock_tes_server_request_function)


@pytest_asyncio.fixture(scope="function", autouse=True)
async def reset_mock_tes_server_request():
    """
    Before each test, reset `mock_tes_server_request` to forget previous function calls.
    """
    global mock_tes_server_request
    mock_tes_server_request.reset_mock()


def mock_arborist_request(
    method: str, url: str, authorized: bool
):
    # URLs to reponses: { URL: { METHOD: response body } }
    urls_to_responses = {
        "http://test-arborist-server/auth/request": {
            "POST": {"auth": authorized}
        },
    }

    text, body = None, None
    if url not in urls_to_responses:
        print(
            f"Unable to mock Arborist request: '{url}' is not in `urls_to_responses`."
        )
        status_code = 404
        text = "NOT FOUND"
    elif method not in urls_to_responses[url]:
        status_code = 405
        text = "METHOD NOT ALLOWED"
    else:
        content = urls_to_responses[url][method]
        status_code = 200
        if isinstance(content, dict):
            body = content
        else:
            text = content

    return httpx.Response(status_code=status_code, json=body, text=text)


@pytest_asyncio.fixture(scope="session")
async def client(request):
    """
    Requests made by the tests to the app use a real HTTPX client.
    Requests made by the app to external mocked services (such as Funnel) use a mocked client.
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
            path = url[len(config["TES_SERVER_URL"]) :].split("?")[0]
            mocked_response = mock_tes_server_request(
                method=request.method,
                path=path,
                query_params=parsed_url.query,
                body=request.content.decode(),
                status_code=tes_resp_code,
            )
        elif url.startswith(config["ARBORIST_URL"]):
            mocked_response = mock_arborist_request(
                method=request.method,
                url=url,
                authorized=authorized,
            )

        if mocked_response is not None:
            print(
                f"Mocking request '{request.method} {url}' to return code {tes_resp_code}"
            )
            return mocked_response
        else:
            print(f"Not mocking request '{request.method} {url}'")
            httpx_client_function = getattr(httpx.AsyncClient(), request.method.lower())
            return await httpx_client_function(url)

    mock_httpx_client = httpx.AsyncClient(transport=httpx.MockTransport(handle_request))
    app = get_app(httpx_client=mock_httpx_client)
    app.arborist_client.client_cls = lambda: httpx.AsyncClient(transport=httpx.MockTransport(handle_request))
    async with httpx.AsyncClient(app=app, base_url="http://test-gen3-wf") as real_httpx_client:
        # for easier access to the param in the tests
        real_httpx_client.tes_resp_code = tes_resp_code
        real_httpx_client.authorized = authorized
        yield real_httpx_client
