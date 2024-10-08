import os
from unittest.mock import MagicMock
from urllib.parse import urlparse

from fastapi import Request
import httpx
import pytest_asyncio
from starlette.config import environ

# Set GEN3WORKFLOW_CONFIG_PATH *before* loading the app which loads the configuration
CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
environ["GEN3WORKFLOW_CONFIG_PATH"] = os.path.join(
    CURRENT_DIR, "test-gen3workflow-config.yaml"
)

from gen3workflow.app import get_app
from gen3workflow.config import config


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


@pytest_asyncio.fixture(scope="session")
async def client(request):
    """
    Requests made by the tests to the app use a real HTTPX client.
    Requests made by the app to external mocked services (such as Funnel) use a mocked client.
    """
    status_code = 200
    if hasattr(request, "param"):
        status_code = request.param.get("status_code", 200)

    async def handle_request(request: Request):
        url = str(request.url)

        if url.startswith(config["TES_SERVER_URL"]):
            print(
                f"Mocking request '{request.method} {url}' to return code {status_code}"
            )
            parsed_url = urlparse(url)
            path = url[len(config["TES_SERVER_URL"]) :].split("?")[0]
            return mock_tes_server_request(
                method=request.method,
                path=path,
                query_params=parsed_url.query,
                body=request.content.decode(),
                status_code=status_code,
            )
        else:
            print(f"Not mocking request '{request.method} {url}'")
            httpx_client_function = getattr(httpx.AsyncClient(), request.method.lower())
            return await httpx_client_function(url)

    mock_httpx_client = httpx.AsyncClient(transport=httpx.MockTransport(handle_request))
    app = get_app(httpx_client=mock_httpx_client)
    async with httpx.AsyncClient(app=app, base_url="http://test-gen3-wf") as real_httpx_client:
        real_httpx_client.status_code = status_code  # for easier access to the param in the tests
        yield real_httpx_client
