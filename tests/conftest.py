"""
See https://github.com/uc-cdis/gen3-user-data-library/blob/main/tests/conftest.py#L1
"""

from datetime import datetime
from dateutil.tz import tzutc
import json
import os
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qsl, urlparse

from fastapi import Request
import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.config import environ
from threading import Thread
import uvicorn

# Set up the config *before* loading the app, which loads the configuration
CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
environ["GEN3WORKFLOW_CONFIG_PATH"] = os.path.join(
    CURRENT_DIR, "test-gen3workflow-config.yaml"
)
from gen3workflow.config import config

config.validate()

from gen3workflow.app import get_app
from tests.migrations.migration_utils import MigrationRunner


TEST_USER_ID = "64"
NEW_TEST_USER_ID = "784"  # a new user that does not already exist in arborist

# a "ListBucketResult" S3 response from AWS, and the corresponding response as parsed by boto3
MOCKED_S3_RESPONSE_XML = f"""<?xml version="1.0" encoding="UTF-8"?>\n<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}</Name><Prefix>test-folder/test-file1.txt</Prefix><Marker></Marker><MaxKeys>250</MaxKeys><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated><Contents><Key>test-folder/test-file1.txt</Key><LastModified>2024-12-09T22:32:20.000Z</LastModified><ETag>&quot;something&quot;</ETag><Size>211</Size><Owner><ID>something</ID><DisplayName>something</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>"""
MOCKED_S3_RESPONSE_DICT = {
    "ResponseMetadata": {
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "server": "uvicorn",
            "content-length": "569",
            "content-type": "application/xml",
        },
        "RetryAttempts": 0,
    },
    "IsTruncated": False,
    "Marker": "",
    "Contents": [
        {
            "Key": "test-folder/test-file1.txt",
            "LastModified": datetime(2024, 12, 9, 22, 32, 20, tzinfo=tzutc()),
            "ETag": '"something"',
            "Size": 211,
            "StorageClass": "STANDARD",
            "Owner": {"DisplayName": "something", "ID": "something"},
        }
    ],
    "Name": f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}",
    "Prefix": "test-folder/test-file1.txt",
    "MaxKeys": 250,
    "EncodingType": "url",
}


@pytest_asyncio.fixture(scope="session", autouse=True)
async def migrate_database_to_the_latest():
    """
    Migrate the database to the latest version before running the tests.
    """
    migration_runner = MigrationRunner()
    await migration_runner.upgrade("head")


@pytest_asyncio.fixture(scope="function")
async def reset_database():
    """
    Most tests do not store data in the database, so for performance this fixture does not
    autorun. To be used in tests that interact with the database.
    """
    migration_runner = MigrationRunner()
    await migration_runner.downgrade("base")
    await migration_runner.upgrade("head")

    yield

    await migration_runner.downgrade("base")
    await migration_runner.upgrade("head")


@pytest_asyncio.fixture(scope="function")
async def session():
    """
    Database session
    """
    engine = create_async_engine(
        config["DB_CONNECTION_STRING"], echo=False, future=True
    )
    session_maker = async_sessionmaker(
        engine, expire_on_commit=False, autocommit=False, autoflush=False
    )

    async with session_maker() as session:
        yield session

    await engine.dispose()


@pytest.fixture(scope="function")
def access_token_patcher(request):
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
    # paths to reponses: { URL: { METHOD: (status code, response body) } }
    paths_to_responses = {
        # access check:
        "/auth/request": {"POST": (200, {"auth": authorized})},
        # list of things the user has access to:
        "/auth/mapping": {
            "POST": (
                200,
                (
                    {
                        f"/users/{TEST_USER_ID}/gen3-workflow/tasks/123": [
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
    accessible_task = {
        "id": "123",
        "state": "COMPLETE",
        "logs": [{"system_logs": ["blah"]}],
        "tags": {
            "AUTHZ": f"/users/{TEST_USER_ID}/gen3-workflow/tasks/TASK_ID_PLACEHOLDER"
        },
    }
    # paths to reponses: { URL: { METHOD: response body } }
    paths_to_responses = {
        "/service-info": {"GET": {"name": "TES server"}},
        "/tasks": {
            "GET": {
                "tasks": [
                    # a task the test user has access to:
                    accessible_task,
                    # a task the test user does not have access to:
                    {
                        "id": "789",
                        "state": "COMPLETE",
                        "logs": [{"system_logs": ["blah"]}],
                        "tags": {
                            "AUTHZ": f"/users/OTHER_USER/gen3-workflow/tasks/TASK_ID_PLACEHOLDER"
                        },
                    },
                    # test that the app can handle a task with no tags:
                    {"id": "456", "state": "COMPLETE"},
                ],
            },
            "POST": {"id": "123"},
        },
        "/tasks/123": {"GET": accessible_task},
        "/tasks/123:cancel": {"POST": {}},
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
            # mock calls to the TES server
            path = url[len(config["TES_SERVER_URL"]) :].split("?")[0].rstrip("/")
            mocked_response = mock_tes_server_request(
                method=request.method,
                path=path,
                query_params=dict(parse_qsl(parsed_url.query)),
                body=request.content.decode(),
                status_code=tes_resp_code,
            )
        elif url.startswith(config["ARBORIST_URL"]):
            # mock calls to Arborist
            path = url[len(config["ARBORIST_URL"]) :].split("?")[0].rstrip("/")
            mocked_response = mock_arborist_request(
                method=request.method,
                path=path,
                body=request.content.decode(),
                authorized=authorized,
            )
        elif url.startswith(
            f"https://gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}.s3.amazonaws.com"
        ):
            # mock calls to AWS S3
            mocked_response = httpx.Response(
                status_code=200,
                text=MOCKED_S3_RESPONSE_XML,
                headers={"content-type": "application/xml"},
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

    get_url = False
    if hasattr(request, "param"):
        get_url = request.param.get("get_url", get_url)

    if get_url:  # for tests that need to hit the app URL directly
        host = "0.0.0.0"
        port = 8080

        def run_uvicorn():
            uvicorn.run(app, host=host, port=port)

        # start the app in a separate thread
        thread = Thread(target=run_uvicorn)
        thread.daemon = True  # ensures the thread ends when the test ends
        thread.start()

        yield f"http://{host}:{port}"  # URL to use in the tests
    else:
        # the tests use a real httpx client that forwards requests to the app
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test-gen3-wf"
        ) as real_httpx_client:
            # for easier access to the param in the tests
            real_httpx_client.tes_resp_code = tes_resp_code
            real_httpx_client.authorized = authorized
            yield real_httpx_client
