import os
from unittest.mock import MagicMock
from urllib.parse import urlparse

# import asyncio
# from alembic.config import main as alembic_main
# import copy
from fastapi import Request
import httpx

# import pytest
import pytest_asyncio
from starlette.config import environ

# from starlette.testclient import TestClient
# from unittest.mock import AsyncMock, MagicMock, patch

# Set GEN3WORKFLOW_CONFIG_PATH *before* loading the app which loads the configuration
CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
environ["GEN3WORKFLOW_CONFIG_PATH"] = os.path.join(
    CURRENT_DIR, "test-gen3workflow-config.yaml"
)

from gen3workflow.app import get_app
from gen3workflow.config import config
from gen3workflow.routes.ga4gh_tes import get_request_body


# @pytest.fixture(scope="session")
# def app():
#     app = get_app()
#     return app


# @pytest.fixture(autouse=True, scope="session")
# def setup_test_database():
#     """
#     At teardown, restore original config and reset test DB.
#     """
#     saved_config = copy.deepcopy(config._configs)

#     alembic_main(["--raiseerr", "upgrade", "head"])

#     yield

#     # restore old configs
#     config.update(saved_config)

#     if not config["TEST_KEEP_DB"]:
#         alembic_main(["--raiseerr", "downgrade", "base"])


def mock_tes_server_request(
    method: str, path: str, query_params: str, body: str, status_code: int
):
    # URLs to reponses: { URL: { METHOD: ( code, content ) } }
    paths_to_responses = {
        "/service-info": {"GET": {"name": "TES server"}},
        "/tasks": {"GET": {"tasks": [{"id": "12345"}]}, "POST": {"id": "12345"}},
        "/tasks/12345": {"GET": {"id": "12345"}},
        "/tasks/12345:cancel": {"POST": {}},
    }
    text, json = None, None
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
            json = content
        else:
            text = content
    return httpx.Response(status_code=status_code, json=json, text=text)


# making this function a mock allows tests to check the requests that were made, for
# example: `mock_tes_server_request.assert_called_with(...)`
mock_tes_server_request = MagicMock(side_effect=mock_tes_server_request)


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
        print(
            f"Mocking request '{request.method} {request.url}' to return code {status_code}"
        )
        url = str(request.url)
        parsed_url = urlparse(url)
        if url.startswith(config["TES_SERVER_URL"]):
            path = url[len(config["TES_SERVER_URL"]) :].split("?")[0]
            return mock_tes_server_request(
                method=request.method,
                path=path,
                query_params=parsed_url.query,
                body=request.content.decode(),
                status_code=status_code,
            )
        return await real_httpx_client.get("/_status")

    mock_httpx_client = httpx.AsyncClient(transport=httpx.MockTransport(handle_request))
    app = get_app(httpx_client=mock_httpx_client)
    async with httpx.AsyncClient(app=app, base_url="http://test") as real_httpx_client:
        real_httpx_client.status_code = status_code
        yield real_httpx_client


# @pytest.fixture(scope="function")
# def list_policies_patcher(test_data):
#     """
#     This fixture patches the list_policies method with a mock implementation based on
#     the test_data provided which is a dictionary consisting of resource_path(s) and
#     policy_id wherever appropriate
#     """
#     resource_paths = (
#         test_data["resource_paths"]
#         if "resource_paths" in test_data
#         else [test_data["resource_path"]]
#     )
#     expanded_permissions = (
#         test_data["permissions"]
#         if "permissions" in test_data
#         else [
#             {
#                 "id": permission,
#                 "description": "",
#                 "action": {
#                     "service": "*",
#                     "method": permission,
#                 },
#             }
#             for permission in ["reader", "storage_reader"]
#         ]
#     )
#     policy_id = (
#         test_data["policy_id"]
#         if "policy_id" in test_data
#         else get_auto_policy_id(resource_paths=[resource_paths[0]])
#     )

#     future = asyncio.Future()
#     future.set_result(
#         {
#             "policies": [
#                 {
#                     "id": policy_id,
#                     "resource_paths": resource_paths,
#                     "roles": [
#                         {
#                             "id": "reader",
#                             "description": "",
#                             "permissions": expanded_permissions,
#                         }
#                     ],
#                 },
#             ]
#         }
#     )

#     list_policies_mock = MagicMock()
#     list_policies_mock.return_value = future
#     policy_expand_patch = patch(
#         "requestor.routes.query.arborist.list_policies", list_policies_mock
#     )
#     policy_expand_patch.start()

#     yield

#     policy_expand_patch.stop()


# @pytest.fixture(scope="function")
# def list_roles_patcher():
#     """
#     This fixture patches the list_roles method.
#     """

#     future = asyncio.Future()
#     future.set_result(
#         {
#             "roles": [
#                 {
#                     "id": "study_registrant",
#                     "permissions": [
#                         {
#                             "id": "study_registration",
#                             "action": {
#                                 "service": "study_registration",
#                                 "method": "access",
#                             },
#                         },
#                     ],
#                 },
#                 {
#                     "id": "/mds_user",
#                     "permissions": [
#                         {
#                             "id": "mds_access",
#                             "action": {"service": "mds_gateway", "method": "access"},
#                         },
#                     ],
#                 },
#                 {
#                     "id": "/study_user",
#                     "permissions": [
#                         {
#                             "id": "study_access",
#                             "action": {"service": "study_access", "method": "access"},
#                         },
#                     ],
#                 },
#             ]
#         }
#     )

#     list_roles_mock = MagicMock()
#     list_roles_mock.return_value = future
#     role_patch = patch("requestor.routes.query.arborist.list_roles", list_roles_mock)
#     role_patch.start()

#     yield

#     role_patch.stop()


# @pytest.fixture(autouse=True, scope="function", params=["user_token", "client_token"])
# def access_token_user_client_patcher(client, request):
#     """
#     The `access_token` function will return first a token linked to a test
#     user, then a token linked to a test client.
#     """

#     async def get_access_token(*args, **kwargs):
#         if request.param == "user_token":
#             return {"sub": "1", "context": {"user": {"name": "requestor_user"}}}
#         if request.param == "client_token":
#             return {"context": {}, "azp": "test-client-id"}

#     access_token_mock = MagicMock()
#     access_token_mock.return_value = get_access_token

#     access_token_patch = patch("requestor.auth.access_token", access_token_mock)
#     access_token_patch.start()

#     yield access_token_mock

#     access_token_patch.stop()


# @pytest.fixture(scope="function")
# def access_token_user_only_patcher(client, request):
#     """
#     The `access_token` function will return a token linked to a test user.
#     This fixture should be used explicitely instead of the automatic
#     `access_token_user_client_patcher` fixture for endpoints that do not
#     support client tokens.
#     """

#     async def get_access_token(*args, **kwargs):
#         return {"sub": "1", "context": {"user": {"name": "requestor_user"}}}

#     access_token_mock = MagicMock()
#     access_token_mock.return_value = get_access_token

#     access_token_patch = patch("requestor.auth.access_token", access_token_mock)
#     access_token_patch.start()

#     yield access_token_mock

#     access_token_patch.stop()


# @pytest.fixture(autouse=True)
# def clean_db():
#     """
#     Before each test, delete all existing requests from the DB
#     """
#     # The code below doesn't work because of this issue
#     # https://github.com/encode/starlette/issues/440, so for now reset
#     # using alembic.
#     # pytest-asyncio = "^0.14.0"
#     # from requestor.models import Request as RequestModel
#     # @pytest.mark.asyncio
#     # async def clean_db():
#     #     await RequestModel.delete.gino.all()
#     #     yield

#     alembic_main(["--raiseerr", "downgrade", "base"])
#     alembic_main(["--raiseerr", "upgrade", "head"])

#     yield


# @pytest.fixture(scope="function")
# def mock_arborist_requests(request):
#     """
#     This fixture returns a function which you call to mock the call to
#     arborist client's auth_request method.
#     By default, it returns a 200 response. If parameter "authorized" is set
#     to False, it raises a 401 error.
#     """

#     def do_patch(authorized=True):
#         # URLs to reponses: { URL: { METHOD: ( content, code ) } }
#         urls_to_responses = {
#             "http://arborist-service/auth/request": {
#                 "POST": ({"auth": authorized}, 200)
#             },
#             "http://arborist-service/user/requestor_user": {
#                 "GET": (
#                     {
#                         "name": "requestor_user",
#                         "groups": [],
#                         "policies": [{"policy": "test-policy"}],
#                     },
#                     200 if authorized else 403,
#                 )
#             },
#             "http://arborist-service/user/requestor_user/policy": {
#                 "POST": ({}, 204 if authorized else 403)
#             },
#             "http://arborist-service/user/other_user/policy": {
#                 "POST": ({}, 204 if authorized else 403)
#             },
#             "http://arborist-service/user/requestor_user/policy/test-policy": {
#                 "DELETE": ({}, 204 if authorized else 403)
#             },
#             "http://arborist-service/policy/?expand": {
#                 "GET": (
#                     {
#                         "policies": [
#                             {
#                                 "id": "test-policy",
#                                 "resource_paths": ["/my/resource"],
#                                 "roles": [
#                                     {
#                                         "id": "reader",
#                                         "description": "",
#                                         "permissions": [
#                                             {
#                                                 "id": "read",
#                                                 "description": "",
#                                                 "action": {
#                                                     "service": "*",
#                                                     "method": "read",
#                                                 },
#                                             }
#                                         ],
#                                     }
#                                 ],
#                             },
#                             {
#                                 "id": "test-policy-with-redirect",
#                                 "resource_paths": ["/resource-with-redirect/resource"],
#                                 "roles": [],
#                             },
#                             {
#                                 "id": "test-policy-with-external-calls",
#                                 "resource_paths": [
#                                     "/resource-with-external-calls/resource"
#                                 ],
#                                 "roles": [],
#                             },
#                             {
#                                 "id": "test-policy-with-authed-external-call",
#                                 "resource_paths": [
#                                     "/resource-with-authed-external-call/resource"
#                                 ],
#                                 "roles": [],
#                             },
#                             {
#                                 "id": "test-policy-with-redirect-and-external-call",
#                                 "resource_paths": [
#                                     "/resource-with-redirect-and-external-call"
#                                 ],
#                                 "roles": [],
#                             },
#                             {
#                                 "id": "test-policy-i-cant-access",
#                                 "resource_paths": ["something-i-cant-access"],
#                                 "roles": [],
#                             },
#                             {
#                                 "id": "my.resource_accessor",
#                                 "resource_paths": ["/my/resource"],
#                                 "roles": [],
#                             },
#                             {
#                                 "id": "test-existing-policy",
#                                 "resource_paths": [],
#                                 "roles": [],
#                             },
#                             {
#                                 "id": "test-existing-policy-2",
#                                 "resource_paths": [],
#                                 "roles": [],
#                             },
#                         ]
#                     },
#                     204 if authorized else 403,
#                 )
#             },
#             "http://arborist-service/auth/mapping": {
#                 "POST": (
#                     {"/": [{"service": "*", "method": "*"}]} if authorized else {},
#                     200,
#                 )
#             },
#         }

#         def make_mock_response(method, url, *args, **kwargs):
#             method = method.upper()
#             mocked_response = MagicMock(requests.Response)

#             if url not in urls_to_responses:
#                 mocked_response.status_code = 404
#                 mocked_response.text = "NOT FOUND"
#             elif method not in urls_to_responses[url]:
#                 mocked_response.status_code = 405
#                 mocked_response.text = "METHOD NOT ALLOWED"
#             else:
#                 content, code = urls_to_responses[url][method]
#                 mocked_response.status_code = code
#                 if isinstance(content, dict):
#                     mocked_response.json.return_value = content
#                 else:
#                     mocked_response.text = content

#             return mocked_response

#         mocked_method = AsyncMock(side_effect=make_mock_response)
#         patch_method = patch(
#             "gen3authz.client.arborist.async_client.httpx.AsyncClient.request",
#             mocked_method,
#         )

#         patch_method.start()
#         request.addfinalizer(patch_method.stop)

#     return do_patch


# @pytest.fixture(autouse=True)
# def arborist_authorized(mock_arborist_requests):
#     """
#     By default, mocked arborist calls return Authorized.
#     To mock an unauthorized response, use fixture
#     "mock_arborist_requests(authorized=False)" in the test itself
#     """
#     mock_arborist_requests()
