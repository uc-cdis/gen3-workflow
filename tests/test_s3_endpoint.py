import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from fastapi import HTTPException
from unittest.mock import AsyncMock, patch
import pytest
import tempfile

from conftest import MOCKED_S3_RESPONSE_DICT, TEST_USER_ID, TEST_USER_TOKEN
from gen3workflow.config import config
from gen3workflow.routes.s3 import (
    set_access_token_and_get_user_id,
    chunked_to_non_chunked_body,
)


TEST_CLIENT_ID = "client-azp"


# reusable parametrization of the `s3_client` and `access_token_patcher` fixtures
s3_client_and_token_test_ids = [
    "s3 path-user creds",
    "root path-user creds",
    "s3 path-client creds",
    "root path-client creds",
]
s3_client_and_token_test_cases = [
    # first 2 test cases: user key ID and user token
    (
        {"endpoint": "s3", "aws_access_key_id": TEST_USER_TOKEN},
        {"user_id": TEST_USER_ID},
    ),
    ({"endpoint": "", "aws_access_key_id": TEST_USER_TOKEN}, {"user_id": TEST_USER_ID}),
    # last 2 test cases: client key ID and client token
    (
        {
            "endpoint": "s3",
            "aws_access_key_id": f"{TEST_USER_TOKEN};userId={TEST_USER_ID}",
        },
        {"user_id": None, "client_id": TEST_CLIENT_ID},
    ),
    (
        {
            "endpoint": "",
            "aws_access_key_id": f"{TEST_USER_TOKEN};userId={TEST_USER_ID}",
        },
        {"user_id": None, "client_id": TEST_CLIENT_ID},
    ),
]


@pytest.fixture(
    params=[
        pytest.param({"endpoint": "s3"}, id="s3 path"),
        pytest.param({"endpoint": ""}, id="root path"),
    ]
)
def s3_client(client, request):
    """
    Return an S3 client configured to talk to the gen3-workflow S3 endpoint.

    - Set request param "endpoint" (str, default "s3") to change the endpoint used by boto3 calls.
      Specifically, most tests should run on both `/s3` and `/` because the root endpoint should
      also point to the `/s3` endpoint logic.
    - Set request param "aws_access_key_id" (str, default `TEST_USER_TOKEN`) to change the key ID
      used in boto3 calls. Specifically, some tests should use the key ID format
      `<token>;userId=<user ID>` to test the client token flow.
    """
    endpoint = request.param.get("endpoint", "s3")
    aws_access_key_id = request.param.get("aws_access_key_id", TEST_USER_TOKEN)
    session = boto3.session.Session()
    return session.client(
        service_name="s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key="N/A",
        endpoint_url=f"{client}/{endpoint}",
        # no retries; only try each call once:
        config=Config(retries={"max_attempts": 0}),
    )


@pytest.mark.parametrize("client", [{"get_url": True}], indirect=True)
@pytest.mark.parametrize(
    "s3_client, access_token_patcher",
    s3_client_and_token_test_cases,
    ids=s3_client_and_token_test_ids,
    indirect=True,
)
def test_s3_endpoint(s3_client, access_token_patcher):
    """
    Hitting the `/s3` endpoint should result in the request being forwarded to AWS S3.

    Testing:
    - s3 path and root path
    - matching credentials: user aws_access_key_id and user token
    - matching credentials: client aws_access_key_id and client token
    """
    res = s3_client.list_objects(Bucket=f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}")
    res.get("ResponseMetadata", {}).get("HTTPHeaders", {}).pop("date", None)
    assert res == MOCKED_S3_RESPONSE_DICT


@pytest.mark.parametrize("client", [{"get_url": True}], indirect=True)
@pytest.mark.parametrize(
    "s3_client, access_token_patcher",
    [
        # user key ID and client token
        (
            {"aws_access_key_id": TEST_USER_TOKEN},
            {"user_id": None, "client_id": TEST_CLIENT_ID},
        ),
        # client key ID and user token
        (
            {"aws_access_key_id": f"{TEST_USER_TOKEN};userId={TEST_USER_ID}"},
            {"user_id": TEST_USER_ID},
        ),
    ],
    ids=["client aws_access_key_id-user token", "user aws_access_key_id-client token"],
    indirect=True,
)
def test_s3_endpoint_creds_mismatch(s3_client, access_token_patcher):
    """
    Hitting the `/s3` endpoint with mismatched credentials (user aws_access_key_id and client
    token, or client aws_access_key_id and user token) should result in a 401 Unauthorized
    error.
    """
    with pytest.raises(ClientError, match="Unauthorized"):
        s3_client.list_objects(Bucket=f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}")


@pytest.mark.parametrize("client", [{"get_url": True}], indirect=True)
def test_s3_endpoint_no_token(s3_client):
    """
    Hitting the `/s3` endpoint without a Gen3 access token should result in a 401 Unauthorized
    error.
    """
    with pytest.raises(ClientError, match="Unauthorized"):
        s3_client.list_objects(Bucket=f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}")


@pytest.mark.parametrize("client", [{"get_url": True}], indirect=True)
@pytest.mark.parametrize(
    "s3_client, access_token_patcher",
    [
        # user key ID and user+client token
        (
            {"aws_access_key_id": TEST_USER_TOKEN},
            {"user_id": TEST_USER_ID, "client_id": TEST_CLIENT_ID},
        ),
        # client key ID and user+client token
        (
            {"aws_access_key_id": f"{TEST_USER_TOKEN};userId={TEST_USER_ID}"},
            {"user_id": TEST_USER_ID, "client_id": TEST_CLIENT_ID},
        ),
    ],
    ids=["supported user+client token", "unsupported user+client token"],
    indirect=True,
)
def test_s3_endpoint_unsupported_oidc_token(s3_client, access_token_patcher, request):
    """
    Hitting the `/s3` endpoint with a Gen3 access token issued from the OIDC flow (token linked to a client AND to a user) is supported in the case of a user key ID. In the case of a client key ID, it should result in a 401 Unauthorized error.
    """
    if "unsupported" in request.node.callspec.id:
        with pytest.raises(ClientError, match="Unauthorized"):
            s3_client.list_objects(Bucket=f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}")
    else:
        s3_client.list_objects(Bucket=f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}")


@pytest.mark.parametrize(
    "client", [{"get_url": True, "authorized": False}], indirect=True
)
@pytest.mark.parametrize(
    "s3_client, access_token_patcher",
    s3_client_and_token_test_cases,
    ids=s3_client_and_token_test_ids,
    indirect=True,
)
def test_s3_endpoint_unauthorized(s3_client, access_token_patcher):
    """
    Hitting the `/s3` endpoint with a Gen3 access token that does not have the appropriate access
    should result in a 403 Forbidden error.
    """
    with pytest.raises(ClientError, match="403"):
        s3_client.list_objects(Bucket=f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}")


@pytest.mark.parametrize("client", [{"get_url": True}], indirect=True)
@pytest.mark.parametrize(
    "bucket_name",
    ["not-the-user-s-bucket", f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}-2"],
)
@pytest.mark.parametrize(
    "s3_client, access_token_patcher",
    s3_client_and_token_test_cases,
    ids=s3_client_and_token_test_ids,
    indirect=True,
)
def test_s3_endpoint_wrong_bucket(s3_client, access_token_patcher, bucket_name):
    """
    Hitting the `/s3` endpoint with a bucket that is not the bucket generated by gen3-workflow for
    the current user should result in a 403 Forbidden error.
    Specific edge case: if the user's bucket is "gen3wf-<hostname>-<user ID>", a bucket name which
    is a superstring of that, such as "gen3wf-<hostname>-<user ID>-2", should not be allowed.
    """
    with pytest.raises(ClientError, match="Forbidden"):
        s3_client.list_objects(Bucket=bucket_name)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["s3", ""], ids=["s3 path", "root path"])
async def test_s3_endpoint_with_bearer_token(client, path):
    """
    Hitting the `/s3` endpoint with a bearer token instead of using the AWS SDK/CLI should result
    in a 401 error.
    """
    res = await client.get(
        f"{path}/gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}",
        headers={"Authorization": f"bearer test-token"},
    )
    assert res.status_code == 401, res.text
    assert res.json() == {
        "detail": "Bearer tokens in the authorization header are not supported by this endpoint, which expects signed S3 requests. The recommended way to use this endpoint is to use an AWS library, SDK or CLI"
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token_claims_azp",
    [TEST_CLIENT_ID, None],
    ids=["with token azp", "without token azp"],
)
@pytest.mark.parametrize(
    "token_claims_sub",
    [TEST_USER_ID, None],
    ids=["with token sub", "without token sub"],
)
@pytest.mark.parametrize(
    "key_includes_userId", [True, False], ids=["key format A", "key format B"]
)
@pytest.mark.parametrize(
    "auth_header_format", [1, 2], ids=["auth format 1", "auth format 2"]
)
async def test_set_access_token_and_get_user_id(
    auth_header_format, key_includes_userId, token_claims_sub, token_claims_azp
):
    """
    Test `set_access_token_and_get_user_id` behavior with various combinations of access token and
    key ID.

    Testing:
    - Authorization header ID format 1 and 2, as documented in the
      `set_access_token_and_get_user_id` docstring
    - Key ID format A and B, as documented in the `set_access_token_and_get_user_id`
      docstring
    - Access token claims with or without the `sub` field (user ID)
    - Access token claims with or without the `azp` field (client ID)
    """
    token_claims = {}
    if token_claims_sub:
        token_claims["sub"] = token_claims_sub
    if token_claims_azp:
        token_claims["azp"] = token_claims_azp

    auth = AsyncMock()
    auth.get_token_claims.return_value = token_claims

    aws_access_key_id = TEST_USER_TOKEN
    if key_includes_userId:
        aws_access_key_id += f";userId={TEST_USER_ID}"

    if auth_header_format == 1:
        auth_header = f"AWS4-HMAC-SHA256 Credential={aws_access_key_id}/<date>/<region>/<service>/aws4_request, SignedHeaders=some-text, Signature=some-text"
    else:
        auth_header = f"AWS {aws_access_key_id}:some-text"

    # no user ID in the token claims or in the key ID: error
    if not key_includes_userId and not token_claims_sub:
        with pytest.raises(HTTPException, match="401: No user ID in token or key ID"):
            await set_access_token_and_get_user_id(auth, {"authorization": auth_header})
    # user ID in the key ID, which implies a client flow, but no client ID in the token
    # claims: error
    elif key_includes_userId and not token_claims_azp:
        with pytest.raises(HTTPException, match="401: No client ID in token"):
            await set_access_token_and_get_user_id(auth, {"authorization": auth_header})
    # user ID in the key ID, which implies a client flow, AND user ID in the token claims: error.
    # similar test case as `test_s3_endpoint_unsupported_oidc_token`
    elif key_includes_userId and token_claims_sub:
        with pytest.raises(
            HTTPException, match="401: Expected a client token not linked to a user"
        ):
            await set_access_token_and_get_user_id(auth, {"authorization": auth_header})
    # every other case is supported: success
    else:
        user_id = await set_access_token_and_get_user_id(
            auth, {"authorization": auth_header}
        )
        assert user_id == TEST_USER_ID
        assert auth.bearer_token.credentials == TEST_USER_TOKEN


@pytest.mark.asyncio
async def test_set_access_token_and_get_user_id_invalid_auth():
    """
    Test `set_access_token_and_get_user_id` behavior when no authorization header is provided,
    when a bearer token is used, or when the authorization header format is invalid.
    """
    # anonymous call (no authorization header): error
    with pytest.raises(HTTPException, match="401: No Authorization header"):
        await set_access_token_and_get_user_id(None, {})

    # unsupported bearer token: error.
    # similar test case as `test_s3_endpoint_with_bearer_token`
    with pytest.raises(
        HTTPException,
        match="401: Bearer tokens in the authorization header are not supported by this endpoint, which expects signed S3 requests. The recommended way to use this endpoint is to use an AWS library, SDK or CLI",
    ):
        await set_access_token_and_get_user_id(None, {"authorization": "bearer token"})

    # auth header does not match format 1 or 2: error
    with pytest.raises(
        HTTPException,
        match="401: Unexpected format; unable to extract access token from authorization header",
    ):
        await set_access_token_and_get_user_id(None, {"authorization": "blah"})


@pytest.mark.parametrize("multipart", [True, False])
@pytest.mark.parametrize("client", [{"get_url": True}], indirect=True)
@pytest.mark.parametrize("s3_client", [{"endpoint": "s3"}], indirect=True)
def test_s3_upload_file(s3_client, access_token_patcher, multipart):
    """
    Test that the boto3 `upload_file` function works with the `/s3` endpoint, both for a small
    file uploaded in 1 chunk and for a large file uploaded in multiple chunks.
    """
    with patch(
        "gen3workflow.aws_utils.get_existing_kms_key_for_bucket",
        lambda _: ("test_kms_key_alias", "test_kms_key_arn"),
    ):
        with tempfile.NamedTemporaryFile(mode="w+t", delete=True) as file_to_upload:
            file_to_upload.write("Test file contents\n")
            s3_client.upload_file(
                file_to_upload.name,
                f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}",
                f"test_s3_upload_file{'_multipart' if multipart else ''}.txt",
                # to test a multipart upload, set the chunk size to 1 to force splitting the file
                # into multiple chunks:
                Config=boto3.s3.transfer.TransferConfig(
                    multipart_threshold=1 if multipart else 9999
                ),
            )


def test_chunked_to_non_chunked_body():
    body = b"f;chunk-signature=34dd77cb18532bc47b54bdd13695cab5b2ae837044842fa782bb374b246d6891\r\nBonjour world!\n\r\n0;chunk-signature=08a3c85444fa43f618638e17498d3e2c8a7166e62ae75ef1fad29e5bff2f8a46\r\n\r\n"
    assert chunked_to_non_chunked_body(body) == b"Bonjour world!\n"

    body = b"5;chunk-signature=9f5c0b7f5c1a1e0a6f2f7c5f7c0d3a8f1c9e3a3b8b1cbb4eaa27f0d5b3a0b0f2\r\nHello\r\n5;chunk-signature=3b92d0a84f7b91f3a9f4d1f8c1e90c0f5b6d1b42a2f82a8e0b91d78a0cb8e0f1\r\nWorld\r\n5;chunk-signature=7e2c5a8c8a3d1b0f9d3a3a5e1f3e6b1a9c9f1a3e5f9c0d8a2b4c3e8f0d9b1c2\r\nAgain\r\n0;chunk-signature=2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d\r\n\r\n"
    assert chunked_to_non_chunked_body(body) == b"HelloWorldAgain"
