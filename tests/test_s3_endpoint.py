import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import pytest

from conftest import MOCKED_S3_RESPONSE_DICT, TEST_USER_ID
from gen3workflow.config import config


# reusable parametrization of the `s3_client` and `access_token_patcher` fixtures
s3_client_and_token_test_ids = [
    "s3 path-user creds",
    "root path-user creds",
    "s3 path-client creds",
    "root path-client creds",
]
s3_client_and_token_test_cases = [
    # first 2 test cases: user key ID (default) and user token (default)
    ({"endpoint": "s3"}, {}),
    ({"endpoint": ""}, {}),
    # last 2 test cases: client key ID and client token
    (
        {"endpoint": "s3", "aws_access_key_id": f"123;userId={TEST_USER_ID}"},
        {"client_id": "test-azp"},
    ),
    (
        {"endpoint": "", "aws_access_key_id": f"123;userId={TEST_USER_ID}"},
        {"client_id": "test-azp"},
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
    Return an S3 client configured to talk to the gen3-workflow `/s3` endpoint (the root endpoint
    should also point to the `/s3` endpoint logic).
    """
    endpoint = request.param.get("endpoint", "s3")
    # TODO "123" constant var
    aws_access_key_id = request.param.get("aws_access_key_id", "123")  # TODO comment
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
        (
            {},  # user key ID (default)
            {"client_id": "test-azp"},  # client token
        ),
        (
            {"aws_access_key_id": f"123;userId={TEST_USER_ID}"},  # client key ID
            {},  # user token (default)
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
        headers={"Authorization": "bearer 123"},
    )
    assert res.status_code == 401, res.text
    assert res.json() == {
        "detail": "Bearer tokens in the authorization header are not supported by this endpoint, which expects signed S3 requests. The recommended way to use this endpoint is to use the AWS SDK or CLI"
    }
