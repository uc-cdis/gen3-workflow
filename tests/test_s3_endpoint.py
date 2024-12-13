import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import pytest

from conftest import MOCKED_S3_RESPONSE_DICT, TEST_USER_ID
from gen3workflow.config import config


@pytest.fixture()
def s3_client(client):
    """
    Return an S3 client configured to talk to the gen3-workflow `/s3` endpoint.
    """
    session = boto3.session.Session()
    return session.client(
        service_name="s3",
        aws_access_key_id=config["S3_ENDPOINTS_AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=config["S3_ENDPOINTS_AWS_SECRET_ACCESS_KEY"],
        endpoint_url=f"{client}/s3",
        # no retries; only try each call once:
        config=Config(retries={"max_attempts": 0}),
    )


@pytest.mark.parametrize("client", [{"get_url": True}], indirect=True)
def test_s3_endpoint(s3_client, access_token_patcher):
    """
    Hitting the `/s3` endpoint should result in the request being forwarded to AWS S3.
    """
    res = s3_client.list_objects(Bucket=f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}")
    res.get("ResponseMetadata", {}).get("HTTPHeaders", {}).pop("date", None)
    assert res == MOCKED_S3_RESPONSE_DICT


@pytest.mark.parametrize("client", [{"get_url": True}], indirect=True)
def test_s3_endpoint_no_token(s3_client):
    """
    Hitting the `/s3` endpoint without a Gen3 access token should result in a 401 Unauthorized
    error.
    """
    with pytest.raises(ClientError, match="Unauthorized"):
        s3_client.list_objects(Bucket=f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}")


"""
This test currently doesn't work because the client generated when `get_url` is True is not stopped
properly, so generating a different client (with `authorized=False` param) triggers an error:
> OSError: [Errno 48] error while attempting to bind on address ('0.0.0.0', 8080): address already
  in use
TODO fix that
"""
# @pytest.mark.parametrize("client", [{"get_url": True, "authorized": False}], indirect=True)
# def test_s3_endpoint_unauthorized(s3_client, access_token_patcher):
#     """
#     Hitting the `/s3` endpoint with a Gen3 access token that does not have the appropriate access
#     should result in a 403 Forbidden error.
#     """
#     with pytest.raises(ClientError, match="403"):
#         s3_client.list_objects(Bucket=f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}")


@pytest.mark.parametrize("client", [{"get_url": True}], indirect=True)
@pytest.mark.parametrize(
    "bucket_name",
    ["not-the-user-s-bucket", f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}-2"],
)
def test_s3_endpoint_wrong_bucket(s3_client, access_token_patcher, bucket_name):
    """
    Hitting the `/s3` endpoint with a bucket that is not the bucket generated by gen3-workflow for
    the current user should result in a 401 Unauthorized error.
    Specific edge case: if the user's bucket is "gen3wf-<hostname>-<user ID>", a bucket name which
    is a superstring of that, such as "gen3wf-<hostname>-<user ID>-2", should not be allowed.
    """
    with pytest.raises(ClientError, match="Unauthorized"):
        s3_client.list_objects(Bucket=bucket_name)
