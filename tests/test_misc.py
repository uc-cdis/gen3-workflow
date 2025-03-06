import boto3
from botocore.exceptions import ClientError
import json
from moto import mock_aws
import pytest

from conftest import TEST_USER_ID
from gen3workflow import aws_utils
from gen3workflow.aws_utils import get_safe_name_from_hostname
from gen3workflow.config import config


@pytest.fixture(scope="function")
def reset_config_hostname():
    original_hostname = config["HOSTNAME"]
    yield
    config["HOSTNAME"] = original_hostname


@pytest.fixture(scope="function")
def mock_aws_services():
    with mock_aws():
        aws_utils.iam_client = boto3.client("iam")
        aws_utils.kms_client = boto3.client(
            "kms", region_name=config["USER_BUCKETS_REGION"]
        )
        aws_utils.s3_client = boto3.client("s3")

        yield


def test_get_safe_name_from_hostname(reset_config_hostname):
    user_id = "asdfgh"

    # test a hostname with a `.`; it should be replaced by a `-`
    config["HOSTNAME"] = "qwert.qwert"
    escaped_shortened_hostname = "qwert-qwert"
    safe_name = get_safe_name_from_hostname(user_id)
    assert len(safe_name) < 63
    assert safe_name == f"gen3wf-{escaped_shortened_hostname}-{user_id}"

    # test with a hostname that would result in a name longer than the max (63 chars)
    config["HOSTNAME"] = (
        "qwertqwert.qwertqwert.qwertqwert.qwertqwert.qwertqwert.qwertqwert"
    )
    escaped_shortened_hostname = "qwertqwert-qwertqwert-qwertqwert-qwertqwert-qwert"
    safe_name = get_safe_name_from_hostname(user_id)
    assert len(safe_name) == 63
    assert safe_name == f"gen3wf-{escaped_shortened_hostname}-{user_id}"


@pytest.mark.asyncio
async def test_storage_info(client, access_token_patcher, mock_aws_services):
    # check that the user's storage information is as expected
    expected_bucket_name = f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}"
    res = await client.get("/storage/info", headers={"Authorization": "bearer 123"})
    assert res.status_code == 200, res.text
    storage_info = res.json()
    assert storage_info == {
        "bucket": expected_bucket_name,
        "workdir": f"s3://{expected_bucket_name}/ga4gh-tes",
        "region": config["USER_BUCKETS_REGION"],
    }

    # check that the bucket is setup with KMS encryption
    kms_key = aws_utils.kms_client.describe_key(KeyId=f"alias/{expected_bucket_name}")
    kms_key_arn = kms_key["KeyMetadata"]["Arn"]
    bucket_encryption = aws_utils.s3_client.get_bucket_encryption(
        Bucket=expected_bucket_name
    )
    assert bucket_encryption.get("ServerSideEncryptionConfiguration") == {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": kms_key_arn,
                },
                "BucketKeyEnabled": True,
            }
        ]
    }

    # check the bucket policy, which should enforce KMS encryption
    bucket_policy = aws_utils.s3_client.get_bucket_policy(Bucket=expected_bucket_name)
    assert json.loads(bucket_policy.get("Policy", "{}")) == {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RequireKMSEncryption",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::gen3wf-localhost-64/*",
                "Condition": {
                    "StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}
                },
            },
            {
                "Sid": "RequireSpecificKMSKey",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::gen3wf-localhost-64/*",
                "Condition": {
                    "StringNotEquals": {
                        "s3:x-amz-server-side-encryption-aws-kms-key-id": kms_key_arn
                    }
                },
            },
        ],
    }

    # check the bucket's lifecycle configuration
    lifecycle_config = aws_utils.s3_client.get_bucket_lifecycle_configuration(
        Bucket=expected_bucket_name
    )
    assert lifecycle_config.get("Rules") == [
        {
            "Expiration": {"Days": config["S3_OBJECTS_EXPIRATION_DAYS"]},
            "ID": "None",
            "Filter": {"Prefix": ""},
            "Status": "Enabled",
        }
    ]


@pytest.mark.asyncio
async def test_bucket_enforces_encryption(
    client, access_token_patcher, mock_aws_services
):
    """
    Attempting to PUT an object that does not respect the bucket policy should fail (not using KMS
    encryption, or not using the right KMS key). It should succeed when using KMS encryption and
    the right key.
    """
    res = await client.get("/storage/info", headers={"Authorization": "bearer 123"})
    assert res.status_code == 200, res.text
    storage_info = res.json()

    with pytest.raises(ClientError, match="Forbidden"):
        aws_utils.s3_client.put_object(
            Bucket=storage_info["bucket"], Key="test-file.txt"
        )

    unauthorized_kms_key_arn = aws_utils.kms_client.create_key(
        Tags=[
            {
                "TagKey": "Name",
                "TagValue": "some-other-key",
            }
        ]
    )["KeyMetadata"]["Arn"]
    with pytest.raises(ClientError, match="Forbidden"):
        aws_utils.s3_client.put_object(
            Bucket=storage_info["bucket"],
            Key="test-file.txt",
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=unauthorized_kms_key_arn,
        )

    # For some reason the call below is denied when it should be allowed. I believe there is a bug
    # in `moto.mock_aws`. This test works well when ran against the real AWS.
    # Against the real AWS, the 2 calls above also raise `AccessDenied` instead of `Forbidden`.

    # authorized_kms_key_arn = aws_utils.kms_client.describe_key(KeyId=f"alias/{storage_info['bucket']}")["KeyMetadata"]["Arn"]
    # aws_utils.s3_client.put_object(
    #     Bucket=storage_info["bucket"],
    #     Key="test-file.txt",
    #     ServerSideEncryption="aws:kms",
    #     SSEKMSKeyId=authorized_kms_key_arn,
    # )


@pytest.mark.asyncio
async def test_delete_user_bucket(client, access_token_patcher, mock_aws_services):
    """
    The user should be able to delete their own bucket.
    """

    # Get users bucket name using through user ID
    expected_bucket_name = f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}"

    # Create the bucket if it doesn't exist
    res = await client.get("/storage/info", headers={"Authorization": "bearer 123"})
    assert res.status_code == 200, res.text
    storage_info = res.json()
    assert storage_info == {
        "bucket": expected_bucket_name,
        "workdir": f"s3://{expected_bucket_name}/ga4gh-tes",
        "region": config["USER_BUCKETS_REGION"],
    }

    # Verify the bucket exists
    bucket_exists = aws_utils.s3_client.head_bucket(Bucket=expected_bucket_name)
    assert bucket_exists, "Bucket does not exist"

    # Delete the bucket
    res = await client.delete(
        "/storage/user-bucket", headers={"Authorization": "bearer 123"}
    )
    assert res.status_code == 204, res.text

    # Verify the bucket is deleted
    with pytest.raises(ClientError) as e:
        aws_utils.s3_client.head_bucket(Bucket=expected_bucket_name)
    assert (
        e.value.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404
    ), f"Bucket still exists: {e.value}"
