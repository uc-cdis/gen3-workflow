import boto3
from freezegun import freeze_time
from moto import mock_aws
import pytest

from conftest import TEST_USER_ID
from gen3workflow import aws_utils
from gen3workflow.config import config
from gen3workflow.aws_utils import get_iam_user_name


@pytest.mark.asyncio
async def test_create_and_list_user_keys(client, access_token_patcher):
    """
    Create and delete keys, and check that the listing endpoint returns active keys.
    """
    with mock_aws():
        aws_utils.iam_client = boto3.client("iam")

        # the user does not have keys yet
        res = await client.get(
            "/storage/credentials", headers={"Authorization": f"bearer 123"}
        )
        assert res.status_code == 200, res.text
        assert res.json() == []

        # create 2 keys
        keys = []
        for _ in range(2):
            res = await client.post(
                "/storage/credentials", headers={"Authorization": f"bearer 123"}
            )
            assert res.status_code == 200, res.text
            key_data = res.json()
            assert "aws_key_id" in key_data and "aws_key_secret" in key_data
            keys.append(key_data)

        # both keys should be listed in the user's keys
        res = await client.get(
            "/storage/credentials", headers={"Authorization": f"bearer 123"}
        )
        assert res.status_code == 200, res.text
        assert res.json() == [
            {
                "aws_key_id": keys[0]["aws_key_id"],
                "status": f"expires in {config['IAM_KEYS_LIFETIME_DAYS'] - 1} days",
            },
            {
                "aws_key_id": keys[1]["aws_key_id"],
                "status": f"expires in {config['IAM_KEYS_LIFETIME_DAYS'] - 1} days",
            },
        ]

        # delete the 1st key
        res = await client.delete(
            f"/storage/credentials/{keys[0]['aws_key_id']}",
            headers={"Authorization": f"bearer 123"},
        )
        assert res.status_code == 200, res.text

        # only the 2nd key should now be listed in the user's keys
        res = await client.get(
            "/storage/credentials", headers={"Authorization": f"bearer 123"}
        )
        assert res.status_code == 200, res.text
        assert res.json() == [
            {
                "aws_key_id": keys[1]["aws_key_id"],
                "status": f"expires in {config['IAM_KEYS_LIFETIME_DAYS'] - 1} days",
            }
        ]


@pytest.mark.asyncio
async def test_list_user_keys_status(client, access_token_patcher):
    """
    Keys that are deactivated or past the expiration date should be listed as "expired" when listing a user's keys.
    """
    with mock_aws():
        aws_utils.iam_client = boto3.client("iam")

        # create 2 keys. The 1st one has a mocked creation date of more than IAM_KEYS_LIFETIME_DAYS
        # days ago, so it should be expired.
        keys = []
        import datetime

        for i in range(2):
            if i == 0:
                with freeze_time(
                    datetime.date.today()
                    - datetime.timedelta(days=config["IAM_KEYS_LIFETIME_DAYS"] + 1)
                ):
                    res = await client.post(
                        "/storage/credentials", headers={"Authorization": f"bearer 123"}
                    )
            else:
                res = await client.post(
                    "/storage/credentials", headers={"Authorization": f"bearer 123"}
                )
            assert res.status_code == 200, res.text
            key_data = res.json()
            assert "aws_key_id" in key_data and "aws_key_secret" in key_data
            keys.append(key_data)

        # list the user's keys; the 1st key should show as expired
        res = await client.get(
            "/storage/credentials", headers={"Authorization": f"bearer 123"}
        )
        assert res.status_code == 200, res.text
        assert res.json() == [
            {"aws_key_id": keys[0]["aws_key_id"], "status": f"expired"},
            {
                "aws_key_id": keys[1]["aws_key_id"],
                "status": f"expires in {config['IAM_KEYS_LIFETIME_DAYS'] - 1} days",
            },
        ]

        # deactivate the 2nd key
        access_key = boto3.resource("iam").AccessKey(
            get_iam_user_name(TEST_USER_ID), keys[1]["aws_key_id"]
        )
        access_key.deactivate()

        # list the user's keys; both keys should now show as expired
        res = await client.get(
            "/storage/credentials", headers={"Authorization": f"bearer 123"}
        )
        assert res.status_code == 200, res.text
        assert res.json() == [
            {"aws_key_id": keys[0]["aws_key_id"], "status": "expired"},
            {"aws_key_id": keys[1]["aws_key_id"], "status": "expired"},
        ]


@pytest.mark.asyncio
async def test_too_many_user_keys(client, access_token_patcher):
    """
    Users should not be able to create new keys after reaching MAX_IAM_KEYS_PER_USER.
    """
    with mock_aws():
        aws_utils.iam_client = boto3.client("iam")

        # create the max number of keys
        for _ in range(config["MAX_IAM_KEYS_PER_USER"]):
            res = await client.post(
                "/storage/credentials", headers={"Authorization": f"bearer 123"}
            )
            assert res.status_code == 200, res.text
            key_data = res.json()
            assert "aws_key_id" in key_data and "aws_key_secret" in key_data

        # attempt to create another key; this should fail since `MAX_IAM_KEYS_PER_USER` is reached
        res = await client.post(
            "/storage/credentials", headers={"Authorization": f"bearer 123"}
        )
        assert res.status_code == 400, res.text
        assert res.json() == {
            "detail": "Too many existing keys: only 2 are allowed per user. Delete an existing key before creating a new one"
        }

        # delete one of the keys
        res = await client.delete(
            f"/storage/credentials/{key_data['aws_key_id']}",
            headers={"Authorization": f"bearer 123"},
        )
        assert res.status_code == 200, res.text

        # attempt to create another key; now it should succeed
        res = await client.post(
            "/storage/credentials", headers={"Authorization": f"bearer 123"}
        )
        assert res.status_code == 200, res.text
        key_data = res.json()
        assert "aws_key_id" in key_data and "aws_key_secret" in key_data


@pytest.mark.asyncio
async def test_torage_info(client, access_token_patcher):
    """
    TODO
    """
    with mock_aws():
        aws_utils.iam_client = boto3.client("iam")

        res = await client.get(
            "/storage/info", headers={"Authorization": f"bearer 123"}
        )
        assert res.status_code == 200, res.text
        storage_info = res.json()
        assert storage_info == {
            "bucket": "TODO",
            "workdir": "s3://TODO/ga4gh-tes",
            "region": "us-east-1",
        }
