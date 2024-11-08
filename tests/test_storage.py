import boto3
from moto import mock_aws
import pytest

from conftest import TEST_USER_ID
from gen3workflow import aws_utils


@pytest.mark.asyncio
async def test_create_and_list_user_keys(client, access_token_patcher):
    """
    TODO
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
            {"aws_key_id": keys[0]["aws_key_id"], "status": "expires in 30 days"},
            {"aws_key_id": keys[1]["aws_key_id"], "status": "expires in 30 days"},
        ]

        # delete the 2st key
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
            {"aws_key_id": keys[1]["aws_key_id"], "status": "expires in 30 days"}
        ]


@pytest.mark.asyncio
async def test_too_many_user_keys(client, access_token_patcher):
    """
    TODO
    """
    with mock_aws():
        aws_utils.iam_client = boto3.client("iam")

        # create 2 keys
        for _ in range(2):
            res = await client.post(
                "/storage/credentials", headers={"Authorization": f"bearer 123"}
            )
            assert res.status_code == 200, res.text
            key_data = res.json()
            assert "aws_key_id" in key_data and "aws_key_secret" in key_data

        # attempt to create another key; this should fail since `MAX_IAM_KEYS_PER_USER` is 2
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
