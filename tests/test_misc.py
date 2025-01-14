import boto3
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
async def test_storage_info(client, access_token_patcher):
    with mock_aws():
        aws_utils.iam_client = boto3.client("iam")
        expected_bucket_name = f"gen3wf-{config['HOSTNAME']}-{TEST_USER_ID}"

        res = await client.get("/storage/info", headers={"Authorization": "bearer 123"})
        assert res.status_code == 200, res.text
        storage_info = res.json()
        assert storage_info == {
            "bucket": expected_bucket_name,
            "workdir": f"s3://{expected_bucket_name}/ga4gh-tes",
            "region": config["USER_BUCKETS_REGION"],
        }
