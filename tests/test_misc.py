import pytest

from gen3workflow.aws_utils import get_iam_user_name
from gen3workflow.config import config


@pytest.fixture(scope="function")
def reset_config_hostname():
    original_hostname = config["HOSTNAME"]
    yield
    config["HOSTNAME"] = original_hostname


def test_get_iam_user_name(reset_config_hostname):
    user_id = "asdfgh"

    # test a hostname with a `.`; it should be replaced by a `-`
    config["HOSTNAME"] = "qwert.qwert"
    escaped_shortened_hostname = "qwert-qwert"
    iam_user_id = get_iam_user_name(user_id)
    assert len(iam_user_id) < 64
    assert iam_user_id == f"gen3wf-{escaped_shortened_hostname}-{user_id}"

    # test with a hostname that would result in a name longer than the max (64 chars)
    config["HOSTNAME"] = (
        "qwertqwert.qwertqwert.qwertqwert.qwertqwert.qwertqwert.qwertqwert"
    )
    escaped_shortened_hostname = "qwertqwert-qwertqwert-qwertqwert-qwertqwert-qwertq"
    iam_user_id = get_iam_user_name(user_id)
    assert len(iam_user_id) == 64
    assert iam_user_id == f"gen3wf-{escaped_shortened_hostname}-{user_id}"
