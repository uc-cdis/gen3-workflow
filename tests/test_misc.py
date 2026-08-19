import pytest

from gen3workflow.aws.aws_utils import get_safe_name_from_hostname
from gen3workflow.config import config


@pytest.fixture(scope="function")
def reset_config_hostname():
    """
    Reset the `HOSTNAME` configuration at the end of tests that use this fixture
    """
    original_val = config["HOSTNAME"]
    yield
    config["HOSTNAME"] = original_val


def test_get_safe_name_from_hostname(reset_config_hostname):
    """
    Test that `get_safe_name_from_hostname` correctly generates "safe names" from hostnames
    """
    user_id = "asdfgh"

    # test a hostname with a `.`; it should be replaced by a `-`
    config["HOSTNAME"] = "qwert.qwert"
    escaped_shortened_hostname = "qwert-qwert"
    safe_name = get_safe_name_from_hostname(user_id)
    assert len(safe_name) < 63
    assert safe_name == f"gen3wf-{escaped_shortened_hostname}-{user_id}"

    # test a mixed-case user ID (e.g. a client ID); it should be lowercased since S3 bucket and
    # k8s service account names do not allow uppercase characters
    safe_name = get_safe_name_from_hostname("MixedCaseClientID")
    assert safe_name == f"gen3wf-{escaped_shortened_hostname}-mixedcaseclientid"

    # test with a hostname that would result in a name longer than the max (63 chars)
    config["HOSTNAME"] = (
        "qwertqwert.qwertqwert.qwertqwert.qwertqwert.qwertqwert.qwertqwert"
    )
    escaped_shortened_hostname = "qwertqwert-qwertqwert-qwertqwert-qwertqwert-qwert"
    safe_name = get_safe_name_from_hostname(user_id)
    assert len(safe_name) == 63
    assert safe_name == f"gen3wf-{escaped_shortened_hostname}-{user_id}"

    # test with a hostname longer than max and an extra few characters of reserved length
    reserved_length = len("qwert")
    escaped_shortened_hostname_with_reserved_length = (
        "qwertqwert-qwertqwert-qwertqwert-qwertqwert-"
    )
    safe_name = get_safe_name_from_hostname(user_id, reserved_length=reserved_length)
    assert len(safe_name) + reserved_length == 63
    assert (
        safe_name
        == f"gen3wf-{escaped_shortened_hostname_with_reserved_length}-{user_id}"
    )
