import pytest

from gen3workflow.aws.aws_utils import get_safe_name_from_hostname
from gen3workflow.config import DEFAULT_CFG_PATH, Gen3WorkflowConfig, config


@pytest.fixture(scope="function")
def reset_config_hostname():
    """
    Reset the `HOSTNAME` configuration at the end of tests that use this fixture
    """
    original_val = config["HOSTNAME"]
    yield
    config["HOSTNAME"] = original_val


@pytest.fixture(scope="function")
def dpop_required_without_shared_secret(monkeypatch):
    """
    Require DPoP, and remove the DPoP shared secret from the configuration and the environment,
    for the duration of the test.
    """
    original_vals = {k: config[k] for k in ("DPOP_REQUIRED", "DPOP_SHARED_SECRET")}
    monkeypatch.delenv("DPOP_SHARED_SECRET", raising=False)
    config["DPOP_REQUIRED"] = True
    config["DPOP_SHARED_SECRET"] = None
    yield
    for k, v in original_vals.items():
        config[k] = v


def test_dpop_is_required_by_default():
    """The default configuration requires DPoP."""
    default_config = Gen3WorkflowConfig(DEFAULT_CFG_PATH)
    default_config.load(config_path=DEFAULT_CFG_PATH)
    assert default_config["DPOP_REQUIRED"] is True


def test_dpop_required_without_shared_secret_is_rejected(
    dpop_required_without_shared_secret,
):
    """
    With DPoP required and no shared secret, the configuration is refused at startup rather than
    accepting proofs whose nonces cannot be verified.
    """
    with pytest.raises(AssertionError, match="DPOP_SHARED_SECRET"):
        config.validate()


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
