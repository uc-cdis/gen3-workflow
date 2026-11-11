import pytest

from gen3workflow.redaction import (
    HIGH_ENTROPY_MIN_BITS_PER_CHAR,
    HIGH_ENTROPY_MIN_LENGTH,
    REDACTED_PLACEHOLDER,
    redact_secrets,
    redact_string,
)

# fake secrets, for testing only
JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"  # pragma: allowlist secret
AWS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret
AWS_KEY_ID_2 = "AKIAI44QH8DHBEXAMPLE"  # pragma: allowlist secret
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # pragma: allowlist secret
PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nIBAAKC\n-----END RSA PRIVATE KEY-----"  # pragma: allowlist secret


@pytest.mark.parametrize(
    "value",
    [JWT, AWS_KEY_ID, AWS_SECRET, PEM],
    ids=["jwt", "aws key id", "high entropy", "pem"],
)
def test_secrets_are_redacted(value):
    """Test that all secrets are replaced with the redacted placeholder."""
    assert redact_string(value) == REDACTED_PLACEHOLDER
    # secrets embedded in a longer string, such as a command argument
    assert (
        redact_string(f"curl -H 'Authorization: bearer {value}' x")
        == f"curl -H 'Authorization: bearer {REDACTED_PLACEHOLDER}' x"
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            "Authorization: Bearer abc123opaque",
            f"Authorization: Bearer {REDACTED_PLACEHOLDER}",
        ),
        (
            "curl -H 'Authorization: Basic dXNlcjpwYXNz' x",
            f"curl -H 'Authorization: Basic {REDACTED_PLACEHOLDER}' x",
        ),
        (
            '{"authorization": "basic secret"}',
            f'{{"authorization": "basic {REDACTED_PLACEHOLDER}"}}',
        ),
        (
            "Proxy-Authorization: Basic x",
            f"Proxy-Authorization: Basic {REDACTED_PLACEHOLDER}",
        ),
        ("Bearer abc123opaque", f"Bearer {REDACTED_PLACEHOLDER}"),
        ("Basic dXNlcjpwYXNzd29yZA==", f"Basic {REDACTED_PLACEHOLDER}"),
        ("Basic dXNlcjpwYXNz", f"Basic {REDACTED_PLACEHOLDER}"),
        (
            "postgres://admin:hunter2@db:5432/x",
            f"postgres://admin:{REDACTED_PLACEHOLDER}@db:5432/x",
        ),
        (
            "https://user:p@ss:w0rd@example.com/a@b",
            f"https://user:{REDACTED_PLACEHOLDER}@example.com/a@b",
        ),
        (
            "redis://default:pw@cache:6379",  # pragma: allowlist secret
            f"redis://default:{REDACTED_PLACEHOLDER}@cache:6379",
        ),
        # AWS presigned URL signatures: hex, so only a pattern can catch them
        (
            "https://b.s3.amazonaws.com/k?X-Amz-SignedHeaders=host&X-Amz-Signature="
            + "4f2a9c1e" * 8,
            "https://b.s3.amazonaws.com/k?X-Amz-SignedHeaders=host&X-Amz-Signature="
            + REDACTED_PLACEHOLDER,
        ),
        (
            "/k?Signature=Rd9mXy2Lq%2FbVn8Tz%3D&Expires=1793404800",
            f"/k?Signature={REDACTED_PLACEHOLDER}&Expires=1793404800",
        ),
        # the secret is a JWT: only the token is redacted
        (
            f"Authorization: Bearer {JWT}",
            f"Authorization: Bearer {REDACTED_PLACEHOLDER}",
        ),
    ],
)
def test_secrets_in_context_are_redacted(value, expected):
    """Test that secrets embedded within a longer string are replaced with the redacted placeholder."""
    assert redact_string(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        # the same kind of secret, more than once
        (f"{JWT} & {JWT}", f"{REDACTED_PLACEHOLDER} & {REDACTED_PLACEHOLDER}"),
        (
            f"keys: {AWS_KEY_ID}, {AWS_KEY_ID_2}",
            f"keys: {REDACTED_PLACEHOLDER}, {REDACTED_PLACEHOLDER}",
        ),
        (f"{PEM}\n{PEM}", f"{REDACTED_PLACEHOLDER}\n{REDACTED_PLACEHOLDER}"),
        (
            "postgres://a:pw1@h/x mongodb://b:pw2@h/y",  # pragma: allowlist secret
            f"postgres://a:{REDACTED_PLACEHOLDER}@h/x "
            f"mongodb://b:{REDACTED_PLACEHOLDER}@h/y",
        ),
        (
            "Bearer abc123opaque and bearer def456opaque",
            f"Bearer {REDACTED_PLACEHOLDER} and bearer {REDACTED_PLACEHOLDER}",
        ),
        # different kinds of secret in the same string
        (
            f"export GEN3_TOKEN='{JWT}' AWS_ACCESS_KEY_ID='{AWS_KEY_ID}' "
            f"AWS_SECRET_ACCESS_KEY='{AWS_SECRET}'",
            f"export GEN3_TOKEN='{REDACTED_PLACEHOLDER}' "
            f"AWS_ACCESS_KEY_ID='{REDACTED_PLACEHOLDER}' "
            f"AWS_SECRET_ACCESS_KEY='{REDACTED_PLACEHOLDER}'",
        ),
        (
            f'{{"token": "{JWT}", "db": "postgres://admin:hunter2@db:5432/x", '
            f'"key": "{AWS_KEY_ID}"}}',
            f'{{"token": "{REDACTED_PLACEHOLDER}", '
            f'"db": "postgres://admin:{REDACTED_PLACEHOLDER}@db:5432/x", '
            f'"key": "{REDACTED_PLACEHOLDER}"}}',
        ),
        (
            f'curl -H "Authorization: Bearer {JWT}" '
            '"https://b.s3.amazonaws.com/k?X-Amz-Signature=' + "4f2a9c1e" * 8 + '"',
            f'curl -H "Authorization: Bearer {REDACTED_PLACEHOLDER}" '
            f'"https://b.s3.amazonaws.com/k?X-Amz-Signature={REDACTED_PLACEHOLDER}"',
        ),
        # an unquoted assignment is part of the high-entropy run, so the variable name
        # is redacted along with the secret: over-redaction, which is the safe direction
        (
            f"export GEN3_TOKEN={JWT} AWS_SECRET_ACCESS_KEY={AWS_SECRET}",
            f"export GEN3_TOKEN={REDACTED_PLACEHOLDER} {REDACTED_PLACEHOLDER}",
        ),
    ],
    ids=[
        "two jwts",
        "two aws key ids",
        "two pems",
        "two url passwords",
        "two bearer tokens",
        "jwt and aws key id and aws secret",
        "jwt and url password and aws key id",
        "bearer jwt and presigned url signature",
        "unquoted assignment swallows the variable name",
    ],
)
def test_multiple_secrets_in_one_string_are_redacted(value, expected):
    """Test that every secret in a string is redacted, not just the first one."""
    assert redact_string(value) == expected
    # redacting an already-redacted string changes nothing
    assert redact_string(expected) == expected


@pytest.mark.parametrize(
    "value",
    [
        "hello world",
        "basic information about the run",
        "Basic Instructions",
        "bearer of bad news",
        "bearer information about the token",
        "Basic Instructions for the bearer",
        "the Authorization header is required",
        "https://example.com/a:b@c",
        "postgres://db:5432/x",
        "s3://bucket/key@v1",
        "/services/workflow/gen3-workflow/tasks/64/TASK_ID_PLACEHOLDER",
        "/services/workflow/gen3-workflow/tasks/aB3dEf9xYz12/TASK_ID_PLACEHOLDER",
        "/mnt/data/Run_42/IntermediateOutputs/SampleA1B2C3/results",
        "s3://gen3wf-localhost-64/some/path/to/output_file.txt",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256  # pragma: allowlist secret
        "d1hnepgddd2s73ah7fug",  # funnel task ID
        "quay.io/cdis/some-image:1.2.3",
        "a_very_long_environment_variable_value_without_digits",
    ],
)
def test_non_secrets_are_not_redacted(value):
    """Test that non-secrets are not redacted even if they contain secret-like patterns."""
    assert redact_string(value) == value


@pytest.mark.parametrize(
    "env_var_name",
    [
        "GEN3_TOKEN",
        "GEN3_API_KEY",
        "GEN3_ACCESS_TOKEN",
        "TASK_TOKEN",
        "DB_PASSWORD",
        "aws_secret_access_key",
        "PASSPHRASE",
        "pwd",
        "MY_CREDENTIALS",
        "GITLAB_TOKEN",
    ],
)
def test_env_vars_are_redacted_by_name(env_var_name):
    """Test that an env var whose name says it holds a secret is redacted."""
    # too short and too low-entropy for any value-based rule to catch
    task = {"executors": [{"env": {env_var_name: "hunter2"}}]}
    assert redact_secrets(task) == {
        "executors": [{"env": {env_var_name: REDACTED_PLACEHOLDER}}]
    }


@pytest.mark.parametrize(
    "env_var_name",
    [
        "OUTPUT_DIR",
        "SAMPLE_ID",
        "PYTHONPATH",
        "GEN3_ENDPOINT",
        "authz",
    ],
)
def test_env_vars_are_not_redacted_by_name(env_var_name):
    """Test that an env var with an ordinary name is left to the value-based rules."""
    task = {"executors": [{"env": {env_var_name: "hunter2"}}]}
    assert redact_secrets(task) == task


def test_only_env_vars_are_redacted_by_name():
    """Test that name-based redaction does not apply outside of an executor's env."""
    # a secret-sounding key anywhere else is still only redacted if its value looks like a secret
    assert redact_secrets({"tags": {"my_password": "hunter2"}}) == {
        "tags": {"my_password": "hunter2"}
    }
    assert redact_secrets({"token": "hunter2"}) == {"token": "hunter2"}


def test_env_name_redaction_only_applies_to_non_empty_strings():
    """Test that only non-empty string env values are redacted by name."""
    assert redact_secrets({"env": {"TOKEN": ""}}) == {"env": {"TOKEN": ""}}
    assert redact_secrets({"env": {"TOKEN": 1}}) == {"env": {"TOKEN": 1}}
    assert redact_secrets({"env": {"TOKEN": None}}) == {"env": {"TOKEN": None}}
    # an `env` that is not a dict is redacted like any other value
    assert redact_secrets({"env": [JWT]}) == {"env": [REDACTED_PLACEHOLDER]}


def test_redact_secrets_in_task():
    """Test that secrets in a task response are properly redacted."""
    task = {
        "id": "d1hnepgddd2s73ah7fug",
        "executors": [
            {
                "image": "alpine",
                "command": ["echo", JWT],
                "env": {
                    "GEN3_TOKEN": JWT,
                    # too short for a value-based rule: caught by its key name
                    "GITLAB_TOKEN": "glpat-sVy3Qm2xTd9Lp",  # pragma: allowlist secret
                    "OTHER": "value",
                    "N": 1,
                },
            }
        ],
        "inputs": [{"content": PEM}],
        "tags": {"_AUTHZ": "/services/workflow/gen3-workflow/tasks/64/123"},
    }
    redacted = redact_secrets(task)
    assert redacted == {
        "id": "d1hnepgddd2s73ah7fug",
        "executors": [
            {
                "image": "alpine",
                "command": ["echo", REDACTED_PLACEHOLDER],
                "env": {
                    "GEN3_TOKEN": REDACTED_PLACEHOLDER,
                    "GITLAB_TOKEN": REDACTED_PLACEHOLDER,
                    "OTHER": "value",
                    "N": 1,
                },
            }
        ],
        "inputs": [{"content": REDACTED_PLACEHOLDER}],
        "tags": {"_AUTHZ": "/services/workflow/gen3-workflow/tasks/64/123"},
    }
    # the original task is not modified
    assert task["executors"][0]["env"]["GEN3_TOKEN"] == JWT
