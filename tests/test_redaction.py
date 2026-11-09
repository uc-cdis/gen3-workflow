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


def test_redact_secrets_in_task():
    """Test that secrets in a task response are properly redacted."""
    task = {
        "id": "d1hnepgddd2s73ah7fug",
        "executors": [
            {
                "image": "alpine",
                "command": ["echo", JWT],
                "env": {"GEN3_TOKEN": JWT, "OTHER": "value", "N": 1},
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
