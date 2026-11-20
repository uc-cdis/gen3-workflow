import pytest

from gen3workflow.redaction import (
    ENV_SECRETS_TAG,
    REDACTED_PLACEHOLDER,
    redact_secrets,
    redact_string,
)


def task_with_env_and_tags(env: dict, tags: dict = None) -> dict:
    """A minimal task carrying one executor's env vars and the task's tags."""
    return {"executors": [{"env": env}], "tags": tags or {}}


# fake secrets, for testing only
JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
AWS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_KEY_ID_2 = "AKIAI44QH8DHBEXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nIBAAKC\n-----END RSA PRIVATE KEY-----"


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
            "redis://default:pw@cache:6379",
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
            "postgres://a:pw1@h/x mongodb://b:pw2@h/y",
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
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256
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
def test_secret_keys_are_redacted_by_name_pattern(env_var_name):
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
def test_non_secret_keys_are_not_redacted_by_name_pattern(env_var_name):
    """Test that an env var with an ordinary name is left to the value-based rules."""
    task = {"executors": [{"env": {env_var_name: "hunter2"}}]}
    assert redact_secrets(task) == task


def test_name_pattern_only_applies_to_executor_env():
    """Test that name-based redaction does not apply outside of an executor's env."""
    # a secret-sounding key anywhere else is still only redacted if its value looks like a secret
    assert redact_secrets({"tags": {"my_password": "hunter2"}}) == {
        "tags": {"my_password": "hunter2"}
    }
    assert redact_secrets({"token": "hunter2"}) == {"token": "hunter2"}


@pytest.mark.parametrize(
    "tag_name,tag_value",
    [
        (ENV_SECRETS_TAG, "MY_VAR"),
        (ENV_SECRETS_TAG, "OTHER,MY_VAR"),
        (ENV_SECRETS_TAG, " MY_VAR , , OTHER "),
        (ENV_SECRETS_TAG, "my_var"),
        (ENV_SECRETS_TAG.lower(), "MY_VAR"),
    ],
    ids=[
        "one name",
        "several names",
        "untidy whitespace and empty entries",
        "name in a different case",
        "tag name in a different case",
    ],
)
def test_user_secret_keys_are_redacted(tag_name, tag_value):
    """Test that an env var the user named in the `_ENV_SECRETS` tag is redacted."""
    # neither the name nor the value says "secret", so only the declaration can catch it
    task = task_with_env_and_tags({"MY_VAR": "hunter2"}, {tag_name: tag_value})
    assert redact_secrets(task)["executors"][0]["env"] == {
        "MY_VAR": REDACTED_PLACEHOLDER
    }


@pytest.mark.parametrize(
    "tag_value",
    ["OTHER_VAR", "MY_VAR_PATH", "MY", "", "   ", ",", None, ["MY_VAR"]],
    ids=[
        "a different name",
        "declared name is longer",
        "declared name is a prefix",
        "empty",
        "whitespace only",
        "separators only",
        "not a string",
        "a list instead of a string",
    ],
)
def test_keys_not_in_user_secret_keys_are_not_redacted(tag_value):
    """Test that the tag only redacts exact name matches, and tolerates unusable values."""
    task = task_with_env_and_tags({"MY_VAR": "hunter2"}, {ENV_SECRETS_TAG: tag_value})
    assert redact_secrets(task)["executors"][0]["env"] == {"MY_VAR": "hunter2"}


def test_user_secret_keys_tag_is_only_read_in_upper_or_lower_case():
    """Test that a mixed-case tag name is ignored, as it is for the other user-supplied tags."""
    task = task_with_env_and_tags({"MY_VAR": "hunter2"}, {"_Env_Secrets": "MY_VAR"})
    assert redact_secrets(task)["executors"][0]["env"] == {"MY_VAR": "hunter2"}


def test_user_secret_keys_apply_to_every_executor_in_the_task():
    """Test that the tag is set once per task and covers all of its executors."""
    task = {
        "tags": {ENV_SECRETS_TAG: "MY_VAR"},
        "executors": [
            {"env": {"MY_VAR": "hunter2"}},
            {"env": {"MY_VAR": "hunter2", "SAMPLE_ID": "S42"}},
        ],
    }
    redacted = redact_secrets(task)
    assert redacted["executors"][0]["env"] == {"MY_VAR": REDACTED_PLACEHOLDER}
    assert redacted["executors"][1]["env"] == {
        "MY_VAR": REDACTED_PLACEHOLDER,
        "SAMPLE_ID": "S42",
    }


def test_user_secret_keys_apply_only_to_their_own_task():
    """Test that one task's `_ENV_SECRETS` tag does not redact another task's env vars."""
    declaring = task_with_env_and_tags(
        {"MY_VAR": "hunter2"}, {ENV_SECRETS_TAG: "MY_VAR"}
    )
    plain = task_with_env_and_tags({"MY_VAR": "hunter2"})
    redacted = redact_secrets({"tasks": [declaring, plain]})
    assert redacted["tasks"][0]["executors"][0]["env"] == {
        "MY_VAR": REDACTED_PLACEHOLDER
    }
    assert redacted["tasks"][1]["executors"][0]["env"] == {"MY_VAR": "hunter2"}


def test_user_secret_keys_are_only_read_from_the_task_tags():
    """
    Test that `_ENV_SECRETS` is only read from the task's own `tags`, not from a `tags` nested
    elsewhere in the task, such as in an executor or an input.
    """
    task = {
        "executors": [
            {
                "command": ["echo plainvalue"],
                "env": {"MY_VAR": "plainvalue"},
                "tags": {ENV_SECRETS_TAG: "MY_VAR"},
            }
        ],
        "inputs": [{"url": "s3://bucket/key", "tags": {ENV_SECRETS_TAG: "MY_VAR"}}],
        "logs": [{"logs": [{"stdout": "plainvalue"}]}],
    }
    redacted = redact_secrets(task)
    assert redacted["executors"][0]["env"] == {"MY_VAR": "plainvalue"}
    assert redacted["executors"][0]["command"] == ["echo plainvalue"]
    assert redacted["logs"][0]["logs"][0]["stdout"] == "plainvalue"

    # the same declaration in the task's own `tags` is used
    task["tags"] = {ENV_SECRETS_TAG: "MY_VAR"}
    redacted = redact_secrets(task)
    assert redacted["executors"][0]["env"] == {"MY_VAR": REDACTED_PLACEHOLDER}
    assert redacted["executors"][0]["command"] == [f"echo {REDACTED_PLACEHOLDER}"]
    assert redacted["logs"][0]["logs"][0]["stdout"] == REDACTED_PLACEHOLDER


def test_user_secret_keys_do_not_change_the_tag_itself():
    """Test that the `_ENV_SECRETS` tag stays readable, so users can see what they declared."""
    task = task_with_env_and_tags({"MY_VAR": "hunter2"}, {ENV_SECRETS_TAG: "MY_VAR"})
    assert redact_secrets(task)["tags"] == {ENV_SECRETS_TAG: "MY_VAR"}


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
                    "GITLAB_TOKEN": "glpat-sVy3Qm2xTd9Lp",
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


def test_secret_values_are_redacted_from_command_and_logs():
    """
    The value of an env var that is secret by name, or declared in `_ENV_SECRETS`, is redacted
    from the executors' command and the task's stdout, stderr and system logs, even when it does
    not look like a secret.
    """
    task = {
        "tags": {"_ENV_SECRETS": "MY_VAR"},
        "executors": [
            {
                "command": ["echo hunter2 and plainvalue and other"],
                "env": {"DB_PASSWORD": "hunter2", "MY_VAR": "plainvalue", "X": "other"},
            }
        ],
        "logs": [
            {
                "system_logs": ["pulled image, hunter2 leaked"],
                "logs": [
                    {"stdout": "hunter2 plainvalue other", "stderr": "bad plainvalue"}
                ],
            }
        ],
    }
    redacted = redact_secrets(task)
    log = redacted["logs"][0]
    assert (
        log["logs"][0]["stdout"]
        == f"{REDACTED_PLACEHOLDER} {REDACTED_PLACEHOLDER} other"
    )
    assert log["logs"][0]["stderr"] == f"bad {REDACTED_PLACEHOLDER}"
    assert log["system_logs"] == [f"pulled image, {REDACTED_PLACEHOLDER} leaked"]
    assert redacted["executors"][0]["env"]["X"] == "other"
    assert redacted["executors"][0]["command"] == [
        f"echo {REDACTED_PLACEHOLDER} and {REDACTED_PLACEHOLDER} and other"
    ]


def test_secret_values_skip_empty_and_none_and_stringify_others():
    """
    Test that empty and `None` values of secret env vars are not redacted from the logs, since they
    would match everywhere or redact the word "None", while non-string values are redacted as
    the string they would be echoed as. The env vars themselves are redacted by name regardless.
    """
    task = {
        "executors": [
            {
                "env": {
                    "DB_PASSWORD": "",
                    "MY_TOKEN": None,
                    "API_KEY": 8675309,
                    "SECRET_FLAG": True,
                },
            }
        ],
        "logs": [{"logs": [{"stdout": "None: key 8675309 is True"}]}],
    }
    redacted = redact_secrets(task)
    assert redacted["executors"][0]["env"] == {
        "DB_PASSWORD": REDACTED_PLACEHOLDER,
        "MY_TOKEN": REDACTED_PLACEHOLDER,
        "API_KEY": REDACTED_PLACEHOLDER,
        "SECRET_FLAG": REDACTED_PLACEHOLDER,
    }
    assert (
        redacted["logs"][0]["logs"][0]["stdout"]
        == f"None: key {REDACTED_PLACEHOLDER} is {REDACTED_PLACEHOLDER}"
    )


def test_overlapping_secret_values_are_redacted_longest_first():
    """
    Test that when a secret env var's value contains another's, the longer one is redacted first, so
    no part of it is left behind once the shorter one is replaced.
    """
    task = {
        "executors": [
            {"env": {"DB_PASSWORD": "hunter2", "API_KEY": "hunter2-extended"}}
        ],
        "logs": [{"logs": [{"stdout": "hunter2 and hunter2-extended"}]}],
    }
    redacted = redact_secrets(task)
    assert (
        redacted["logs"][0]["logs"][0]["stdout"]
        == f"{REDACTED_PLACEHOLDER} and {REDACTED_PLACEHOLDER}"
    )


def test_secret_values_are_scoped_to_their_own_task():
    """
    Test that in a list of tasks that declare the same env var as secret but with different values, each task
    only redacts its own value, even though both values are printed in both tasks' stdout.
    """

    def make_task(value):
        return {
            "tags": {"_ENV_SECRETS": "MY_VAR"},
            "executors": [{"env": {"MY_VAR": value}}],
            "logs": [{"logs": [{"stdout": "first-value second-value"}]}],
        }

    redacted_first, redacted_second = redact_secrets(
        [make_task("first-value"), make_task("second-value")]
    )
    assert (
        redacted_first["logs"][0]["logs"][0]["stdout"]
        == f"{REDACTED_PLACEHOLDER} second-value"
    )
    assert (
        redacted_second["logs"][0]["logs"][0]["stdout"]
        == f"first-value {REDACTED_PLACEHOLDER}"
    )


def test_secret_values_are_redacted_across_executors():
    """
    Test that a secret value from one executor's env is redacted from every executor's logs, since
    executors in a task share volumes and a later executor may echo an earlier one's secret.
    """
    task = {
        "volumes": ["/shared"],
        "executors": [
            {
                "image": "alpine",
                # writes its secret to the shared volume, and echoes it
                "command": [
                    "sh",
                    "-c",
                    'echo "$DB_PASSWORD" > /shared/pw && echo "wrote $DB_PASSWORD"',
                ],
                "env": {"DB_PASSWORD": "hunter2"},
            },
            {
                "image": "alpine",
                # has no secret of its own, but reads and echoes the first executor's
                "command": [
                    "sh",
                    "-c",
                    'echo "read $(cat /shared/pw) for $SAMPLE_ID"',
                ],
                "env": {"SAMPLE_ID": "S42"},
            },
        ],
        "logs": [
            {
                "logs": [
                    {"stdout": "wrote hunter2\n", "exit_code": 0},
                    {"stdout": "read hunter2 for S42\n", "exit_code": 0},
                ]
            }
        ],
    }
    redacted = redact_secrets(task)
    executor_logs = redacted["logs"][0]["logs"]
    assert executor_logs[0]["stdout"] == f"wrote {REDACTED_PLACEHOLDER}\n"
    assert executor_logs[1]["stdout"] == f"read {REDACTED_PLACEHOLDER} for S42\n"
    # the commands only reference the env vars, so there is nothing to redact in them
    assert redacted["executors"][0]["command"] == task["executors"][0]["command"]
    assert redacted["executors"][1]["command"] == task["executors"][1]["command"]


def test_secret_values_are_not_redacted_from_other_fields():
    """Test that the values are only looked for in the fields that may echo them."""
    task = {
        "name": "run with hunter2",
        "description": "hunter2",
        "executors": [{"image": "hunter2", "env": {"DB_PASSWORD": "hunter2"}}],
    }
    redacted = redact_secrets(task)
    assert redacted["name"] == task["name"]
    assert redacted["description"] == task["description"]
    assert redacted["executors"][0]["image"] == "hunter2"


@pytest.mark.parametrize(
    "executors", [None, "not a list", [None, "x", {"env": "not a dict"}]]
)
def test_secret_values_ignore_malformed_executors(executors):
    """Test that a malformed `executors` does not break collecting the secret env var values."""
    task = {"executors": executors, "logs": [{"stdout": "hunter2"}]}
    assert redact_secrets(task) == task


def test_secret_values_are_read_from_executors_only():
    """
    Test that only `executors[*].env` is read for the values to redact from the strings that may echo them.
    The TES spec has no `env` outside of executors, but a request body is redacted before it is validated: a
    stray `env` is still redacted by name, but its values are not tracked.
    """
    task = {
        "env": {"API_KEY": "plainvalue"},
        "executors": [{"env": {"DB_PASSWORD": "hunter2"}}],
        "logs": [{"logs": [{"stdout": "hunter2 plainvalue"}]}],
    }
    redacted = redact_secrets(task)
    assert redacted["env"] == {"API_KEY": REDACTED_PLACEHOLDER}
    assert (
        redacted["logs"][0]["logs"][0]["stdout"] == f"{REDACTED_PLACEHOLDER} plainvalue"
    )
