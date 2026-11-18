"""
Redaction of whole JSON-like objects, such as TES tasks: walks the object, redacts every string
with `redact_string`, and redacts an executor's env vars by name.
"""

import re
from typing import Any, Iterable

from gen3workflow.redaction.patterns import REDACTED_PLACEHOLDER, redact_string

# an env var whose name contains one of these holds a secret, whatever its value looks like:
# this covers `GEN3_TOKEN`, `GEN3_API_KEY`, `GEN3_ACCESS_TOKEN`, `TASK_TOKEN`, `DB_PASSWORD`...
# matched against a lowercased name: `re.IGNORECASE` would cost more than the `str.lower()` call
SECRET_ENV_VAR_NAME = re.compile(
    r"credential|key|passphrase|passwd|password|pwd|secret|token"
)

# a task tag holding a comma-separated list of env var names the user declares as secret, for
# credentials this module would not otherwise recognise
ENV_SECRETS_TAG = "_ENV_SECRETS"

# the keys whose strings may echo a secret env var's value: an executor's `command`, an executor
# log's `stdout` and `stderr`, and the task log's `system_logs`. The values of a task's secret
# env vars are only looked for in the strings under these keys.
KNOWN_SECRET_VALUE_KEYS = frozenset({"command", "stdout", "stderr", "system_logs"})


def _declared_secret_env_var_names(tags: Any) -> frozenset:
    """
    Read the env var names a user declared as secret in the task's `_ENV_SECRETS` tag.

    Args:
        tags: the value of a task's `tags` key, normally a dict of tag names to values

    Returns:
        frozenset: the declared names, lowercased. Empty if the tag is absent, or does not hold a string.
    """
    if not isinstance(tags, dict):
        return frozenset()

    declared = tags.get(ENV_SECRETS_TAG, tags.get(ENV_SECRETS_TAG.lower(), ""))
    if not isinstance(declared, str):
        return frozenset()
    return frozenset(
        name.strip().lower() for name in declared.split(",") if name.strip()
    )


def _env_var_names_a_secret(name: Any, declared_secret_env_vars: frozenset) -> bool:
    if not isinstance(name, str):
        return False
    lowered = name.lower()
    return (
        lowered in declared_secret_env_vars
        or SECRET_ENV_VAR_NAME.search(lowered) is not None
    )


def _secret_env_var_values(task: Any, declared_secret_env_vars: frozenset) -> frozenset:
    """
    Collect the values of a task's secret env vars, so they can be redacted wherever they are
    echoed: in an executor's `command`, or in logs where a tool printed them (see
    `KNOWN_SECRET_VALUE_KEYS`). This catches secrets that pattern matching on the string alone
    would miss, because the value itself may look like anything.

    An env var is secret if its name matches `SECRET_ENV_VAR_NAME` or is listed in the task's
    `_ENV_SECRETS` tag. Only `executors[*].env` is read, which is where the TES spec puts env
    vars. Executors that are not dicts, and `env` values that are `None`, are skipped. Non-string
    values (e.g. numbers) are converted with `str()`, since that is how they would be echoed.

    Args:
        task (dict): a TES task. One without an `executors` list yields no values.
        declared_secret_env_vars (frozenset): lowercased names from the task's `_ENV_SECRETS` tag

    Returns:
        frozenset: the distinct values of the secret env vars, as strings. Empty if there are none.
    """
    executors = task.get("executors")
    if not isinstance(executors, list):
        return frozenset()

    values = set()
    for executor in executors:
        if not isinstance(executor, dict):
            continue
        for key, env in executor.items():
            if not (
                isinstance(key, str) and key.lower() == "env" and isinstance(env, dict)
            ):
                continue
            values.update(
                value if isinstance(value, str) else str(value)
                for name, value in env.items()
                # `None` would turn into "None" and redact that word everywhere
                if value is not None
                and _env_var_names_a_secret(name, declared_secret_env_vars)
            )
    return frozenset(values)


def _redact_env_secrets(env: Any, declared_secret_env_vars: frozenset) -> Any:
    """
    Redact an executor's `env`. A variable whose name says it holds a secret, or that the user
    declared in the `_ENV_SECRETS` tag, is redacted outright.

    Args:
        env: the value of an `env` key, normally a dict of variable names to values
        declared_secret_env_vars (frozenset): lowercased names from the task's `_ENV_SECRETS` tag

    Returns:
        a redacted copy of the value
    """
    # the TES spec says this is a dict of strings, but `create_task` redacts and logs the
    # request body before the TES server has validated it, so it can be any JSON a user sent
    if not isinstance(env, dict):
        return _redact(env, declared_secret_env_vars)
    return {
        name: (
            REDACTED_PLACEHOLDER
            if _env_var_names_a_secret(name, declared_secret_env_vars)
            else _redact(value, declared_secret_env_vars)
        )
        for name, value in env.items()
    }


def redact_secrets(obj: Any, declared_secret_env_vars: frozenset = frozenset()) -> Any:
    """
    Recursively redact secret-looking values in a JSON-like object (dicts, lists, strings).
    Dictionary keys are not redacted. The input object is not modified.

    The values of a task's secret env vars (by name, or declared in its `_ENV_SECRETS` tag) are
    also redacted from the strings that may echo them: an executor's `command`, and the task's
    `stdout`, `stderr` and `system_logs`.

    Args:
        obj: object to redact, for example a TES task or a list of TES tasks
        declared_secret_env_vars (frozenset): lowercased env var names declared as secret
            by an enclosing task's `_ENV_SECRETS` tag. Each task in a list response is read
            separately.

    Returns:
        a redacted copy of the object
    """
    return _redact(obj, declared_secret_env_vars)


def _redact(
    obj: Any,
    declared_secret_env_vars: frozenset,
    secret_values: tuple = (),
    check_known_values: bool = False,
) -> Any:
    """
    Args:
        secret_values (tuple): the secret env var values of the enclosing task, longest first
        check_known_values (bool): whether `obj` is the value of a `KNOWN_SECRET_VALUE_KEYS` key, in which case
            `secret_values` are redacted from its strings
    """
    if isinstance(obj, str):
        return redact_string(obj, secret_values if check_known_values else ())
    if isinstance(obj, dict):
        # a task declares its own secret env vars, so the names travel down to its executors
        declared = _declared_secret_env_var_names(obj.get("tags"))
        if declared or "executors" in obj:
            declared_secret_env_vars = declared or declared_secret_env_vars
            # a task's secret env var values are redacted from the `KNOWN_SECRET_VALUE_KEYS` strings within that task
            # sorted once per task, longest first, so a value containing another is fully
            # redacted; empty values are dropped since they would match everywhere
            secret_values = tuple(
                sorted(
                    {
                        *secret_values,
                        *_secret_env_var_values(obj, declared_secret_env_vars),
                    }
                    - {""},
                    key=len,
                    reverse=True,
                )
            )
        return {
            k: (
                _redact_env_secrets(v, declared_secret_env_vars)
                if isinstance(k, str) and k.lower() == "env"
                else _redact(
                    v,
                    declared_secret_env_vars,
                    secret_values,
                    k in KNOWN_SECRET_VALUE_KEYS,
                )
            )
            for k, v in obj.items()
        }
    if isinstance(obj, Iterable):
        return [
            _redact(v, declared_secret_env_vars, secret_values, check_known_values)
            for v in obj
        ]
    return obj
