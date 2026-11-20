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


def _get_user_secret_keys(tags: Any) -> frozenset:
    """
    Read the env var names a user declared as secret in the task's `_ENV_SECRETS` tag.

    Args:
        tags: the value of a task's `tags` key, normally a dict of tag names to values. The TES spec says this is a dict of strings, but `create_task` redacts and logs the
                request body before the TES server has validated it, so it can be any JSON a user sent

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


def _get_executor_envs(task: dict) -> list:
    """
    Args:
        task (dict): a TES task

    Returns:
        list: the `env` dicts of the task's executors. Malformed executors, and `env`s that are
            not dicts, are skipped: a request body is redacted before it is validated.
    """
    executors = task.get("executors")
    if not isinstance(executors, list):
        return []
    return [
        env
        for executor in executors
        if isinstance(executor, dict)
        for key, env in executor.items()
        if isinstance(key, str) and key.lower() == "env" and isinstance(env, dict)
    ]


def _get_secret_env_names(env: dict) -> frozenset:
    """
    Args:
        env (dict): an `env` dict, normally of variable names to values

    Returns:
        frozenset: the lowercased names that match `SECRET_ENV_VAR_NAME`
    """
    lowered_names = (name.lower() for name in env if isinstance(name, str))
    return frozenset(name for name in lowered_names if SECRET_ENV_VAR_NAME.search(name))


def _get_secret_keys(task: dict) -> frozenset:
    """
    Get the names of a task's secret env vars: the ones listed in its `_ENV_SECRETS` tag, and the
    ones whose name matches `SECRET_ENV_VAR_NAME`. Only `executors[*].env` is read, which is where
    the TES spec puts env vars.

    Args:
        task (dict): a TES task

    Returns:
        frozenset: the lowercased names
    """
    secret_keys = set(_get_user_secret_keys(task.get("tags")))
    for env in _get_executor_envs(task):
        secret_keys.update(_get_secret_env_names(env))
    return frozenset(secret_keys)


def _is_env_var_a_secret(name: Any, secret_keys: frozenset) -> bool:
    return isinstance(name, str) and name.lower() in secret_keys


def _get_secret_values(task: dict, secret_keys: frozenset) -> tuple:
    """
    Collect the values of a task's secret env vars, so they can be redacted wherever they are
    echoed: in an executor's `command`, or in logs where a tool printed them (see
    `KNOWN_SECRET_VALUE_KEYS`). This catches secrets that pattern matching on the string alone
    would miss, because the value itself may look like anything.

    `None` values are skipped, and non-string values (e.g. numbers) are converted with `str()`,
    since that is how they would be echoed.

    Args:
        task (dict): a TES task. One without an `executors` list yields no values.
        secret_keys (frozenset): the lowercased names of the task's secret env vars

    Returns:
        tuple: the distinct values of the secret env vars, as strings, longest first so a value
            containing another is fully redacted. Empty values are dropped since they would
            match everywhere.
    """
    values = set()
    for env in _get_executor_envs(task):
        for name, value in env.items():
            # `None` would turn into "None" and redact that word everywhere
            if value is not None and _is_env_var_a_secret(name, secret_keys):
                values.add(str(value))
    values.discard("")
    return tuple(sorted(values, key=len, reverse=True))


def _redact_env_secrets(env: Any, secret_keys: frozenset) -> Any:
    """
    Redact the value of an `env` key. A variable is redacted outright if its name is in
    `secret_keys` or matches `SECRET_ENV_VAR_NAME`. The pattern is checked again here, as
    `secret_keys` only covers executors' envs: an `env` anywhere else is still redacted by name.

    Args:
        env: the value of an `env` key, normally a dict of variable names to values
        secret_keys (frozenset): the lowercased secret env var names of the enclosing task

    Returns:
        a redacted copy of the value
    """
    # the TES spec says this is a dict of strings, but `create_task` redacts and logs the
    # request body before the TES server has validated it, so it can be any JSON a user sent
    if not isinstance(env, dict):
        return _redact(env, secret_keys)
    secret_keys = secret_keys | _get_secret_env_names(env)
    return {
        name: (
            REDACTED_PLACEHOLDER
            if _is_env_var_a_secret(name, secret_keys)
            else _redact(value, secret_keys)
        )
        for name, value in env.items()
    }


def redact_secrets(obj: Any) -> Any:
    """
    Recursively redact secret-looking values in a JSON-like object (dicts, lists, strings).
    Dictionary keys are not redacted. The input object is not modified.

    A task's secret env vars are redacted by name: the ones whose name matches
    `SECRET_ENV_VAR_NAME`, and the ones listed in its `_ENV_SECRETS` tag. Their values are also
    redacted from the strings that may echo them: an executor's `command`, and the task's
    `stdout`, `stderr` and `system_logs`. Each task, including those in a list response, is read
    separately.

    Args:
        obj: object to redact, for example a TES task or a list of TES tasks

    Returns:
        a redacted copy of the object
    """
    return _redact(obj)


def _redact(
    obj: Any,
    secret_keys: frozenset = frozenset(),
    secret_values: tuple = (),
    check_known_values: bool = False,
) -> Any:
    """
    Args:
        secret_keys (frozenset): the lowercased secret env var names of the enclosing task
        secret_values (tuple): the secret env var values of the enclosing task, longest first
        check_known_values (bool): whether `obj` is the value of a `KNOWN_SECRET_VALUE_KEYS` key, in which case
            `secret_values` are redacted from its strings
    """
    if isinstance(obj, str):
        return redact_string(obj, secret_values if check_known_values else ())
    if isinstance(obj, dict):
        # a task is read once, then its secret env vars travel down to its executors and logs
        if "executors" in obj:
            secret_keys = _get_secret_keys(obj)
            secret_values = _get_secret_values(obj, secret_keys)
        return {
            k: (
                _redact_env_secrets(v, secret_keys)
                if isinstance(k, str) and k.lower() == "env"
                else _redact(
                    v, secret_keys, secret_values, k in KNOWN_SECRET_VALUE_KEYS
                )
            )
            for k, v in obj.items()
        }
    if isinstance(obj, Iterable):
        return [_redact(v, secret_keys, secret_values, check_known_values) for v in obj]
    return obj
