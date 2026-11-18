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
        return redact_secrets(env, declared_secret_env_vars)
    return {
        name: (
            REDACTED_PLACEHOLDER
            if _env_var_names_a_secret(name, declared_secret_env_vars)
            else redact_secrets(value, declared_secret_env_vars)
        )
        for name, value in env.items()
    }


def redact_secrets(obj: Any, declared_secret_env_vars: frozenset = frozenset()) -> Any:
    """
    Recursively redact secret-looking values in a JSON-like object (dicts, lists, strings).
    Dictionary keys are not redacted. The input object is not modified.

    Args:
        obj: object to redact, for example a TES task or a list of TES tasks
        declared_secret_env_vars (frozenset): lowercased env var names declared as secret
            by an enclosing task's `_ENV_SECRETS` tag. Each task in a list response is read
            separately.

    Returns:
        a redacted copy of the object
    """
    if isinstance(obj, str):
        return redact_string(obj)
    if isinstance(obj, dict):
        # a task declares its own secret env vars, so the names travel down to its executors
        declared_secret_env_vars = (
            _declared_secret_env_var_names(obj.get("tags")) or declared_secret_env_vars
        )
        return {
            k: (
                _redact_env_secrets(v, declared_secret_env_vars)
                if isinstance(k, str) and k.lower() == "env"
                else redact_secrets(v, declared_secret_env_vars)
            )
            for k, v in obj.items()
        }
    if isinstance(obj, Iterable):
        return [redact_secrets(v, declared_secret_env_vars) for v in obj]
    return obj
