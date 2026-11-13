"""
Value-based detection and redaction of secrets in TES tasks.

Secrets (such as a `GEN3_TOKEN` env var) are detected by looking at values, not names, so they
are caught regardless of the variable name or where they are in the task. As a second line of
defence, an executor's env vars are also redacted by name, which catches short or low-entropy
credentials that no value-based rule can recognise. Users can name their own secret env vars in
the task's `_ENV_SECRETS` tag. Redaction is applied to API responses and to gen3-workflow's own
logs. The task sent to the TES server is unchanged.
"""

import math
import re
from collections import Counter
from typing import Any, Iterable

REDACTED_PLACEHOLDER = "[REDACTED]"

# Required to compute shannon entropy for high-entropy secret detection.
HIGH_ENTROPY_MIN_BITS_PER_CHAR = 4.5
HIGH_ENTROPY_LENGTH_HEADROOM = 1.4
HIGH_ENTROPY_MIN_LENGTH = math.ceil(
    2**HIGH_ENTROPY_MIN_BITS_PER_CHAR * HIGH_ENTROPY_LENGTH_HEADROOM
)
HIGH_ENTROPY_CANDIDATE = re.compile(rf"[A-Za-z0-9+/_=-]{{{HIGH_ENTROPY_MIN_LENGTH},}}")

PATH_MIN_SEPARATORS = 3

# an env var whose name contains one of these holds a secret, whatever its value looks like:
# this covers `GEN3_TOKEN`, `GEN3_API_KEY`, `GEN3_ACCESS_TOKEN`, `TASK_TOKEN`, `DB_PASSWORD`...
# matched against a lowercased name: `re.IGNORECASE` would cost more than the `str.lower()` call
SECRET_ENV_VAR_NAME = re.compile(
    r"credential|key|passphrase|passwd|password|pwd|secret|token"
)

# a task tag holding a comma-separated list of env var names the user declares as secret, for
# credentials this module would not otherwise recognise
ENV_SECRETS_TAG = "_ENV_SECRETS"


def shannon_entropy(s: str) -> float:
    """
    Shannon entropy of a string, in bits per character
    """
    if not s:
        return 0.0
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length) for count in Counter(s).values()
    )


def _looks_like_path(s: str) -> bool:
    # authz resource paths, bucket keys, mount points... a base64 secret is not rooted at "/"
    return s.startswith("/") and s.count("/") >= PATH_MIN_SEPARATORS


def _is_high_entropy_secret(s: str) -> bool:
    if _looks_like_path(s):
        return False
    has_lower = any(c.islower() for c in s)
    has_upper = any(c.isupper() for c in s)
    has_digit = any(c.isdigit() for c in s)
    if not (has_lower and has_upper and has_digit):
        return False
    return shannon_entropy(s) >= HIGH_ENTROPY_MIN_BITS_PER_CHAR


def _redact_token_keeping_prefix(match: re.Match) -> str:
    return match.group("prefix") + REDACTED_PLACEHOLDER


def _redact_auth_scheme_token(match: re.Match) -> str:
    # "basic" and "bearer" are also English words: "bearer of bad news" is not a secret
    looks_like_token = re.search(r"[a-z][A-Z]|\d|[=+/]", match.group("token"))
    if looks_like_token:
        return _redact_token_keeping_prefix(match)
    return match.group(0)


# (pattern, replacement): where replacement is either a string or a callable that takes a regex match and returns a string
SECRET_PATTERNS = [
    # PEM
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
            re.DOTALL,
        ),
        REDACTED_PLACEHOLDER,
    ),
    # JWT
    (
        re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"),
        REDACTED_PLACEHOLDER,
    ),
    # AWS
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), REDACTED_PLACEHOLDER),
    # AWS signature
    (
        re.compile(
            r"(?P<prefix>\b(?:X-Amz-)?Signature=)(?P<token>[^&\s\"']+)", re.IGNORECASE
        ),
        _redact_token_keeping_prefix,
    ),
    # Authorization
    (
        re.compile(
            r"(?P<prefix>\bauthorization[\"']?\s*[:=]\s*[\"']?(?:bearer|basic)\s+)(?P<token>[^\s\"']+)",
            re.IGNORECASE,
        ),
        _redact_token_keeping_prefix,
    ),
    # bearer
    (
        re.compile(
            r"(?P<prefix>\bbearer\s+)(?P<token>[A-Za-z0-9._~+/=-]{8,})", re.IGNORECASE
        ),
        _redact_auth_scheme_token,
    ),
    # basic
    (
        re.compile(
            r"(?P<prefix>\bbasic\s+)(?P<token>[A-Za-z0-9+/]{8,}={0,2})", re.IGNORECASE
        ),
        _redact_auth_scheme_token,
    ),
    # DB URL
    (
        re.compile(
            r"(?P<prefix>\b[a-z][a-z0-9+.-]*://[^\s/:@]+:)(?P<token>[^\s/]+)(?=@)",
            re.IGNORECASE,
        ),
        _redact_token_keeping_prefix,
    ),
]


def redact_string(value: str) -> str:
    """
    Redact any secret-looking substrings from a string.

    Args:
        value (str): string to redact

    Returns:
        str: the string, with secrets replaced by `REDACTED_PLACEHOLDER`
    """
    for pattern, replacement in SECRET_PATTERNS:
        value = pattern.sub(replacement, value)
    value = HIGH_ENTROPY_CANDIDATE.sub(
        lambda m: (
            REDACTED_PLACEHOLDER if _is_high_entropy_secret(m.group(0)) else m.group(0)
        ),
        value,
    )
    return value


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
            if value
            and isinstance(value, str)
            and _env_var_names_a_secret(name, declared_secret_env_vars)
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
