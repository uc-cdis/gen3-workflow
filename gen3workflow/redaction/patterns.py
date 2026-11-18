"""
Value-based detection of secrets in strings: the patterns, and `redact_string`, which applies them.
"""

import math
import re
from collections import Counter
from typing import Callable, NamedTuple, Union

REDACTED_PLACEHOLDER = "[REDACTED]"

# Required to compute shannon entropy for high-entropy secret detection.
HIGH_ENTROPY_MIN_BITS_PER_CHAR = 4.5
HIGH_ENTROPY_LENGTH_HEADROOM = 1.4
HIGH_ENTROPY_MIN_LENGTH = math.ceil(
    2**HIGH_ENTROPY_MIN_BITS_PER_CHAR * HIGH_ENTROPY_LENGTH_HEADROOM
)
HIGH_ENTROPY_CANDIDATE = re.compile(rf"[A-Za-z0-9+/_=-]{{{HIGH_ENTROPY_MIN_LENGTH},}}")

PATH_MIN_SEPARATORS = 2


def _shannon_entropy(s: str) -> float:
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
    return _shannon_entropy(s) >= HIGH_ENTROPY_MIN_BITS_PER_CHAR


def _redact_token_keeping_prefix(match: re.Match) -> str:
    return match.group("prefix") + REDACTED_PLACEHOLDER


def _redact_auth_scheme_token(match: re.Match) -> str:
    # "basic" and "bearer" are also English words: "bearer of bad news" is not a secret
    looks_like_token = re.search(r"[a-z][A-Z]|\d|[=+/]", match.group("token"))
    if looks_like_token:
        return _redact_token_keeping_prefix(match)
    return match.group(0)


class SecretPattern(NamedTuple):
    """
    A regex that recognises one kind of secret.

    Attributes:
        name: what the pattern recognises. Documentation only.
        hint: a lowercase literal the regex cannot match without, so a string that does not
            contain it can skip the regex entirely. This roughly halves the time spent on
            patterns, because most strings in a task hold none of these literals.
        regex: the compiled pattern.
        replacement: a string, or a callable that takes a regex match and returns a string
            (as in `re.sub`).
    """

    name: str
    hint: str
    regex: re.Pattern
    replacement: Union[str, Callable[[re.Match], str]]


SECRET_PATTERNS = [
    SecretPattern(
        name="PEM private key",
        hint="private key",
        regex=re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
            re.DOTALL,
        ),
        replacement=REDACTED_PLACEHOLDER,
    ),
    SecretPattern(
        name="JWT",
        hint="eyj",
        regex=re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"),
        replacement=REDACTED_PLACEHOLDER,
    ),
    SecretPattern(
        name="AWS long-term key ID",
        hint="akia",
        regex=re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
        replacement=REDACTED_PLACEHOLDER,
    ),
    SecretPattern(
        name="AWS temporary key ID",
        hint="asia",
        regex=re.compile(r"\bASIA[A-Z0-9]{16}\b"),
        replacement=REDACTED_PLACEHOLDER,
    ),
    SecretPattern(
        name="AWS signature",
        hint="signature=",
        regex=re.compile(
            r"(?P<prefix>\b(?:X-Amz-)?Signature=)(?P<token>[^&\s\"']+)", re.IGNORECASE
        ),
        replacement=_redact_token_keeping_prefix,
    ),
    SecretPattern(
        name="Authorization header",
        hint="authorization",
        regex=re.compile(
            r"(?P<prefix>\bauthorization[\"']?\s*[:=]\s*[\"']?(?:bearer|basic)\s+)(?P<token>[^\s\"']+)",
            re.IGNORECASE,
        ),
        replacement=_redact_token_keeping_prefix,
    ),
    SecretPattern(
        name="bearer token",
        hint="bearer",
        regex=re.compile(
            r"(?P<prefix>\bbearer\s+)(?P<token>[A-Za-z0-9._~+/=-]{8,})", re.IGNORECASE
        ),
        replacement=_redact_auth_scheme_token,
    ),
    SecretPattern(
        name="basic auth token",
        hint="basic",
        regex=re.compile(
            r"(?P<prefix>\bbasic\s+)(?P<token>[A-Za-z0-9+/]{8,}={0,2})", re.IGNORECASE
        ),
        replacement=_redact_auth_scheme_token,
    ),
    SecretPattern(
        name="password in a DB URL",
        # "@" is rarer than "://", so it rules out more strings
        hint="@",
        regex=re.compile(
            r"(?P<prefix>\b[a-z][a-z0-9+.-]*://[^\s/:@]+:)(?P<token>[^\s/]+)(?=@)",
            re.IGNORECASE,
        ),
        replacement=_redact_token_keeping_prefix,
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
    lowered = value.lower()
    for pattern in SECRET_PATTERNS:
        if pattern.hint in lowered:
            value = pattern.regex.sub(pattern.replacement, value)
    value = HIGH_ENTROPY_CANDIDATE.sub(
        lambda m: (
            REDACTED_PLACEHOLDER if _is_high_entropy_secret(m.group(0)) else m.group(0)
        ),
        value,
    )
    return value
