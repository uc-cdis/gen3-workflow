"""
Redacts secrets from TES tasks before they are returned in API responses or written to logs.
The task sent to the TES server is never modified.

Two layers of protection:
1. By value: strings are matched against known secret patterns (e.g. a JWT in a `GEN3_TOKEN`
   env var), so secrets are caught wherever they appear in the task, whatever the field name.
2. By name: an executor's env vars are redacted by name, to catch short or low-entropy secrets
   that no pattern can recognise. Users can list their own secret env vars in the task's
   `_ENV_SECRETS` tag.

Modules:
- `patterns`: the secret patterns, and `redact_string` to redact a single string
- `redactor`: `redact_secrets` to redact a whole task (or any nested object)

Performance: about 0.04 ms for a typical task (p50) and 1.8 ms for a page of 50 tasks.
See docs/redaction_benchmark.md for details.
"""

from gen3workflow.redaction.patterns import REDACTED_PLACEHOLDER, redact_string
from gen3workflow.redaction.redactor import ENV_SECRETS_TAG, redact_secrets

__all__ = [
    "ENV_SECRETS_TAG",
    "REDACTED_PLACEHOLDER",
    "redact_secrets",
    "redact_string",
]
