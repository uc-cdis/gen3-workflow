# Secrets in TES tasks

Tasks often need credentials: a Gen3 token to reach an API, a database password, a license key.
Gen3-Workflow redacts secret-looking values before returning a task to the user.
Redacted values are replaced with `[REDACTED]`.

The task sent to the TES server is **not** modified, so your executors still receive the real
values at runtime.

## What is redacted automatically

You do not have to do anything for these. Gen3-Workflow looks at the *values* in a task, anywhere
in the task, and redacts anything that looks like:

* a PEM private key
* a JWT, such as a Gen3 access token
* an AWS access key ID, or the signature on a presigned S3 URL
* an `Authorization`, `Bearer` or `Basic` credential
* a password embedded in a connection URL, such as `postgres://user:password@host/db`
* a long, random-looking string that no pattern recognises

It also looks at the *names* of an executor's environment variables, and redacts any variable
whose name contains `credential`, `key`, `passphrase`, `passwd`, `password`, `pwd`, `secret` or
`token`. So `GEN3_TOKEN`, `GEN3_API_KEY` and `DB_PASSWORD` are all covered even when their values
are too short or too predictable to be recognised on their own.

The *values* of those variables are then looked for in the rest of the task. If the value of
`DB_PASSWORD` appears in the task's `command`, `stdout`, `stderr` or system logs — for example
because a command echoed it, or a tool printed it in an error message — it is redacted there too,
even when it does not look like a secret. See [Secret values in commands and
logs](#secret-values-in-commands-and-logs).

## Declaring your own secret env vars

Some credentials look like ordinary text — a short license key, a username, an account number —
and are stored in a variable whose name says nothing about it. Name those variables in the
special `_ENV_SECRETS` tag, as a comma-separated list, and they will be redacted too:

```
{
  "name": "my-job",
  "tags": {"_ENV_SECRETS": "MY_LICENSE,ACCOUNT_NUMBER"},
  "executors": [
    {
      "image": "quay.io/nextflow/bash",
      "command": ["my-tool", "--run"],
      "env": {
        "MY_LICENSE": "ABC-123",
        "ACCOUNT_NUMBER": "40041",
        "SAMPLE_ID": "S42"
      }
    }
  ]
}
```

Reading that task back returns `MY_LICENSE` and `ACCOUNT_NUMBER` as `[REDACTED]`, while
`SAMPLE_ID` is returned unchanged. If `ABC-123` or `40041` appears in the task's `command`,
`stdout`, `stderr` or system logs, it is redacted there as well.

Notes:

* Names are matched in full, not as fragments, and case does not matter. Declaring `MY_LICENSE`
  redacts `MY_LICENSE` and `my_license`, but not `MY_LICENSE_PATH`.
* Spaces around the names are ignored, so `"MY_LICENSE, ACCOUNT_NUMBER"` works too.
* The tag is set once per task, and applies to every executor in that task. A variable only has
  to be named once, however many executors use it.
* The tag applies only to the task it is on. Other tasks are unaffected, including tasks in the
  same list response.
* The tag itself is returned as you wrote it, so you can always see what you declared. It holds
  variable *names*, not their values.

## Secret values in commands and logs

The value of every secret environment variable of a task — one whose name matches the list above,
or one you declared in `_ENV_SECRETS` — is also redacted wherever it appears in these fields of
the same task:

* an executor's `command`
* the `stdout` and `stderr` of the executor logs
* the task's `system_logs`

So with the task above, the log line `Connecting with license ABC-123` is returned as
`Connecting with license [REDACTED]`.

This is an exact text match, and it has limits:

* Only the fields listed above are checked. The task's `name`, `description`, `image`, `inputs`
  and other fields are not, so do not put a credential there.
* A value that has been changed before it is printed — encoded (for example base64), hashed,
  truncated, or split over several lines or log entries — no longer matches. Only the original
  value is recognised.
* A short or common value is redacted everywhere it appears in those fields, including inside
  unrelated text. A value of `40041` also redacts the `40041` in `1400412`. Empty values are
  ignored.
* The values are only collected from the task's own executors. Another task's values are never
  used, including tasks in the same list response.

### Secrets are shared across the executors of a task

The values are collected from **all** of a task's executors and redacted from **every**
executor's logs, not only from the logs of the executor that declared them. Executors in a task
share its volumes, so a later executor can read and print a secret it never had in its own `env`:

```
{
  "volumes": ["/shared"],
  "executors": [
    {
      "image": "alpine",
      "command": ["sh", "-c", "echo \"$DB_PASSWORD\" > /shared/pw && echo \"wrote $DB_PASSWORD\""],
      "env": {"DB_PASSWORD": "hunter2"}
    },
    {
      "image": "alpine",
      "command": ["sh", "-c", "echo \"read $(cat /shared/pw) for $SAMPLE_ID\""],
      "env": {"SAMPLE_ID": "S42"}
    }
  ]
}
```

The second executor has no secret of its own, but its `stdout`, `read hunter2 for S42`, is
returned as `read [REDACTED] for S42`, just like the first executor's `wrote [REDACTED]`.

In the TES task, `logs` holds one entry per attempt, and each attempt's `logs` holds one entry per
executor, in the same order as `executors`. Every one of those executor logs is checked for every
secret value of the task.

## Be careful what your commands print

**Anything your executor prints is stored as part of the task record, and stays there.** Running
the task again or cancelling it does not remove it.

Executor output is returned when a task is requested with `view=FULL`, and redaction is applied
to those responses the same way, including the exact values of your secret environment variables.
But redaction is a safety net, not a guarantee — a credential that is not one of your environment
variables, or that is transformed before it is printed, is only caught if it looks like a secret.
The only reliable way to keep a credential out of the task record is to not print it.

In particular:

* Do not `echo` or `print` a credential, even temporarily while debugging.
* Avoid `set -x` in shell commands. It echoes every command as it runs, including any secret
  passed as an argument.
* Avoid `curl -v`, which prints request headers, including `Authorization`.
* Prefer passing credentials through `env` rather than as command arguments, since arguments are
  easier to print by accident and show up in process listings inside the container.

## Limitations

* Detection is heuristic. It can miss a credential whose value and variable name both look
  ordinary — which is what `_ENV_SECRETS` is for — and it can over-redact a value that merely
  looks random, such as a long checksum.
* `_ENV_SECRETS` declares which environment variables are secret. Their values are redacted from
  an executor's `command`, the `stdout` and `stderr` of its logs, and the task's system logs, but
  only as an exact match: a transformed value (encoded, truncated, split over several lines) is
  not recognised, and other fields of the task are not checked.
  A credential your command generates or reads from somewhere other than an environment variable
  is not covered unless it looks like a secret.
* Redaction protects what the API returns and what Gen3-Workflow logs. The backing task database
  holds the task as you submitted it.

Treat redaction as defence in depth, and prefer short-lived credentials wherever your workflow
allows it.
