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
`SAMPLE_ID` is returned unchanged.

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

## Be careful what your commands print

**Anything your executor prints is stored as part of the task record, and stays there.** Running
the task again or cancelling it does not remove it.

Executor output is returned when a task is requested with `view=FULL`, and redaction is applied
to those responses the same way. But redaction is a safety net, not a guarantee — the only
reliable way to keep a credential out of the task record is to not print it.

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
* `_ENV_SECRETS` covers an executor's environment variables only. It has no effect on what your
  command writes to stdout or stderr.
* Redaction protects what the API returns and what Gen3-Workflow logs. The backing task database
  holds the task as you submitted it.

Treat redaction as defence in depth, and prefer short-lived credentials wherever your workflow
allows it.
