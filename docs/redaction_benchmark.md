# Redaction benchmark

Benchmark of `gen3workflow.redaction.redact_secrets` end to end (env var name checks and the
redaction of secret env var values from `command`, `stdout`, `stderr` and `system_logs` included).

## Sample

A dump of ~29,000 TES tasks (~1.6M strings, ~86 MB of text), made from a dump of real tasks with
secrets added so that redaction has work to do:

- every executor has 2 to 4 added env vars whose names say they hold a secret (for example
  `DB_PASSWORD`, `GEN3_API_KEY` or `CLIENT_SECRET`), with random values;
- 10% of the tasks have an `_ENV_SECRETS` tag declaring 1 to 3 more env vars, whose names do not
  say they hold a secret (for example `DATABASE_URL` or `SALT`), and the executor has these env vars;
- 20% of the tasks have the values of 1 to 3 of those secret env vars written into their `stdout`
  or `stderr`.

## Latency per call

| Unit                | p50     | p95     | p99     | max   |
|---------------------|---------|---------|---------|-------|
| one task per call   | 0.05 ms | 0.16 ms | 0.39 ms | 82 ms |
| page of 50 per call | 2.4 ms  | 9.9 ms  | 13.2 ms | 85 ms |

## Whole-dump runs

| Run                   | Time   | Rate                       |
|-----------------------|--------|----------------------------|
| all tasks, one by one | 2.19 s | about 39 MB of text per s  |
| whole dump, one call  | 2.50 s | about 1.5 µs per string    |

## Slowest 5 tasks

One task per call (mean over 5 passes), by position in the dump:

| Task   | Time    | Text    |
|--------|---------|---------|
| #18    | 80.9 ms | 3827 KB |
| #19    | 3.1 ms  | 163 KB  |
| #13678 | 1.5 ms  | 21 KB   |
| #13683 | 1.5 ms  | 21 KB   |
| #13687 | 1.5 ms  | 21 KB   |

The first is a task with 3.8 MB of logs: the time is linear in the length of the strings.

About 6.3% of the strings were changed.
