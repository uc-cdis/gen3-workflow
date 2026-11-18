# Redaction benchmark

Benchmark of `gen3workflow.redaction.redact_secrets` end to end (env var name checks included),
on a dump of real TES tasks (~29,000 tasks, ~1.5M strings, ~81 MB of text).

## Latency per call

| Unit                | p50     | p95     | p99     | max    |
|---------------------|---------|---------|---------|--------|
| one task per call   | 0.04 ms | 0.12 ms | 0.31 ms | 68 ms  |
| page of 50 per call | 1.8 ms  | 7.9 ms  | 10.5 ms | 129 ms |

## Whole-dump runs

| Run                   | Time  | Rate                       |
|-----------------------|-------|----------------------------|
| all tasks, one by one | 1.6 s | about 49 MB of text per s  |
| whole dump, one call  | 2.0 s | about 1.4 µs per string    |

## Slowest 5 tasks

One task per call (mean over 3 passes), by position in the dump:

| Task   | Time      | Text     |
|--------|-----------|----------|
| #18    | 67.0 ms   | 3827 KB  |
| #19    | 2.4 ms    | 163 KB   |
| #13678 | 1.2 ms    | 20 KB    |
| #13719 | 1.2 ms    | 20 KB    |
| #13683 | 1.2 ms    | 20 KB    |

About 0.03% of the strings were changed.
