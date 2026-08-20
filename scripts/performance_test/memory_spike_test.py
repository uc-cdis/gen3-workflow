import inspect
import io
import os
import sys
import textwrap
import time

import boto3
import requests
from botocore.config import Config

"""
Usage:
  # Run all tests:
  GEN3_TOKEN=your_token python memory_spike_test.py

  # Run a single test by label:
  GEN3_TOKEN=your_token python memory_spike_test.py test_s3_upload

Memory profiling is done by a background thread inside the app (debug_memory.py),
so this script does NOT poll during the load test. It calls three endpoints after
the test finishes, which is safe even on a saturated event loop:
  /_debug/memory/sampled  — full timeline collected by the in-app thread
  /_debug/memory/gc-test  — forces gc.collect() and checks if objects are freed
  /_debug/memory/diff     — tracemalloc growth vs the pre-test baseline

Recommended k8s setup for accurate per-worker profiling (avoids ingress routing
requests to different workers):
  1. Set N_WORKERS=1 in the gen3-workflow config and redeploy.
  2. Port-forward the pod: kubectl port-forward <pod> 8000:8000
  3. Set DEBUG_BASE_URL=http://localhost:8000 and run this script.
"""

GEN3_TOKEN = os.environ["GEN3_TOKEN"]
BASE_URL = "https://sai.dev.planx-pla.net/workflows"
SETUP_URL = f"{BASE_URL}/storage/setup"
TES_URL = "https://sai.dev.planx-pla.net/ga4gh/tes/v1/tasks"
S3_ENDPOINT = f"{BASE_URL}/s3"
BUCKET = "gen3wf-sai-dev-planx-pla-net-3"

# Debug endpoints go directly to the pod (via port-forward) to ensure the same
# worker process is measured. Override with the /workflows public URL if needed.
DEBUG_BASE_URL = os.environ.get("DEBUG_BASE_URL", BASE_URL)

NUM_ITERATIONS = 30
FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
POLL_INTERVAL_SECONDS = 5


def auth_headers() -> dict:
    return {"Authorization": f"Bearer {GEN3_TOKEN}"}


def make_s3_client():
    return boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=GEN3_TOKEN,
        aws_secret_access_key="N/A",
        region_name="us-east-1",
        config=Config(
            s3={"addressing_style": "path"},
            retries={"max_attempts": 1},
        ),
    )


# ── Memory collection (post-test) ──────────────────────────────────────────────
# Sampling is done inside the app by a daemon thread (debug_memory.py), so this
# script does not need to poll during the load test. We just collect results
# after the test finishes, when the event loop is no longer saturated.


def _fetch(http: requests.Session, path: str, tag: str) -> dict | None:
    try:
        r = http.get(f"{DEBUG_BASE_URL}{path}", timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"  [memmon:{tag}] WARNING: {e}")
        return None


def start_monitoring(http: requests.Session):
    """Reset the in-app sampler and capture a tracemalloc baseline."""
    result = _fetch(http, "/_debug/memory/snapshot", "snapshot")
    if result:
        print(f"  [memmon] {result.get('status', 'baseline captured')}")
    else:
        print(
            "  [memmon] WARNING: could not reach snapshot endpoint — profiling will be limited"
        )


def collect_report(http: requests.Session, label: str, duration: float) -> dict:
    """After the test, retrieve the full timeline and diagnostic results."""
    print(f"  [memmon] collecting timeline, gc-test, diff for {label}...")
    sampled = _fetch(http, "/_debug/memory/sampled", "sampled")
    gc_result = _fetch(http, "/_debug/memory/gc-test", "gc-test")
    diff_result = _fetch(http, "/_debug/memory/diff", "diff")
    samples = sampled.get("samples", []) if sampled else []
    return {
        "label": label,
        "samples": samples,
        "gc_result": gc_result,
        "diff_result": diff_result,
        "duration": duration,
        "interval_seconds": (
            sampled.get("interval_seconds", POLL_INTERVAL_SECONDS)
            if sampled
            else POLL_INTERVAL_SECONDS
        ),
    }


# ── Report ─────────────────────────────────────────────────────────────────────

WIDTH = 66


def _hr(char="═"):
    return char * WIDTH


def _row(text=""):
    lines = textwrap.wrap(text, WIDTH - 4) or [""]
    return "\n".join(f"║  {l:<{WIDTH - 4}}  ║" for l in lines)


def print_report(data: dict):
    label = data["label"]
    samples = data["samples"]
    gc_result = data.get("gc_result") or {}
    diff_result = data.get("diff_result") or {}
    duration = data["duration"]

    print(f"\n╔{_hr()}╗")
    print(f"║  {'MEMORY SPIKE REPORT: ' + label:^{WIDTH - 4}}  ║")
    print(f"╠{_hr()}╣")
    interval = data.get("interval_seconds", POLL_INTERVAL_SECONDS)
    print(
        _row(
            f"Duration: {duration}s  |  Samples: {len(samples)}  |  Poll interval: {interval}s"
        )
    )
    print(_row(f"Debug URL: {DEBUG_BASE_URL}"))

    # ── Timeline ──
    print(f"╠{_hr('─')}╣")
    print(_row("LARGE BYTES (>500 KB) TIMELINE"))
    print(_row())

    peak_sample = None
    peak_mb = 0.0
    for s in samples:
        count = s.get("count", 0)
        total_mb = s.get("total_mb", 0.0)
        elapsed = s.get("elapsed", "?")
        marker = ""
        if total_mb > peak_mb:
            peak_mb = total_mb
            peak_sample = s
            marker = "  ← peak"
        print(
            _row(f"  t={elapsed}s    count={count}   total={total_mb:.2f} MB{marker}")
        )

    # ── Peak referrer chain ──
    print(f"╠{_hr('─')}╣")
    if peak_sample and peak_sample.get("largest"):
        largest = peak_sample["largest"][0]
        chain = largest.get("referrer_chain", [])
        size_mb = largest.get("size_mb", 0)
        print(
            _row(f"PEAK: {peak_sample.get('count', 0)} objects, {peak_mb:.2f} MB total")
        )
        print(_row(f"Largest object: {size_mb:.2f} MB"))
        print(_row())
        print(_row("Referrer chain (what holds the largest body):"))
        if chain:
            for i, link in enumerate(chain):
                prefix = "  root" if i == len(chain) - 1 else f"  [{i + 1}]"
                print(_row(f"{prefix}  {link}"))
        else:
            print(
                _row(
                    "  (no referrers found — object may have been freed by the time of the call)"
                )
            )
    else:
        print(_row("PEAK: no large bytes objects observed"))

    # ── GC test ──
    print(f"╠{_hr('─')}╣")
    print(_row("POST-TEST GC TEST"))
    print(_row())
    if gc_result:
        before = gc_result.get("large_bytes_before_gc", "?")
        after = gc_result.get("large_bytes_after_gc", "?")
        collected = gc_result.get("objects_collected", "?")
        verdict = gc_result.get("interpretation", "?")
        print(_row(f"  Large bytes before gc.collect(): {before}"))
        print(_row(f"  Large bytes after  gc.collect(): {after}"))
        print(_row(f"  Objects collected by GC:         {collected}"))
        print(_row())
        print(_row(f"  Verdict: {verdict}"))
    else:
        print(_row("  (gc-test endpoint unreachable)"))

    # ── tracemalloc diff ──
    print(f"╠{_hr('─')}╣")
    print(_row("TOP MEMORY GROWTH (tracemalloc diff from baseline)"))
    print(_row())
    grew = diff_result.get("grew", [])
    if grew:
        for entry in grew[:10]:
            loc = entry.get("location", "?")
            kb = entry.get("added_kb", 0)
            count = entry.get("added_count", 0)
            print(_row(f"  +{kb:>6} KB  ({count:>4} allocs)  {loc}"))
    elif diff_result.get("note"):
        print(_row(f"  {diff_result['note']}"))
        for entry in (diff_result.get("top") or [])[:10]:
            loc = entry.get("location", "?")
            kb = entry.get("size_kb", 0)
            count = entry.get("count", 0)
            print(_row(f"  {kb:>7} KB  ({count:>4} allocs)  {loc}"))
    else:
        print(_row("  (diff endpoint unreachable or no growth)"))

    print(f"╚{_hr()}╝\n")


# ── Tests ──────────────────────────────────────────────────────────────────────


def test_setup_storage(http: requests.Session):
    """Call /workflows/storage/setup NUM_ITERATIONS times."""
    for i in range(1, NUM_ITERATIONS + 1):
        resp = http.get(SETUP_URL, headers=auth_headers())
        print(f"[setup {i:03d}] status={resp.status_code}")
        resp.raise_for_status()


def test_s3_upload(s3):
    """Upload a 10 MB in-memory buffer to S3 NUM_ITERATIONS times."""
    for i in range(1, NUM_ITERATIONS + 1):
        key = f"load-test/10mb-{i:03d}.bin"
        data = io.BytesIO(b"0" * FILE_SIZE_BYTES)
        s3.upload_fileobj(data, BUCKET, key)
        print(f"[upload {i:03d}] s3://{BUCKET}/{key}")
        time.sleep(0.05)


def test_tes_create_10mb_file(http: requests.Session):
    """Submit a TES task that generates a 10 MB output file, NUM_ITERATIONS times."""
    task_ids = []
    for i in range(1, NUM_ITERATIONS + 1):
        task = {
            "name": f"Create-10MB-File-{i:03d}",
            "outputs": [
                {
                    "url": f"s3://{BUCKET}/tes-outputs/10mb-{i:03d}.bin",
                    "path": "/work/output.bin",
                    "type": "FILE",
                }
            ],
            "executors": [
                {
                    "image": "quay.io/nextflow/bash",
                    "workdir": "/work",
                    "command": [
                        "/bin/bash",
                        "-c",
                        "dd if=/dev/urandom of=/work/output.bin bs=1M count=10",
                    ],
                }
            ],
        }
        resp = http.post(TES_URL, json=task, headers=auth_headers())
        print(f"[tes {i:03d}] status={resp.status_code}")
        resp.raise_for_status()
        task_ids.append(resp.json().get("id"))
        print(f"[tes {i:03d}] task_id={task_ids[-1]}")
    return task_ids


# ── Registry ───────────────────────────────────────────────────────────────────

TESTS: dict[str, callable] = {
    "test_setup_storage": test_setup_storage,
    "test_s3_upload": test_s3_upload,
    "test_tes_create_10mb_file": test_tes_create_10mb_file,
}


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else None

    if label and label not in TESTS:
        print(f"Unknown test label: {label!r}")
        print(f"Available labels: {', '.join(TESTS)}")
        sys.exit(1)

    http = requests.Session()
    s3 = make_s3_client()
    deps = {"http": http, "s3": s3}

    to_run = {label: TESTS[label]} if label else TESTS

    reports = []
    for name, fn in to_run.items():
        print(f"\n{'=' * 60}\nRunning: {name}\n{'=' * 60}")
        start_monitoring(http)
        t0 = time.monotonic()

        try:
            kwargs = {k: deps[k] for k in inspect.signature(fn).parameters if k in deps}
            fn(**kwargs)
            print(f"Passed:  {name}")
        except Exception as e:
            print(f"FAILED:  {name} — {e}")
        finally:
            duration = round(time.monotonic() - t0, 1)
            report_data = collect_report(http, label=name, duration=duration)
            reports.append(report_data)

    for report_data in reports:
        print_report(report_data)


if __name__ == "__main__":
    main()
