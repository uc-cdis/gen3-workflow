"""
Usage:
  # Run all scenarios:
  GEN3_TOKEN=your_token python memory_spike.py

  # Run a single scenario by label:
  GEN3_TOKEN=your_token python memory_spike.py run_s3_upload

  # Pause for keyboard input after every 10 iterations:
  GEN3_TOKEN=your_token python memory_spike.py --with-pause run_s3_upload
"""

import argparse
import inspect
import io
import json
import os
import sys
import time

import boto3
import jwt
import requests
from botocore.config import Config

GEN3_TOKEN = os.environ["GEN3_TOKEN"]
hostname = jwt.decode(GEN3_TOKEN, options={"verify_signature": False})["iss"].split(
    "/user"
)[0]
print(hostname)
BASE_URL = f"{hostname}/workflows"
SETUP_URL = f"{BASE_URL}/storage/setup"
TES_URL = f"{BASE_URL}/ga4gh/tes/v1/tasks"
S3_ENDPOINT = f"{BASE_URL}/s3"

NUM_ITERATIONS = 100
FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB
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


def get_bucket_name_from_setup() -> str:
    """Call /workflows/storage/setup to get the bucket name."""
    resp = requests.get(SETUP_URL, headers=auth_headers())
    resp.raise_for_status()
    return resp.json()["bucket"]


# ── Scenarios ──────────────────────────────────────────────────────────────────


def run_setup_storage(http: requests.Session, with_pause: bool = False):
    """Call /workflows/storage/setup NUM_ITERATIONS times."""
    elapsed = []
    for i in range(1, NUM_ITERATIONS + 1):
        if with_pause and i % 10 == 0:
            user_input = input(
                f"Press Enter to continue with setup iteration {i} ... or press C to continue without pausing"
            )
            if user_input.upper() == "C":
                with_pause = False
        start = time.monotonic()
        resp = http.get(SETUP_URL, headers=auth_headers())
        elapsed.append(time.monotonic() - start)
        print(f"[setup {i:03d}] status={resp.status_code}; elapsed={elapsed[-1]:.1f}s")
        resp.raise_for_status()
        time.sleep(
            1
        )  # Change this to 0.05 after ratelimiting is handled in gen3-workflow (https://ctds-planx.atlassian.net/browse/MIDRC-1340)
    print(f"[setup] average setup elapsed time: {sum(elapsed) / len(elapsed):.1f}s")


def run_s3_upload(s3, bucket_name: str, with_pause: bool = False):
    """Upload a 100 MB in-memory buffer to S3 NUM_ITERATIONS times."""
    elapsed = []
    for i in range(1, NUM_ITERATIONS + 1):
        if with_pause and i % 10 == 0:
            user_input = input(
                f"Press Enter to continue with upload {i} ... or press C to continue without pausing"
            )
            if user_input.upper() == "C":
                with_pause = False
        key = f"load-test/{FILE_SIZE_BYTES // (1024 * 1024)}mb-{i:03d}.bin"
        data = io.BytesIO(b"0" * FILE_SIZE_BYTES)
        start = time.monotonic()
        s3.upload_fileobj(data, bucket_name, key)
        elapsed.append(time.monotonic() - start)
        print(f"[upload {i:03d}] s3://{bucket_name}/{key}; elapsed={elapsed[-1]:.1f}s")
        time.sleep(0.05)
    print(f"[upload] average upload elapsed time: {sum(elapsed) / len(elapsed):.1f}s")


def run_tes_create_and_upload_file(
    http: requests.Session, bucket_name: str, with_pause: bool = False
):
    """Submit a TES task that generates a 10 MB output file, NUM_ITERATIONS times."""
    print(
        f"Starting {NUM_ITERATIONS} tasks of {FILE_SIZE_BYTES // (1024 * 1024)} MB files..."
    )
    task_ids = []
    elapsed = []
    for i in range(1, NUM_ITERATIONS + 1):
        if with_pause and i % 10 == 0:
            user_input = input(
                f"Press Enter to continue with TES task {i} ... or press C to continue without pausing"
            )
            if user_input.upper() == "C":
                with_pause = False
        task = {
            "name": f"Create-{FILE_SIZE_BYTES // (1024 * 1024)}MB-File-{i:03d}",
            "outputs": [
                {
                    "url": f"s3://{bucket_name}/tes-outputs/{FILE_SIZE_BYTES // (1024 * 1024)}mb-{i:03d}.bin",
                    "path": "/work/output.bin",
                    "type": "FILE",
                }
            ],
            "tags": {
                "_IMAGE_PULL_POLICY": "IfNotPresent",
            },
            "executors": [
                {
                    "image": "quay.io/nextflow/bash",
                    "workdir": "/work",
                    "command": [
                        "/bin/bash",
                        "-c",
                        f"dd if=/dev/urandom of=/work/output.bin bs=1M count={FILE_SIZE_BYTES // (1024 * 1024)}",
                    ],
                }
            ],
        }
        start = time.monotonic()
        resp = http.post(TES_URL, json=task, headers=auth_headers())
        elapsed.append(time.monotonic() - start)
        print(f"[tes {i:03d}] status={resp.status_code}; elapsed={elapsed[-1]:.1f}s")
        resp.raise_for_status()
        task_ids.append(resp.json().get("id"))
        print(f"[tes {i:03d}] task_id={task_ids[-1]}")
        time.sleep(0.05)
    print(f"[tes] average POST elapsed time: {sum(elapsed) / len(elapsed):.1f}s")
    return task_ids


def run_tes_create_hello_world(http: requests.Session, with_pause: bool = False):
    """TES task that just echoes 'Hello World' NUM_ITERATIONS times, to test memory usage without large file output."""
    task_ids = []
    elapsed = []
    for i in range(1, NUM_ITERATIONS + 1):
        if with_pause and i % 10 == 0:
            user_input = input(
                f"Press Enter to continue with TES task {i} ... or press C to continue without pausing"
            )
            if user_input.upper() == "C":
                with_pause = False
        task = {
            "name": f"Say Hello world-{i:03d}",
            "tags": {
                "_IMAGE_PULL_POLICY": "IfNotPresent",
            },
            "executors": [
                {
                    "image": "quay.io/nextflow/bash",
                    "workdir": "/work",
                    "command": ["echo Hello World"],
                }
            ],
        }
        start = time.monotonic()
        resp = http.post(TES_URL, json=task, headers=auth_headers())
        elapsed.append(time.monotonic() - start)
        print(f"[tes {i:03d}] status={resp.status_code}; elapsed={elapsed[-1]:.1f}s")
        resp.raise_for_status()
        task_ids.append(resp.json().get("id"))
        print(f"[tes {i:03d}] task_id={task_ids[-1]}")
        time.sleep(0.05)
    print(f"[tes] average POST elapsed time: {sum(elapsed) / len(elapsed):.1f}s")
    return task_ids


# ── Registry ───────────────────────────────────────────────────────────────────

TESTS: dict[str, callable] = {
    "run_setup_storage": run_setup_storage,
    "run_s3_upload": run_s3_upload,
    "run_tes_create_and_upload_file": run_tes_create_and_upload_file,
    "run_tes_create_hello_world": run_tes_create_hello_world,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "label", nargs="?", default=None, help="Scenario label to run (default: all)"
    )
    parser.add_argument(
        "--with-pause",
        action="store_true",
        help="Pause for keyboard input after every 10 iterations",
    )
    args = parser.parse_args()
    label = args.label

    if label and label not in TESTS:
        print(f"Unknown test label: {label!r}")
        print(f"Available labels: {', '.join(TESTS)}")
        sys.exit(1)

    http = requests.Session()
    s3 = make_s3_client()
    bucket_name = get_bucket_name_from_setup()
    deps = {
        "http": http,
        "s3": s3,
        "with_pause": args.with_pause,
        "bucket_name": bucket_name,
    }
    print(f"Using bucket: {bucket_name}")
    to_run = {label: TESTS[label]} if label else TESTS

    for name, fn in to_run.items():
        print(f"\n{'=' * 60}\nRunning: {name}\n{'=' * 60}")
        t0 = time.monotonic()

        try:
            kwargs = {k: deps[k] for k in inspect.signature(fn).parameters if k in deps}
            task_ids = fn(**kwargs)
            print(f"Completed: {name}")

            if task_ids:
                print(
                    f"Polling {len(task_ids)} TES tasks until they are all complete..."
                )
                while True:
                    statuses = {}
                    for task_id in task_ids:
                        r = http.get(f"{TES_URL}/{task_id}", headers=auth_headers())
                        r.raise_for_status()
                        statuses[task_id] = r.json().get("state")
                    incomplete = {
                        tid: s for tid, s in statuses.items() if s != "COMPLETE"
                    }
                    task_ids = list(incomplete.keys())
                    print(f"TES task statuses: {incomplete}")
                    if all(
                        s in ("COMPLETE", "EXECUTOR_ERROR", "SYSTEM_ERROR")
                        for s in statuses.values()
                    ):
                        print("All TES tasks complete.")
                        break
                    print(f"— waiting {POLL_INTERVAL_SECONDS}s...")
                    time.sleep(POLL_INTERVAL_SECONDS)
            print(f"Passed:  {name}")
            failed_statuses = []
            for task_id in task_ids:
                r = http.get(f"{TES_URL}/{task_id}?view=FULL", headers=auth_headers())
                r.raise_for_status()
                print(f"Incomplete Task {task_id} final state: {r.json().get('state')}")
                failed_statuses.append(r.json())
            print(
                f"Failed task details: {json.dumps(failed_statuses, indent=2) if failed_statuses else 'None'}"
            )

        except KeyboardInterrupt:
            print(f"Aborted: {name}")
        except Exception as e:
            print(f"FAILED: @ {time.strftime('%Y-%m-%d %H:%M:%S')} {name} — {e}")
        finally:
            duration = round(time.monotonic() - t0, 1)
            print(f"Duration: {duration}s")


if __name__ == "__main__":
    main()
