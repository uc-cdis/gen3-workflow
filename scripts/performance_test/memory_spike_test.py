import inspect
import io
import os
import sys
import time

import boto3
import requests
from botocore.config import Config

"""
# Usage:
Run all tests:
GEN3_TOKEN=your_token python memory_spike_test.py

Run a single test by label:
GEN3_TOKEN=your_token python memory_spike_test.py test_setup_storage
"""

# Change the following environment variable to point to your Gen3 instance
# and set your Gen3 token in the environment variable GEN3_TOKEN.
GEN3_TOKEN = os.environ["GEN3_TOKEN"]
SETUP_URL = "https://sai.dev.planx-pla.net/workflows/storage/setup"
TES_URL = "https://sai.dev.planx-pla.net/ga4gh/tes/v1/tasks"
S3_ENDPOINT = "https://sai.dev.planx-pla.net/workflows/s3"
BUCKET = "gen3wf-sai-dev-planx-pla-net-3"
NUM_ITERATIONS = 1000
FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


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
        task_id = resp.json().get("id")
        task_ids.append(task_id)
        print(f"[tes {i:03d}] task_id={task_id}")
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

    for name, fn in to_run.items():
        print(f"\n{'=' * 60}\nRunning: {name}\n{'=' * 60}")
        kwargs = {k: deps[k] for k in inspect.signature(fn).parameters if k in deps}
        fn(**kwargs)
        print(f"Passed:  {name}")


if __name__ == "__main__":
    main()
