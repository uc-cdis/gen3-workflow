import asyncio
from dataclasses import dataclass
import json
import os
import random
from statistics import stdev
import subprocess
import sys
import time
from typing import List

from cdislogging import get_logger

VERBOSE = 1
N_SEQ_RUNS = 3
ENDPOINT = "https://brhstaging.data-commons.org"
BUCKET = "gen3wf-brhstaging-data-commons-org-35"

# TODO
# GPU TES
# nextflow number of tasks
TESTS = [
    # {
    #     "name": "Random failures",
    #     "type": "Random",
    #     "n_sequential_runs": N_SEQ_RUNS,
    #     "n_concurrent_runs": 5,
    # },
    # {
    #     "name": f"TES test (concurrency: {1})",
    #     "type": "TES",
    #     "n_sequential_runs": N_SEQ_RUNS,
    #     "n_concurrent_runs": 1,
    #     "body": {
    #         "name": "Hello-World",
    #         "executors": [
    #             {"image": "quay.io/nextflow/bash", "command": ["echo hello world!"]}
    #         ],
    #     },
    # },
    # {
    #     "name": f"Nextflow CPU test (concurrency: {1})",
    #     "type": "Nextflow",
    #     "n_sequential_runs": N_SEQ_RUNS,
    #     "n_concurrent_runs": 1,
    #     "n_tasks": 2,
    #     "gpu": False,
    #     "workflow_file": "hello.nf",
    # }
]
# TES tests
for concurrency in [5, 10, 15]:
    # break
    TESTS.append(
        {
            "name": f"TES test (concurrency {concurrency})",
            "type": "TES",
            "n_sequential_runs": N_SEQ_RUNS,
            "n_concurrent_runs": concurrency,
            "body": {
                "name": "Hello-World",
                "executors": [
                    {"image": "quay.io/nextflow/bash", "command": ["echo hello world!"]}
                ],
            },
        }
    )
    # TODO fix this: missing bucket env var
    TESTS.append(
        {
            "name": f"TES test with inputs/outputs (concurrency {concurrency})",
            "type": "TES",
            "n_sequential_runs": N_SEQ_RUNS,
            "n_concurrent_runs": concurrency,
            "body": {
                "name": "Input-Output-Test",
                "inputs": [
                    {
                        "url": f"s3://{BUCKET}/inputs/test-file.txt",
                        "path": "/work/test-file.txt",
                        "type": "FILE",
                    }
                ],
                "outputs": [
                    {
                        "url": f"s3://{BUCKET}/outputs/output.txt",
                        "path": "/work/output.txt",
                        "type": "FILE",
                    }
                ],
                "executors": [
                    {
                        "image": "quay.io/nextflow/bash",
                        "workdir": "/work",
                        "command": ["cat test-file.txt && echo hello > output.txt"],
                    }
                ],
            },
        }
    )
# Nextflow tests
for concurrency in [5, 10]:
    for n_tasks in [1, 5, 10]:
        # break
        # Note: Nextflow tests always include inputs/outputs
        TESTS.append(
            {
                "name": f"Nextflow CPU test ({n_tasks} tasks, concurrency {concurrency})",
                "type": "Nextflow",
                "n_sequential_runs": N_SEQ_RUNS,
                "n_concurrent_runs": concurrency,
                "n_tasks": n_tasks,
                "gpu": False,
                "workflow_file": "hello.nf",
            }
        )
        TESTS.append(
            {
                "name": f"Nextflow GPU test ({n_tasks} tasks, concurrency {concurrency})",
                "type": "Nextflow",
                "n_sequential_runs": N_SEQ_RUNS,
                "n_tasks": n_tasks,
                "n_concurrent_runs": concurrency,
                "gpu": True,
                "workflow_file": "gpu.nf",
            }
        )


CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
logger = get_logger("tes-perf", log_level="debug" if VERBOSE else "info")


@dataclass
class RunStats:
    test_name: str
    seq_id: int
    conc_id: int
    successful: float
    run_time: float
    return_code: int
    error_details: str = ""


def compute_stats(metrics_list, total_run_time=None):
    n_runs = len(metrics_list)
    n_successful_runs = 0
    avg_run_time = 0
    total_time_failed = 0
    successful_run_times = []

    for m in metrics_list:
        avg_run_time += m.run_time
        if not m.successful:
            total_time_failed += m.run_time
            continue
        n_successful_runs += 1
        successful_run_times.append(m.run_time)

    avg_run_time = avg_run_time / n_runs
    n_failed_runs = n_runs - n_successful_runs

    logger.info(f"Number of runs: {n_runs}")
    logger.info(f"Successful runs: {n_successful_runs}")
    if n_runs:
        logger.info(f"Success rate: {n_successful_runs / n_runs * 100:.2f}%")
    if total_run_time:
        logger.info(f"Total run time: {total_run_time:.2f}s")
    logger.info(f"Average run time (all runs): {avg_run_time:.2f}s")
    if n_successful_runs:
        logger.info(
            f"Average run time (successful runs): {sum(successful_run_times) / n_successful_runs:.2f}s"
        )
        logger.info(f"Min run time (successful runs): {min(successful_run_times):.2f}s")
        logger.info(f"Max run time (successful runs): {max(successful_run_times):.2f}s")
    if n_failed_runs:
        logger.info(
            f"Average run time (failed runs): {total_time_failed / n_failed_runs:.2f}s"
        )
    if len(successful_run_times) > 1:
        logger.info(
            f"Run time standard deviation (successful runs): {stdev(successful_run_times):.2f}s"
        )
    logger.info("")


async def run_command(
    cmd: List[str], seq_id: int, conc_id: int, config: dict, env: dict = {}
) -> RunStats:
    start_time = time.time()
    test_name = config["name"]

    try:
        loop = asyncio.get_event_loop()
        # TODO add a timeout
        my_env = {**os.environ.copy(), **env}
        result = await loop.run_in_executor(
            None,  # uses default ThreadPoolExecutor
            # lambda: subprocess.run(cmd, capture_output=True, text=True),
            lambda: subprocess.run(cmd, env=my_env, capture_output=True, text=True),
        )
        run_time = time.time() - start_time

        successful = True
        if result.returncode != 0 or "ERROR" in result.stdout:
            successful = False
        logger.debug(
            f"    Run 'seq{seq_id}-conc{conc_id}' {'completed' if successful else 'failed'} in {run_time:.2f}s"
        )
        if not successful:
            stdout = f"{result.stdout}\n---\n" if result.stdout else ""
            logger.debug(
                f"    Error code: {result.returncode}. Logs:\n{stdout}{result.stderr}"
            )
        elif result.stdout:
            logger.debug(f"    Logs:\n{result.stdout}")

        return RunStats(
            test_name=test_name,
            seq_id=seq_id,
            conc_id=conc_id,
            successful=successful,
            run_time=run_time,
            return_code=result.returncode,
        )

    except Exception as e:
        logger.error(f"❌ {test_name} Run 'seq{seq_id}-conc{conc_id}' failed: {e}")
        # raise
        return RunStats(
            test_name=test_name,
            seq_id=seq_id,
            conc_id=conc_id,
            successful=False,
            run_time=0,
            return_code=-1,
            error_details=str(e),
        )


async def run_random_failures(seq_id: int, conc_id: int, config: dict) -> RunStats:
    r = random.randint(-2, 3)
    cmd = ["sleep", str(r)]
    return await run_command(cmd, seq_id, conc_id, config)


async def run_nextflow_workflow(seq_id: int, conc_id: int, config: dict) -> RunStats:
    cmd = [
        "gen3",
        "run",
        "nextflow",
        "run",
        os.path.join(CURRENT_DIR, config["workflow_file"]),
        "-c",
        os.path.join(CURRENT_DIR, "base_nextflow.config"),
        "--n_tasks",
        f"{config["n_tasks"]}",
    ]
    return await run_command(
        cmd,
        seq_id,
        conc_id,
        config,
        {
            "ENDPOINT": ENDPOINT,
            "BUCKET": BUCKET,
            "GPU": "yes" if config["gpu"] else "no",
        },
    )


async def run_tes_task(seq_id: int, conc_id: int, config: dict) -> RunStats:
    body = config["body"]
    cmd = [
        "gen3",
        "run",
        "python",
        "run_tes_task.py",
        ENDPOINT,
        json.dumps(body),
    ]
    return await run_command(cmd, seq_id, conc_id, config)


async def run_tests():
    all_stats = []
    for config in TESTS:
        logger.info(
            f"[{config['name']}] Launching {config['n_sequential_runs']} sequential runs"
        )
        for seq_run in range(1, config["n_sequential_runs"] + 1):
            _type = config["type"]
            if _type == "Random":
                method = run_random_failures
            elif _type == "Nextflow":
                method = run_nextflow_workflow
            elif _type == "TES":
                method = run_tes_task
            else:
                raise Exception(f"Unknown test type '{_type}'")

            n_concurrent_runs = config["n_concurrent_runs"]
            logger.info(
                f"  [{config['name']}] Launching {n_concurrent_runs} concurrent runs"
            )
            tasks = [
                method(seq_id=seq_run, conc_id=conc_run, config=config)
                for conc_run in range(1, n_concurrent_runs + 1)
            ]
            start_time = time.time()
            run_stats = await asyncio.gather(*tasks)
            total_run_time = time.time() - start_time

            logger.info(
                f"✅ [{config['name']}] Sequential run #{seq_run} completed. Stats:"
            )
            compute_stats(run_stats, total_run_time)
            all_stats.extend(run_stats)

        # TODO get latency
        tested_methods = list(set(m.test_name for m in all_stats))
        for test_name in tested_methods:
            logger.info(
                f"✅ [{config['name']}] All sequential runs completed. Final stats:"
            )
            compute_stats([m for m in all_stats if m.test_name == test_name])


if __name__ == "__main__":
    try:
        asyncio.run(run_tests())
    except KeyboardInterrupt:
        logger.exception("Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"❌ Test failed with error: {e}")
        raise
