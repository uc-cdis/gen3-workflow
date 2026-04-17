import asyncio
from dataclasses import dataclass
from statistics import stdev
import subprocess
import sys
import time
from typing import List

from cdislogging import get_logger


VERBOSE = True

TESTS = [
    {
        "name": "TES test",
        "type": "TES",  # / Nextflow
        "jobs": 1,
        "n_sequential_runs": 2,
        "n_concurrent_runs": 4,
    }
]


logger = get_logger("tes-perf", log_level="debug" if VERBOSE else "info")


@dataclass
class RunStats:
    tool_name: str
    run_id: int
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
        logger.info(f"Success Rate: {n_successful_runs / n_runs * 100:.2f}%")
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


async def run_command(cmd: List[str], run_id: int, config: dict) -> RunStats:
    start_time = time.time()
    tool_name = config["name"]

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,  # uses default ThreadPoolExecutor
            lambda: subprocess.run(cmd, capture_output=True, text=True),
        )
        run_time = time.time() - start_time

        successful = True
        if result.returncode != 0 or "ERROR" in result.stdout:
            successful = False
        logger.debug(
            f"    Run '{run_id}' {'completed' if successful else 'failed'} in {run_time:.2f}s"
        )
        if not successful:
            stdout = f"{result.stdout}\n---\n" if result.stdout else ""
            logger.debug(
                f"    Error code: {result.returncode}. Logs:\n{stdout}{result.stderr}"
            )
        elif result.stdout:
            logger.debug(f"    Logs:\n{result.stdout}")

        return RunStats(
            tool_name=tool_name,
            run_id=run_id,
            successful=successful,
            run_time=run_time,
            return_code=result.returncode,
        )

    except Exception as e:
        logger.error(f"❌ {tool_name} Run '{run_id}' failed: {e}")
        return RunStats(
            tool_name=tool_name,
            run_id=run_id,
            successful=False,
            run_time=0,
            return_code=-1,
            error_details=str(e),
        )


async def run_tes_task(run_id: int, config: dict) -> RunStats:
    import random

    r = random.randint(-2, 3)
    # r = random.randint(-1, 0)
    # print('   r', r)

    cmd = [
        "sleep",
        f"{r}",
        # "&&",
        # "gen3",
        # "run",
        # "nextflow",
        # "run",
        # "/Users/paulineribeyre/Projects/nextflow-api/hello.nf",
        # "-c",
        # # "/Users/paulineribeyre/Projects/gen3-workflow/scripts/nextflow.config",
        # "/Users/paulineribeyre/Projects/nextflow-api/devenv_nextflow.config",
    ]

    return await run_command(
        cmd,
        run_id,
        config,
    )


async def run_tests():
    all_stats = []
    for config in TESTS:
        logger.info(
            f"Running '{config['name']}' test {config['n_sequential_runs']} times sequentially"
        )
        for seq_run in range(1, config["n_sequential_runs"] + 1):
            _type = config["type"]
            if _type == "TES":
                method = run_tes_task
            else:
                raise Exception(f"Unknown test type '{_type}'")

            n_concurrent_runs = config["n_concurrent_runs"]
            logger.info(
                f"  Running '{config['name']}' test with {n_concurrent_runs} concurrent runs"
            )
            tasks = [
                method(run_id=f"s{seq_run}c{conc_run}", config=config)
                for conc_run in range(1, n_concurrent_runs + 1)
            ]
            start_time = time.time()
            run_stats = await asyncio.gather(*tasks)
            total_run_time = time.time() - start_time

            logger.info(f"✅ Sequential run #{seq_run} completed. Stats:")
            compute_stats(run_stats, total_run_time)
            all_stats.extend(run_stats)

        # TODO get latency
        tested_methods = list(set(m.tool_name for m in all_stats))
        for tool_name in tested_methods:
            logger.info(f"✅ All sequential runs completed. Final stats:")
            compute_stats([m for m in all_stats if m.tool_name == tool_name])


if __name__ == "__main__":
    try:
        asyncio.run(run_tests())
    except KeyboardInterrupt:
        logger.exception("Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"❌ Test failed with error: {e}")
        raise
