import logging
import os
import subprocess
import time
import threading
import asyncio
import sys
from typing import Dict, List, Any
from dataclasses import dataclass, field
from statistics import mean, stdev


VERBOSE = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("download_performance_results/test_run.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    tool_name: str
    run_number: int
    successful: float
    total_time: float
    return_code: int = 0
    error_count: int = 0
    error_details: List[str] = field(default_factory=list)


@dataclass
class TestResult:
    method_name: str
    metrics: PerformanceMetrics
    timing_breakdown: Dict[str, Dict[str, float]] = field(default_factory=dict)


class RealTimeMonitor:
    def __init__(self, interval: float):
        self.interval = interval
        self.monitoring = False
        self.metrics = []
        self.thread = None

    def start_monitoring(self):
        """Start real-time monitoring."""
        self.monitoring = True
        self.metrics = []
        self.thread = threading.Thread(target=self._monitor_loop)
        self.thread.daemon = True
        self.thread.start()

    def stop_monitoring(self) -> Dict[str, Any]:
        """Stop monitoring and return aggregated metrics."""
        self.monitoring = False
        if self.thread:
            self.thread.join(timeout=2.0)

        if not self.metrics:
            return {}

        cpu_values = [m["cpu_percent"] for m in self.metrics]
        memory_values = [m["memory_mb"] for m in self.metrics]

        return {
            "peak_memory_mb": max(memory_values),
            "avg_memory_mb": mean(memory_values),
            "peak_cpu_percent": max(cpu_values),
            "avg_cpu_percent": mean(cpu_values),
            "sample_count": len(self.metrics),
            "duration": len(self.metrics) * self.interval,
        }

    def _monitor_loop(self):
        """Internal monitoring loop."""
        while self.monitoring:
            try:
                memory_info = type("obj", (object,), {"used": 0})()
                cpu_percent = 0

                self.metrics.append(
                    {
                        "timestamp": time.time(),
                        "cpu_percent": cpu_percent,
                        "memory_mb": memory_info.used / (1024 * 1024)
                        if hasattr(memory_info, "used")
                        else 0,
                        "memory_percent": getattr(memory_info, "percent", 0),
                    }
                )
                time.sleep(self.interval)
            except Exception:
                break


def calculate_aggregated_metrics(metrics_list):
    n_runs = len(metrics_list)
    n_successful_runs = 0
    total_time = 0
    total_time_successful = 0
    successful_times = []
    # print('calculate_aggregated_metrics')
    for m in metrics_list:
        # print(f'm {m}')
        total_time += m.total_time
        if not m.successful:
            continue
        n_successful_runs += 1
        total_time_successful += m.total_time
        successful_times.append(m.total_time)

    return {
        "total_runs": n_runs,
        "successful_runs": n_successful_runs,
        "success_percent": n_successful_runs / n_runs * 100,
        "avg_run_time": total_time / n_runs,
        "successful_avg_run_time": total_time_successful / n_successful_runs if n_successful_runs else None,
        "min_successful_run_time": min(successful_times) if successful_times else None,
        "max_successful_run_time": max(successful_times) if successful_times else None,
        "stdev_successful_run_time": stdev(successful_times) if len(successful_times) > 1 else None,
    }



async def run_tool(
    cmd: List[str],
    run_number: int,
    config: dict,
) -> PerformanceMetrics:
    """Run a tool with detailed performance metrics - non-blocking via executor."""

    monitor = RealTimeMonitor(0.1)
    total_start_time = time.time()
    tool_name = config["type"]

    if monitor:
        monitor.start_monitoring()

    try:
        # Run blocking subprocess in a thread pool so other coroutines can proceed
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,  # uses default ThreadPoolExecutor
            lambda: subprocess.run(cmd, capture_output=True, text=True)
        )

        monitoring_stats = monitor.stop_monitoring() if monitor else {}

        successful = True
        if result.returncode != 0 or "ERROR" in result.stdout:
            if VERBOSE:
                logger.info(f"failure - {result.returncode} - {result.stderr}")
            successful = False
        elif VERBOSE:
            logger.info(f"success - {result.stdout}")

        total_time = time.time() - total_start_time

        logger.info(f"📊 {tool_name} Run {run_number}: successful? {successful}, in {total_time:.2f}s")

        return PerformanceMetrics(
            tool_name=tool_name,
            run_number=run_number,
            successful=successful,
            total_time=total_time,
            return_code=result.returncode,
        )

    except Exception as e:
        logger.error(f"❌ {tool_name} Run {run_number} failed: {e}")
        if monitor:
            monitor.stop_monitoring()
        return PerformanceMetrics(
            tool_name=tool_name,
            run_number=run_number,
            successful=False,
            total_time=0,
            return_code=-1,
            error_details=[str(e)],
        )

class Gen3SDKTester:
    """Enhanced Gen3 SDK tester with async and sync support, profiling and monitoring."""

    async def run_tes_task(
        self, run_number: int, config: dict
    ) -> PerformanceMetrics:
        """Test Gen3 SDK download-multiple functionality with enhanced monitoring."""

        import random
        # r = random.randint(-2, 4)
        r = random.randint(-1, 0)
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

        return await run_tool(
            cmd,
            run_number,
            config,
        )



async def tmp(config):
    # all_res = []

    logger.info(f"🔧 Testing {config['name']} with {config['concurrency']} concurrent runs")

    tester = Gen3SDKTester()
    # method = getattr(tester, "run_tes_task")
    tasks = [
        tester.run_tes_task(run_number=run, config=config)
        for run in range(1, config["concurrency"] + 1)
    ]
    # print('tasks', tasks)

    # TODO: change this, the concurrency is not supposed to be here but in `run_tes_task`
    run_results = await asyncio.gather(*tasks)


    
    # print('run_results')
    # for e in run_results:
    #     print(f'  {e}')


    # all_res.append(run_results)
    logger.info(f"  ✅ All {config['concurrency']} concurrent runs finished.")

    # print('all_res', all_res)
    return run_results


async def main():
    """Enhanced main function with comprehensive performance testing, multiple runs, and detailed analysis."""
    os.makedirs("download_performance_results", exist_ok=True)


    N_RUNS = 2  # how many times to run each test. then we get the average metrics
    test_configs = [
        {
            "name": "TES",
            "type": "TES", # / Nextflow
            "jobs": 1,
            "concurrency": 2,
        }
    ]

    all_metrics = []
    for test_config in test_configs:
        logger.info(f"🔧 Testing {test_config['name']} {N_RUNS} times sequentially")

        for run in range(1, N_RUNS + 1):
            # print("=== SEQ run", run)
            run_results = await tmp(config=test_config)
            # print('run_results', run_results)

            agg = calculate_aggregated_metrics(run_results)
            logger.info(f"----- SEQ run {run} stats -----")
            logger.info(f"total_runs: {agg['total_runs']}")
            logger.info(f"successful_runs: {agg['successful_runs']}")
            logger.info(f"Success Rate: {agg['success_percent']:.2f}%")
            logger.info(f"avg_run_time: {agg['avg_run_time']}")
            logger.info(f"successful_avg_run_time: {agg['successful_avg_run_time']}")
            logger.info(f"min_successful_run_time: {agg['min_successful_run_time']}")
            logger.info(f"max_successful_run_time: {agg['max_successful_run_time']}")
            logger.info(f"stdev_successful_run_time: {agg['stdev_successful_run_time']}")

            all_metrics.extend(run_results)

        logger.info(f"  ✅ All {N_RUNS} sequential runs finished.")

    # print('  => all_metrics')
    # for m in all_metrics:
    #     print(m)

    # TODO get latency
    tested_methods = list(set(m.tool_name for m in all_metrics))
    for tool_name in tested_methods:
        agg = calculate_aggregated_metrics([m for m in all_metrics if m.tool_name == tool_name])
        logger.info(f"----- {tool_name} stats -----")
        logger.info(f"total_runs: {agg['total_runs']}")
        logger.info(f"successful_runs: {agg['successful_runs']}")
        logger.info(f"Success Rate: {agg['success_percent']:.2f}%")
        logger.info(f"avg_run_time: {agg['avg_run_time']}")
        logger.info(f"successful_avg_run_time: {agg['successful_avg_run_time']}")
        logger.info(f"min_successful_run_time: {agg['min_successful_run_time']}")
        logger.info(f"max_successful_run_time: {agg['max_successful_run_time']}")
        logger.info(f"stdev_successful_run_time: {agg['stdev_successful_run_time']}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.exception("⚠️  Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.exception(f"❌ Test failed with error: {e}")
        raise
