from cdispyutils.metrics import BaseMetrics
from gen3workflow import logger

from gen3workflow.config import config


class Metrics(BaseMetrics):
    def __init__(
        self,
        prometheus_dir: str = config["PROMETHEUS_MULTIPROC_DIR"],
        enabled: bool = True,
    ) -> None:
        logger.info(f"Setting up Metrics with {prometheus_dir=} and {enabled=}")
        super().__init__(prometheus_dir=prometheus_dir, enabled=enabled)

    def add_task_created(self, status_code: int) -> None:
        """
        Count a GA4GH TES task that was successfully created.

        Counts creations rather than attempts: a rejected request is already covered by
        `gen3_workflow_api_requests`, which records every response with its status code.

        Args:
            status_code (int): status code the task creation returned
        """
        self.increment_counter(
            name="gen3_workflow_tasks_created",
            labels={"status_code": str(status_code)},
            description="GA4GH TES tasks created through this service.",
        )
