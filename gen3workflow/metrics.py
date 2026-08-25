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
