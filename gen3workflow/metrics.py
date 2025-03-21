from typing import Any, Dict

from cdispyutils.metrics import BaseMetrics

from gen3workflow.config import config


class Metrics(BaseMetrics):
    def __init__(self, prometheus_dir: str, enabled: bool = True) -> None:
        super().__init__(
            prometheus_dir=config["PROMETHEUS_MULTIPROC_DIR"], enabled=enabled
        )
