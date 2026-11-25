import os
from pathlib import Path

from gen3workflow.config import config


def prepare_metrics_directory(path: str) -> None:
    if not path:
        raise ValueError("PROMETHEUS_MULTIPROC_DIR must not be empty")
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    for metric_file in directory.glob("*.db"):
        metric_file.unlink()
    os.environ["PROMETHEUS_MULTIPROC_DIR"] = str(directory)


def main() -> None:
    prepare_metrics_directory(config["PROMETHEUS_MULTIPROC_DIR"])

    import uvicorn

    uvicorn.run(
        "gen3workflow.app:app",
        host="0.0.0.0",
        port=int(os.environ.get("UVICORN_PORT", "8000")),
        timeout_graceful_shutdown=int(
            os.environ.get("UVICORN_TIMEOUT_GRACEFUL_SHUTDOWN", "90")
        ),
    )


if __name__ == "__main__":
    main()
