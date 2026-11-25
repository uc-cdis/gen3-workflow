import os
from pathlib import Path

from gen3workflow.config import config


def prepare_metrics_directory(path: str) -> None:
    """
    Prepare the Prometheus multiprocess metrics directory and export it as
    `PROMETHEUS_MULTIPROC_DIR`. Must run before `prometheus_client` is imported.

    Creates the directory if needed and deletes stale `*.db` metric files left by previous
    processes. Other files are kept.

    Args:
        path (str): path to the metrics directory

    Raises:
        ValueError: if `path` is empty
        OSError: if the directory cannot be created or a stale metric file cannot be deleted
    """
    if not path:
        raise ValueError("PROMETHEUS_MULTIPROC_DIR must not be empty")
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    for metric_file in directory.glob("*.db"):
        metric_file.unlink()
    os.environ["PROMETHEUS_MULTIPROC_DIR"] = str(directory)


def main() -> None:
    """
    Container entrypoint: prepare the metrics directory, then serve the app with a single
    uvicorn worker. The port and graceful shutdown timeout can be set with the
    `UVICORN_PORT` (default 8000) and `UVICORN_TIMEOUT_GRACEFUL_SHUTDOWN` (default 90 seconds)
    environment variables.
    """
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
