import json
import logging

import pytest

from gen3workflow import logger
from gen3workflow.app import configure_logging
from gen3workflow.config import config

# The loggers `configure_logging` takes ownership of. Snapshotted and restored so that the
# session-scoped `client` fixture and every later test keep the format they were built with.
CONFIGURED_LOGGERS = [
    None,
    "gen3workflow",
    "gen3config.config",
    "uvicorn",
    "uvicorn.error",
    "uvicorn.access",
]


@pytest.fixture(autouse=True)
def restore_logging():
    """
    Restore the logging configuration and `ENABLE_JSON_LOGS` after each test in this module.
    """
    original_json_logs = config["ENABLE_JSON_LOGS"]
    snapshot = {
        name: (
            logging.getLogger(name).handlers[:],
            logging.getLogger(name).level,
            logging.getLogger(name).propagate,
        )
        for name in CONFIGURED_LOGGERS
    }

    yield

    config["ENABLE_JSON_LOGS"] = original_json_logs
    for name, (handlers, level, propagate) in snapshot.items():
        restored = logging.getLogger(name)
        restored.handlers[:] = handlers
        restored.setLevel(level)
        restored.propagate = propagate


def logging_enabled(json_logs: bool):
    """
    Configure logging with JSON output on or off.

    Args:
        json_logs (bool): whether log lines should be JSON objects
    """
    config["ENABLE_JSON_LOGS"] = json_logs
    configure_logging()


def emitted_lines(capsys) -> list:
    """
    Return the non-empty lines the loggers have written to stdout so far.

    Args:
        capsys: pytest's output capturing fixture

    Returns:
        list: the captured lines
    """
    return [line for line in capsys.readouterr().out.splitlines() if line.strip()]


def test_json_logs_emit_one_parsable_object_per_line(capsys):
    """
    With JSON logging enabled, a logged message is a single parsable JSON object.
    """
    logging_enabled(True)
    logger.info("hello from the service")

    lines = emitted_lines(capsys)
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["logger"] == "gen3workflow"
    assert record["level"] == "INFO"
    assert record["message"] == "hello from the service"
    assert record["timestamp"]


def test_json_logs_disabled_emit_the_text_format(capsys):
    """
    With JSON logging disabled, log lines keep the human-readable text format.
    """
    logging_enabled(False)
    logger.info("hello from the service")

    lines = emitted_lines(capsys)
    assert len(lines) == 1
    assert lines[0].startswith("[")
    assert lines[0].endswith("hello from the service")
    with pytest.raises(json.JSONDecodeError):
        json.loads(lines[0])


def test_exception_traceback_stays_on_one_json_line(capsys):
    """
    A traceback is JSON-escaped into the `exception` field instead of spanning several lines.
    """
    logging_enabled(True)
    try:
        raise ValueError("something went wrong")
    except ValueError:
        logger.exception("failed to do the thing")

    lines = emitted_lines(capsys)
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["message"] == "failed to do the thing"
    assert "ValueError: something went wrong" in record["exception"]


def test_library_logger_shares_the_service_format(capsys):
    """
    A library that configured its own handler before startup still logs in the chosen format.
    """
    logging_enabled(True)
    logging.getLogger("gen3config.config").info("applying configuration")

    lines = emitted_lines(capsys)
    assert len(lines) == 1
    assert json.loads(lines[0])["logger"] == "gen3config.config"


@pytest.mark.parametrize("json_logs", [True, False], ids=["json", "text"])
def test_reconfiguring_does_not_duplicate_output(capsys, json_logs):
    """
    Configuring logging more than once in a process still emits one line per logged message.
    """
    logging_enabled(json_logs)
    logging_enabled(json_logs)
    logger.info("hello from the service")

    assert len(emitted_lines(capsys)) == 1
