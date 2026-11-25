"""
Unit tests for `gen3workflow.start`, the container entrypoint.
"""

import os

import pytest

from gen3workflow.start import prepare_metrics_directory


def test_prepare_metrics_directory_clears_stale_metrics(tmp_path, monkeypatch):
    """
    Test that `prepare_metrics_directory` deletes stale `*.db` metric files, keeps other files,
    and sets `PROMETHEUS_MULTIPROC_DIR` to the directory
    """
    directory = tmp_path / "metrics"
    directory.mkdir()
    (directory / "counter_123.db").write_text("stale")
    (directory / "keep.txt").write_text("keep")
    monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)

    prepare_metrics_directory(str(directory))

    assert not (directory / "counter_123.db").exists()
    assert (directory / "keep.txt").read_text() == "keep"
    assert os.environ["PROMETHEUS_MULTIPROC_DIR"] == str(directory)


def test_prepare_metrics_directory_creates_missing_directory(tmp_path, monkeypatch):
    """
    Test that `prepare_metrics_directory` creates the metrics directory, including missing parent
    directories, when it does not exist
    """
    directory = tmp_path / "new" / "metrics"
    monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)

    prepare_metrics_directory(str(directory))

    assert directory.is_dir()


def test_prepare_metrics_directory_surfaces_cleanup_errors(tmp_path):
    """
    Test that `prepare_metrics_directory` raises errors hit while deleting stale metric files
    instead of ignoring them.
    """
    (tmp_path / "counter_123.db").mkdir()

    with pytest.raises(OSError):
        prepare_metrics_directory(str(tmp_path))


def test_prepare_metrics_directory_rejects_empty_path():
    """
    Test that `prepare_metrics_directory` rejects an empty path with a `ValueError`
    """
    with pytest.raises(ValueError, match="must not be empty"):
        prepare_metrics_directory("")
