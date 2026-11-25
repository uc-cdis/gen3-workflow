import os

import pytest

from gen3workflow.start import prepare_metrics_directory


def test_prepare_metrics_directory_clears_stale_metrics(tmp_path, monkeypatch):
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
    directory = tmp_path / "new" / "metrics"
    monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)

    prepare_metrics_directory(str(directory))

    assert directory.is_dir()


def test_prepare_metrics_directory_surfaces_cleanup_errors(tmp_path):
    (tmp_path / "counter_123.db").mkdir()

    with pytest.raises(IsADirectoryError):
        prepare_metrics_directory(str(tmp_path))


def test_prepare_metrics_directory_rejects_empty_path():
    with pytest.raises(ValueError, match="must not be empty"):
        prepare_metrics_directory("")
