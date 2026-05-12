"""Tests for `loupe scan --budget-usd <N>` hard-cap pre-flight gate."""

import subprocess
from pathlib import Path

from loupe_cli.__main__ import app
from typer.testing import CliRunner

runner = CliRunner()


def _init_minimal_loupe(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@e.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=tmp_path, check=True)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0, result.stdout


def test_scan_accepts_budget_usd_flag(tmp_path, monkeypatch):
    """The flag wiring exists. Empty paths = full-repo scan; we only assert
    Typer parses the flag without error."""
    monkeypatch.chdir(tmp_path)
    _init_minimal_loupe(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-noop")

    result = runner.invoke(app, ["scan", "--budget-usd", "5.00"])
    combined = (result.stdout or "") + (result.stderr or "")
    assert "no such option" not in combined.lower()
    assert "unexpected extra argument" not in combined.lower()
