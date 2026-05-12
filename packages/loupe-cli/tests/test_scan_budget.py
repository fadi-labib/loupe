"""Tests for `loupe scan --budget-usd <N>` hard-cap pre-flight gate."""

import subprocess
from pathlib import Path
from unittest.mock import patch

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


def test_scan_refuses_when_estimate_over_budget(tmp_path, monkeypatch):
    """If pricing.estimate_cost_usd returns > budget_usd, scan exits 64 and
    prints the estimate alongside the budget."""
    monkeypatch.chdir(tmp_path)
    _init_minimal_loupe(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-noop")

    # Mock pricing.estimate_cost_usd to return $10.00 per lens — well over $0.50.
    with patch("loupe_cli.scan_cmd.estimate_cost_usd", return_value=10.0):
        result = runner.invoke(app, ["scan", "--budget-usd", "0.50"])

    combined = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 64, combined
    assert "budget" in combined.lower()
    assert "0.50" in combined
    assert "10" in combined  # the over-budget estimate appears somewhere


def test_scan_proceeds_when_estimate_under_budget(tmp_path, monkeypatch):
    """Estimate under budget = scan proceeds as today (the rest of the run
    may still fail; we only assert the budget check itself didn't trigger)."""
    monkeypatch.chdir(tmp_path)
    _init_minimal_loupe(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-noop")

    with patch("loupe_cli.scan_cmd.estimate_cost_usd", return_value=0.10):
        result = runner.invoke(app, ["scan", "--budget-usd", "5.00"])

    combined = (result.stdout or "") + (result.stderr or "")
    assert "exceeds budget" not in combined.lower()
    assert "refusing" not in combined.lower()


def test_scan_no_budget_set_is_unchanged(tmp_path, monkeypatch):
    """Without --budget-usd, scan behaves exactly as today — the budget gate
    must not fire when budget_usd is None."""
    monkeypatch.chdir(tmp_path)
    _init_minimal_loupe(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-noop")

    # Even with a high mock estimate, no --budget-usd means no gate.
    with patch("loupe_cli.scan_cmd.estimate_cost_usd", return_value=99.0):
        result = runner.invoke(app, ["scan"])

    combined = (result.stdout or "") + (result.stderr or "")
    assert "exceeds budget" not in combined.lower()
    assert "refusing" not in combined.lower()
