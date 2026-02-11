"""Verifies `loupe ci` exists as a command and exits cleanly.

Phase 7 fleshes out the real implementation. Until then, the command must:
1. Be registered (so `loupe ci --help` doesn't error)
2. Accept the flags the GitHub Action passes (--pr, --config)
3. Exit non-zero with a clear "not yet implemented" message so the action
   doesn't appear to succeed silently
"""
from typer.testing import CliRunner
from loupe_cli.__main__ import app

runner = CliRunner()


def test_ci_command_exists():
    result = runner.invoke(app, ["ci", "--help"])
    assert result.exit_code == 0
    assert "ci" in result.stdout.lower()


def test_ci_accepts_pr_and_config_flags():
    result = runner.invoke(app, ["ci", "--pr", "123", "--config", ".loupe/config.yaml"])
    # Should exit non-zero (not yet implemented), not error on argument parsing
    assert result.exit_code != 0
    # Should NOT error with "No such option" or "Missing argument"
    output = (result.stdout + (result.stderr or "")).lower()
    assert "no such option" not in output
    assert "missing argument" not in output


def test_ci_signals_not_implemented():
    result = runner.invoke(app, ["ci", "--pr", "123"])
    assert result.exit_code != 0
    output = result.stdout + (result.stderr or "")
    assert "not yet implemented" in output.lower() or "phase 7" in output.lower()
