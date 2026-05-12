"""Tests for `loupe ci --verbose` plan-trace output."""

import subprocess
from pathlib import Path

from loupe_cli.__main__ import app
from typer.testing import CliRunner

runner = CliRunner()


def _init_minimal_loupe(tmp_path: Path) -> None:
    """Scaffold a minimal .loupe/ via `loupe init` so ci has something to run against."""
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@e.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=tmp_path, check=True)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0, result.stdout


def test_ci_accepts_verbose_flag(tmp_path, monkeypatch):
    """`loupe ci --verbose --diff '...' --base-sha x --head-sha y` should not error
    on the flag presence (we're testing the wiring, not full ci behaviour)."""
    monkeypatch.chdir(tmp_path)
    _init_minimal_loupe(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-noop")

    result = runner.invoke(
        app,
        ["ci", "--verbose", "--diff", "(no changes)", "--base-sha", "x", "--head-sha", "y"],
    )
    combined = (result.stdout or "") + (result.stderr or "")
    assert "no such option" not in combined.lower()
    assert "unexpected extra argument" not in combined.lower()


def test_ci_verbose_prints_lens_consideration_lines(tmp_path, monkeypatch):
    """With --verbose, each lens considered prints a line naming it and its
    relevance score (or skip reason). Without --verbose, those lines are absent."""
    monkeypatch.chdir(tmp_path)
    _init_minimal_loupe(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-noop")

    diff_text = (
        "diff --git a/example.py b/example.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/example.py\n"
        "@@ -0,0 +1 @@\n"
        "+print('hello')\n"
    )

    quiet = runner.invoke(
        app,
        ["ci", "--diff", diff_text, "--base-sha", "x", "--head-sha", "y"],
    )
    quiet_combined = (quiet.stdout or "") + (quiet.stderr or "")
    assert "[verbose]" not in quiet_combined

    loud = runner.invoke(
        app,
        ["ci", "--verbose", "--diff", diff_text, "--base-sha", "x", "--head-sha", "y"],
    )
    loud_combined = (loud.stdout or "") + (loud.stderr or "")
    assert "[verbose]" in loud_combined
