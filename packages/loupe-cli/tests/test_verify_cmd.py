"""Tests for `loupe verify` — Layer 3 enforcement entry point.

The actual verification logic lives in loupe_core/enforcement/verify.py
and is independently tested there. These tests verify the CLI surface:
exit codes, output formatting, the .loupe/ presence check.
"""
import json
import shutil
from pathlib import Path

from loupe_cli.__main__ import app
from typer.testing import CliRunner

runner = CliRunner()
FIXTURES = (
    Path(__file__).parent.parent.parent / "loupe-core" / "tests" / "artifacts" / "fixtures"
)


def _init_project(tmp_path: Path) -> Path:
    """Minimal .loupe/ with a valid run-record chain (two runs)."""
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    shutil.copy(FIXTURES / "valid_context.md", loupe / "context.md")
    (loupe / "runs").mkdir()
    return loupe


def test_verify_exits_zero_on_clean_repo(tmp_path, monkeypatch):
    """No runs at all → verify has nothing to check → exits 0."""
    monkeypatch.chdir(tmp_path)
    _init_project(tmp_path)
    result = runner.invoke(app, ["verify"])
    assert result.exit_code == 0, result.stdout
    assert "ok" in result.stdout.lower()


def test_verify_exits_zero_after_two_ci_runs(tmp_path, monkeypatch):
    """Run two ci invocations, then verify — chain should be intact."""
    monkeypatch.chdir(tmp_path)
    loupe = _init_project(tmp_path)
    (loupe / "config.yaml").write_text(
        "schema_version: 1\n"
        "models:\n  default: anthropic:claude-opus-4-7\n"
        "limits:\n"
        "  per_run_max_usd: 1.0\n  per_run_max_tokens_in: 100000\n  per_run_max_steps: 5\n"
        "agent_writable_paths: [.loupe/runs/**]\n"
        "lenses:\n  threatlens:\n    enabled: false\n    minimum_relevance: 0.99\n"
    )
    # Two clean ci runs (docs-only diff → no-relevant-lens path, but each
    # still writes a run record). Empty diff is no longer a valid input —
    # `loupe ci` requires exactly one of --diff/--diff-file with content.
    docs_diff = "diff --git a/R.md b/R.md\n@@ -1 +1,2 @@\n x\n+y\n"
    runner.invoke(app, ["ci", "--diff", docs_diff, "--base-sha", "a", "--head-sha", "b"])
    runner.invoke(app, ["ci", "--diff", docs_diff, "--base-sha", "b", "--head-sha", "c"])

    result = runner.invoke(app, ["verify"])
    assert result.exit_code == 0, result.stdout


def test_verify_detects_broken_chain(tmp_path, monkeypatch):
    """Tamper with a run record's prev_run_hash — verify must catch it."""
    monkeypatch.chdir(tmp_path)
    loupe = _init_project(tmp_path)
    (loupe / "config.yaml").write_text(
        "schema_version: 1\n"
        "models:\n  default: anthropic:claude-opus-4-7\n"
        "limits:\n"
        "  per_run_max_usd: 1.0\n  per_run_max_tokens_in: 100000\n  per_run_max_steps: 5\n"
        "agent_writable_paths: [.loupe/runs/**]\n"
        "lenses:\n  threatlens:\n    enabled: false\n    minimum_relevance: 0.99\n"
    )
    docs_diff = "diff --git a/R.md b/R.md\n@@ -1 +1,2 @@\n x\n+y\n"
    runner.invoke(app, ["ci", "--diff", docs_diff, "--base-sha", "a", "--head-sha", "b"])
    runner.invoke(app, ["ci", "--diff", docs_diff, "--base-sha", "b", "--head-sha", "c"])

    # Corrupt the second run record's chain pointer.
    runs = sorted((loupe / "runs").glob("*.json"))
    assert len(runs) == 2
    second = json.loads(runs[1].read_text())
    second["prev_run_hash"] = "0" * 64
    runs[1].write_text(json.dumps(second, indent=2, sort_keys=True))

    result = runner.invoke(app, ["verify"])
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "chain" in combined.lower() or "verify" in combined.lower()
