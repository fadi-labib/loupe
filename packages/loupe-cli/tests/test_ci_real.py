"""Tests for the real `loupe ci` command (post-stub).

These tests don't talk to an LLM — they exercise the CLI's coordination
logic. ThreatLens's stub `run()` is a no-op, so we verify everything
*around* the lens invocation: bootstrap, plan building, run-record
writing, exit codes.
"""
import shutil
from pathlib import Path

from loupe_cli.__main__ import app
from loupe_core.artifacts.run_record import load_run_records
from typer.testing import CliRunner

from .conftest import minimal_config_yaml

runner = CliRunner()
FIXTURES = (
    Path(__file__).parent.parent.parent / "loupe-core" / "tests" / "artifacts" / "fixtures"
)


def _init_project(tmp_path: Path) -> Path:
    """Create a .loupe/ with valid context + minimal config."""
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    shutil.copy(FIXTURES / "valid_context.md", loupe / "context.md")
    (loupe / "config.yaml").write_text(minimal_config_yaml())
    (loupe / "runs").mkdir()
    return loupe


def test_ci_exits_zero_when_no_relevant_lens(tmp_path, monkeypatch):
    """A docs-only diff has no relevant lens — ci should exit 0 with a clear message."""
    monkeypatch.chdir(tmp_path)
    _init_project(tmp_path)

    docs_only_diff = (
        "diff --git a/README.md b/README.md\n"
        "@@ -1 +1,2 @@\n"
        " title\n"
        "+more docs\n"
    )
    result = runner.invoke(
        app, ["ci", "--diff", docs_only_diff, "--base-sha", "a", "--head-sha", "b"],
    )
    assert result.exit_code == 0, result.stdout
    assert "no relevant lens" in result.stdout.lower()


def test_ci_writes_run_record(tmp_path, monkeypatch):
    """Every ci invocation writes a runs/*.json with the lens-considered list."""
    monkeypatch.chdir(tmp_path)
    loupe = _init_project(tmp_path)

    # Code-touching diff — ThreatLens will be considered (and "run", but its
    # current stub run() is a no-op, so no threats.yaml is produced).
    code_diff = (
        "diff --git a/src/api.py b/src/api.py\n"
        "@@ -0,0 +1,3 @@\n"
        "+def x():\n"
        "+    return 1\n"
    )
    result = runner.invoke(
        app, ["ci", "--diff", code_diff, "--base-sha", "a", "--head-sha", "b"],
    )
    assert result.exit_code == 0, result.stdout

    runs = load_run_records(loupe / "runs")
    assert len(runs) == 1
    record = runs[0]
    assert record.mode == "ci"
    assert {lc.name for lc in record.lenses_considered} == {"threatlens"}
    # ThreatLens should have been planned (relevance ≥ threshold)
    assert "threatlens" in record.lenses_run


def test_ci_run_records_chain(tmp_path, monkeypatch):
    """Two successive ci invocations must produce records linked by hash chain."""
    monkeypatch.chdir(tmp_path)
    loupe = _init_project(tmp_path)
    diff = "diff --git a/x.py b/x.py\n@@\n+pass\n"

    r1 = runner.invoke(app, ["ci", "--diff", diff, "--base-sha", "a", "--head-sha", "b"])
    assert r1.exit_code == 0
    r2 = runner.invoke(app, ["ci", "--diff", diff, "--base-sha", "b", "--head-sha", "c"])
    assert r2.exit_code == 0

    runs = load_run_records(loupe / "runs")
    assert len(runs) == 2
    assert runs[0].prev_run_hash is None
    assert runs[1].prev_run_hash == runs[0].self_hash


def test_ci_fails_when_loupe_dir_missing(tmp_path, monkeypatch):
    """Without .loupe/ the command should fail with a helpful message, not crash."""
    monkeypatch.chdir(tmp_path)
    docs_diff = "diff --git a/R.md b/R.md\n@@ -1 +1,2 @@\n x\n+y\n"
    result = runner.invoke(
        app, ["ci", "--diff", docs_diff, "--base-sha", "a", "--head-sha", "b"],
    )
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "loupe init" in combined.lower() or ".loupe" in combined


def test_ci_diff_file_option(tmp_path, monkeypatch):
    """`--diff-file path` should read the diff content from the file."""
    monkeypatch.chdir(tmp_path)
    _init_project(tmp_path)
    diff_file = tmp_path / "pr.patch"
    diff_file.write_text(
        "diff --git a/src/x.py b/src/x.py\n@@ -0,0 +1 @@\n+pass\n"
    )
    result = runner.invoke(
        app, ["ci", "--diff-file", str(diff_file), "--base-sha", "a", "--head-sha", "b"],
    )
    assert result.exit_code == 0, result.stdout


def test_ci_rejects_both_diff_flags(tmp_path, monkeypatch):
    """Passing both --diff and --diff-file must exit 64 (sysexits.h EX_USAGE)."""
    monkeypatch.chdir(tmp_path)
    _init_project(tmp_path)
    diff_file = tmp_path / "pr.patch"
    diff_file.write_text("diff --git a/x b/x\n@@\n+y\n")
    result = runner.invoke(
        app,
        [
            "ci", "--diff", "diff --git a/x b/x\n@@\n+z\n",
            "--diff-file", str(diff_file),
        ],
    )
    assert result.exit_code == 64
    combined = (result.stdout or "") + (result.stderr or "")
    assert "mutually exclusive" in combined.lower()


def test_ci_rejects_when_neither_diff_flag_given(tmp_path, monkeypatch):
    """Omitting both --diff and --diff-file must exit 64."""
    monkeypatch.chdir(tmp_path)
    _init_project(tmp_path)
    result = runner.invoke(app, ["ci", "--base-sha", "a", "--head-sha", "b"])
    assert result.exit_code == 64
    combined = (result.stdout or "") + (result.stderr or "")
    assert "exactly one" in combined.lower()
