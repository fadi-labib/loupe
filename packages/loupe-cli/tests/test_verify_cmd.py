"""Tests for `loupe verify` — Layer 3 enforcement entry point.

The actual verification logic lives in loupe_core/enforcement/verify.py
and is independently tested there. These tests verify the CLI surface:
exit codes, output formatting, the .loupe/ presence check.
"""
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from loupe_cli.__main__ import app
from typer.testing import CliRunner

from .conftest import minimal_config_yaml

runner = CliRunner()
FIXTURES = (
    Path(__file__).parent.parent.parent / "loupe-core" / "tests" / "artifacts" / "fixtures"
)


class _FrozenClock:
    """A ``datetime`` stand-in that yields successive frozen timestamps.

    Two ``loupe ci`` invocations back-to-back must produce distinct
    run-record filenames; the filenames are timestamp-derived, so we
    inject a clock that advances by a known delta between calls instead
    of trusting wall-clock microsecond resolution.
    """

    def __init__(self, start: datetime, step: timedelta) -> None:
        self._now = start
        self._step = step

    def now(self, tz: object = None) -> datetime:  # noqa: ARG002 — match datetime API
        current = self._now
        self._now = self._now + self._step
        return current


@pytest.fixture
def frozen_ci_clock(monkeypatch: pytest.MonkeyPatch) -> _FrozenClock:
    """Freeze the clock used by ``ci_cmd.datetime.now`` to a deterministic sequence.

    The CLI's ci command stamps each run with ``datetime.now(UTC)`` and
    derives the run-record filename from that timestamp. Using the real
    clock makes ordering tests brittle (two writes within the same
    microsecond would collide). Injecting a controlled sequence keeps
    the test focussed on chain semantics, not on wall-clock luck.
    """
    clock = _FrozenClock(
        start=datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC),
        step=timedelta(seconds=1),
    )

    class _FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz: object = None) -> datetime:  # noqa: ARG003 — match API
            return clock.now(tz)

    monkeypatch.setattr("loupe_cli.ci_cmd.datetime", _FrozenDatetime)
    return clock


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


def test_verify_exits_zero_after_two_ci_runs(tmp_path, monkeypatch, frozen_ci_clock):
    """Run two ci invocations, then verify — chain should be intact."""
    monkeypatch.chdir(tmp_path)
    loupe = _init_project(tmp_path)
    (loupe / "config.yaml").write_text(
        minimal_config_yaml(
            agent_writable_paths=[".loupe/runs/**"],
            threatlens_enabled=False,
            threatlens_min_relevance=0.99,
        )
    )
    # Two clean ci runs (docs-only diff → no-relevant-lens path, but each
    # still writes a run record). Empty diff is no longer a valid input —
    # `loupe ci` requires exactly one of --diff/--diff-file with content.
    docs_diff = "diff --git a/R.md b/R.md\n@@ -1 +1,2 @@\n x\n+y\n"
    runner.invoke(app, ["ci", "--diff", docs_diff, "--base-sha", "a", "--head-sha", "b"])
    runner.invoke(app, ["ci", "--diff", docs_diff, "--base-sha", "b", "--head-sha", "c"])

    result = runner.invoke(app, ["verify"])
    assert result.exit_code == 0, result.stdout


def test_verify_detects_broken_chain(tmp_path, monkeypatch, frozen_ci_clock):
    """Tamper with a run record's prev_run_hash — verify must catch it."""
    monkeypatch.chdir(tmp_path)
    loupe = _init_project(tmp_path)
    (loupe / "config.yaml").write_text(
        minimal_config_yaml(
            agent_writable_paths=[".loupe/runs/**"],
            threatlens_enabled=False,
            threatlens_min_relevance=0.99,
        )
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
