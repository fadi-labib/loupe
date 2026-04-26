"""Unit tests for `ThreatLens.run`'s LLM-usage telemetry capture.

The lens must warn loudly when it can't read token counts off the
PydanticAI result — silent zero-defaulting would hide a future SDK rename
that produced a cost-tracking blackout [principle §8 "Cost discipline"].

These tests stub `build_agent` so they exercise the telemetry-capture
branch without needing a real provider SDK or API key.
"""

from __future__ import annotations

import logging
from datetime import datetime
from types import SimpleNamespace

from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.run_context import (
    LensRunPlan,
    RelevanceScore,
    RunContext,
)
from loupe_threatlens.lens import ThreatLens


def _ctx() -> RunContext:
    return RunContext(
        run_id="r",
        mode="ci",
        started_at=datetime(2026, 5, 15),
        user_intent="",
        diff=None,
        sbom_delta=None,
        project=None,
        plan=[],
        knowledge=None,
    )


def _plan() -> LensRunPlan:
    return LensRunPlan(
        lens_name="threatlens",
        relevance=RelevanceScore(score=0.95, reason="test"),
        depends_on=[],
        sub_prompt="test focus",
    )


class _FakeAgent:
    """Minimal stand-in for a PydanticAI Agent that returns a canned result."""

    def __init__(self, result):
        self._result = result

    async def run(self, prompt, deps):  # noqa: ARG002 — match Agent.run signature
        return self._result


async def test_warns_when_usage_is_none(monkeypatch, caplog, tmp_path):
    """If `result.usage` is None, the lens must log a WARNING."""
    fake_result = SimpleNamespace(usage=None)
    monkeypatch.setattr(
        "loupe_threatlens.lens.build_agent",
        lambda model_id: _FakeAgent(fake_result),
    )
    loupe_dir = tmp_path / ".loupe"
    loupe_dir.mkdir()
    lens = ThreatLens()
    ctx = _ctx()

    with caplog.at_level(logging.WARNING, logger="loupe_threatlens.lens"):
        await lens.run(ctx, _plan(), PathBoundary(writable_globs=[]), loupe_dir)

    warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("returned None" in r.message for r in warning_records), (
        f"expected a 'returned None' WARNING, got: {[r.message for r in warning_records]}"
    )
    # No telemetry should have been recorded when usage was None.
    assert "threatlens" not in ctx.lens_usage


async def test_warns_when_all_usage_tokens_are_zero(monkeypatch, caplog, tmp_path):
    """If every token field is zero, the lens must log a WARNING.

    This catches the future-PydanticAI-rename failure mode where the
    attribute names shift and every `getattr(usage, ..., 0)` falls back
    to 0 silently.
    """
    zero_usage = SimpleNamespace(
        input_tokens=0,
        output_tokens=0,
        cache_read_tokens=0,
        cache_write_tokens=0,
    )
    fake_result = SimpleNamespace(usage=zero_usage)
    monkeypatch.setattr(
        "loupe_threatlens.lens.build_agent",
        lambda model_id: _FakeAgent(fake_result),
    )
    loupe_dir = tmp_path / ".loupe"
    loupe_dir.mkdir()
    lens = ThreatLens()
    ctx = _ctx()

    with caplog.at_level(logging.WARNING, logger="loupe_threatlens.lens"):
        await lens.run(ctx, _plan(), PathBoundary(writable_globs=[]), loupe_dir)

    warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("all token counts are zero" in r.message for r in warning_records), (
        f"expected an 'all token counts are zero' WARNING, "
        f"got: {[r.message for r in warning_records]}"
    )


async def test_no_warning_when_tokens_present(monkeypatch, caplog, tmp_path):
    """A healthy usage object with non-zero tokens must NOT trigger a warning."""
    good_usage = SimpleNamespace(
        input_tokens=100,
        output_tokens=50,
        cache_read_tokens=0,
        cache_write_tokens=0,
    )
    fake_result = SimpleNamespace(usage=good_usage)
    monkeypatch.setattr(
        "loupe_threatlens.lens.build_agent",
        lambda model_id: _FakeAgent(fake_result),
    )
    loupe_dir = tmp_path / ".loupe"
    loupe_dir.mkdir()
    lens = ThreatLens()
    ctx = _ctx()

    with caplog.at_level(logging.WARNING, logger="loupe_threatlens.lens"):
        await lens.run(ctx, _plan(), PathBoundary(writable_globs=[]), loupe_dir)

    warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert not warning_records, (
        f"unexpected WARNINGs on healthy telemetry: {[r.message for r in warning_records]}"
    )
    # Telemetry was recorded.
    assert "threatlens" in ctx.lens_usage
    assert ctx.lens_usage["threatlens"].input_tokens == 100
    assert ctx.lens_usage["threatlens"].output_tokens == 50
