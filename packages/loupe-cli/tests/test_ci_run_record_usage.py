"""Tests for the run-record token/cost aggregation in `_write_run_record`.

The CLI's `_write_run_record` walks `ctx.lens_usage` and aggregates the
per-lens token counts into the workspace-level RunRecord fields. We
test the aggregation directly with a hand-built RunContext rather than
going end-to-end through `loupe ci` — that path has its own fixture in
test_ci_real.py and would over-couple to the dispatcher.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from loupe_core.artifacts.run_record import load_run_records
from loupe_core.config import LoupeConfig
from loupe_core.run_context import LensUsage, RunContext


def _ctx_with_usage(loupe_dir: Path, usages: dict[str, LensUsage]) -> RunContext:
    ctx = RunContext(
        run_id="run-test", mode="ci", started_at=datetime(2026, 5, 15, 10, 0, tzinfo=UTC),
        user_intent="aggregation test",
        diff=None, sbom_delta=None,
        project=None, plan=[], knowledge=None,
    )
    for lens_name, usage in usages.items():
        ctx.lens_usage[lens_name] = usage
    # Need context.md present for hash; create a stub.
    (loupe_dir / "context.md").write_text("# context")
    return ctx


@pytest.fixture
def loupe_dir(tmp_path: Path) -> Path:
    d = tmp_path / ".loupe"
    d.mkdir()
    (d / "runs").mkdir()
    return d


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def test_single_lens_usage_aggregates_to_run_record(loupe_dir: Path):
    from loupe_cli.ci_cmd import _write_run_record

    ctx = _ctx_with_usage(loupe_dir, {
        "threatlens": LensUsage(
            model_id="anthropic:claude-haiku-4-5",
            input_tokens=3000, output_tokens=500,
            cache_read_tokens=200, cache_write_tokens=100,
            cost_usd_estimate=0.0042,
        ),
    })
    _write_run_record(ctx, loupe_dir, considered=[], cfg=LoupeConfig())

    record = load_run_records(loupe_dir / "runs")[0]
    assert record.models_used == {"threatlens": "anthropic:claude-haiku-4-5"}
    # total_tokens_in = input + cache_read + cache_write
    assert record.total_tokens_in == 3000 + 200 + 100
    assert record.total_tokens_out == 500
    # cache_hit_rate = cache_read / (input + cache_read + cache_write)
    assert record.cache_hit_rate == round(200 / 3300, 4)
    assert record.cost_usd_estimate == pytest.approx(0.0042, abs=1e-6)


def test_multiple_lens_usage_sums(loupe_dir: Path):
    from loupe_cli.ci_cmd import _write_run_record

    ctx = _ctx_with_usage(loupe_dir, {
        "threatlens": LensUsage(
            model_id="anthropic:claude-haiku-4-5",
            input_tokens=1000, output_tokens=200,
            cost_usd_estimate=0.0016,
        ),
        "futurelens": LensUsage(
            model_id="anthropic:claude-opus-4-7",
            input_tokens=500, output_tokens=100,
            cost_usd_estimate=0.0150,
        ),
    })
    _write_run_record(ctx, loupe_dir, considered=[], cfg=LoupeConfig())

    record = load_run_records(loupe_dir / "runs")[0]
    assert record.models_used == {
        "threatlens": "anthropic:claude-haiku-4-5",
        "futurelens": "anthropic:claude-opus-4-7",
    }
    assert record.total_tokens_in == 1500
    assert record.total_tokens_out == 300
    assert record.cost_usd_estimate == pytest.approx(0.0166, abs=1e-6)


def test_no_lens_usage_writes_zero_and_none(loupe_dir: Path):
    """When no lens ran (or no LLM calls happened), totals are 0 and cache_hit_rate is None."""
    from loupe_cli.ci_cmd import _write_run_record

    ctx = _ctx_with_usage(loupe_dir, {})
    _write_run_record(ctx, loupe_dir, considered=[], cfg=LoupeConfig())

    record = load_run_records(loupe_dir / "runs")[0]
    assert record.models_used == {}
    assert record.total_tokens_in == 0
    assert record.total_tokens_out == 0
    assert record.cost_usd_estimate == 0.0
    # None distinguishes "no LLM call happened" from "all cache misses" (which would be 0.0).
    assert record.cache_hit_rate is None


def test_cache_hit_rate_distinguishes_zero_from_none(loupe_dir: Path):
    """A lens that ran but had no cache hits → 0.0 (not None)."""
    from loupe_cli.ci_cmd import _write_run_record

    ctx = _ctx_with_usage(loupe_dir, {
        "threatlens": LensUsage(
            model_id="anthropic:claude-haiku-4-5",
            input_tokens=1000, output_tokens=200,
            cache_read_tokens=0,  # no cache hits
            cache_write_tokens=0,
            cost_usd_estimate=0.0016,
        ),
    })
    _write_run_record(ctx, loupe_dir, considered=[], cfg=LoupeConfig())

    record = load_run_records(loupe_dir / "runs")[0]
    assert record.cache_hit_rate == 0.0
