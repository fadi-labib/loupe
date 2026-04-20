"""Tests for the per-model cost lookup and cache_hit_rate helpers."""

from __future__ import annotations

import pytest
from loupe_core.pricing import cache_hit_rate, estimate_cost_usd
from loupe_core.run_context import LensUsage

# ---------------------------------------------------------------------------
# estimate_cost_usd
# ---------------------------------------------------------------------------


def test_unknown_model_returns_zero():
    """Unknown models cost 0.0 so the run record still serialises; operators
    can re-cost externally once the pricing table is updated."""
    usage = LensUsage(
        model_id="some:future-model-9000",
        input_tokens=10_000,
        output_tokens=1_000,
    )
    assert estimate_cost_usd(usage) == 0.0


def test_haiku_simple_run_pricing():
    """1M input + 0 output at Haiku rate = $0.80."""
    usage = LensUsage(
        model_id="anthropic:claude-haiku-4-5",
        input_tokens=1_000_000,
    )
    assert estimate_cost_usd(usage) == 0.80


def test_haiku_mixed_input_output():
    """100k input + 50k output at Haiku: 0.08 + 0.20 = 0.28."""
    usage = LensUsage(
        model_id="anthropic:claude-haiku-4-5",
        input_tokens=100_000,
        output_tokens=50_000,
    )
    cost = estimate_cost_usd(usage)
    assert cost == pytest.approx(0.28, abs=1e-6)


def test_cache_reads_at_ten_percent():
    """Cache reads cost ~10% of the input rate.

    100k cache_read at $0.80/Mtok normally = $0.08; at 10% = $0.008.
    """
    usage = LensUsage(
        model_id="anthropic:claude-haiku-4-5",
        input_tokens=0,
        cache_read_tokens=100_000,
    )
    cost = estimate_cost_usd(usage)
    assert cost == pytest.approx(0.008, abs=1e-6)


def test_cache_writes_at_premium():
    """Cache writes cost 125% of the input rate (one-time penalty).

    100k cache_write at $0.80/Mtok normally = $0.08; at 125% = $0.10.
    """
    usage = LensUsage(
        model_id="anthropic:claude-haiku-4-5",
        input_tokens=0,
        cache_write_tokens=100_000,
    )
    cost = estimate_cost_usd(usage)
    assert cost == pytest.approx(0.10, abs=1e-6)


def test_opus_pricing_reflects_higher_tier():
    """Opus is roughly 18× Haiku on input. 100k input = $1.50."""
    usage = LensUsage(
        model_id="anthropic:claude-opus-4-7",
        input_tokens=100_000,
    )
    cost = estimate_cost_usd(usage)
    assert cost == pytest.approx(1.50, abs=1e-6)


def test_combined_costs_sum_correctly():
    """All four token categories combine additively."""
    usage = LensUsage(
        model_id="anthropic:claude-haiku-4-5",
        input_tokens=100_000,  # 0.080
        output_tokens=50_000,  # 0.200
        cache_read_tokens=200_000,  # 0.016 (10% of 0.16)
        cache_write_tokens=80_000,  # 0.080 (125% of 0.064)
    )
    cost = estimate_cost_usd(usage)
    assert cost == pytest.approx(0.080 + 0.200 + 0.016 + 0.080, abs=1e-6)


# ---------------------------------------------------------------------------
# cache_hit_rate
# ---------------------------------------------------------------------------


def test_cache_hit_rate_none_when_no_tokens():
    """No LLM call → None (distinct from 0.0 which means "had calls, no cache hits")."""
    usage = LensUsage(model_id="anthropic:claude-haiku-4-5")
    assert cache_hit_rate(usage) is None


def test_cache_hit_rate_zero_when_no_reads():
    usage = LensUsage(
        model_id="anthropic:claude-haiku-4-5",
        input_tokens=10_000,
    )
    assert cache_hit_rate(usage) == 0.0


def test_cache_hit_rate_full_reuse():
    """All input came from cache → rate is 1.0."""
    usage = LensUsage(
        model_id="anthropic:claude-haiku-4-5",
        cache_read_tokens=10_000,
    )
    assert cache_hit_rate(usage) == 1.0


def test_cache_hit_rate_proportional():
    """7k cached reads + 3k new = 70% hit rate."""
    usage = LensUsage(
        model_id="anthropic:claude-haiku-4-5",
        input_tokens=3_000,
        cache_read_tokens=7_000,
    )
    assert cache_hit_rate(usage) == 0.7


def test_cache_hit_rate_accounts_for_writes_in_denominator():
    """Writes count toward "total input observed"; only reads count as hits."""
    usage = LensUsage(
        model_id="anthropic:claude-haiku-4-5",
        input_tokens=2_000,
        cache_read_tokens=5_000,
        cache_write_tokens=3_000,
    )
    # 5000 / (2000 + 5000 + 3000) = 0.5
    assert cache_hit_rate(usage) == 0.5
