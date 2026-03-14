"""Provider/model token-cost lookup for run-record cost_usd_estimate.

Prices are denominated in USD per 1,000,000 tokens (the way every
provider's pricing page expresses them as of 2026-05-15). When a model
isn't in the table — a newer release, a self-hosted local model — we
return 0.0 rather than raise; the run record still has the token
counts and an external observer can re-cost later.

Cache rules (Anthropic prompt caching, the cost lever in [D-10]):
- Cache reads pay ~10% of the input rate
- Cache writes pay ~125% of the input rate (one-time)
- Plain `input_tokens` pay 100% of the input rate

The numbers below are reference points for v1; bump deliberately when
a model price moves or a new family lands. Treat regressions in this
table as out-of-band signals: pricing didn't change, our usage did.
"""
from __future__ import annotations

from loupe_core.run_context import LensUsage

# Per-million-token rates. Mapping: provider:model → (input_usd_per_mtok, output_usd_per_mtok).
_PRICING_PER_MILLION: dict[str, tuple[float, float]] = {
    # Anthropic Claude family (2026-05-15 pricing)
    "anthropic:claude-haiku-4-5": (0.80, 4.00),
    "anthropic:claude-sonnet-4-6": (3.00, 15.00),
    "anthropic:claude-opus-4-7": (15.00, 75.00),
    # OpenAI GPT-5 family
    "openai:gpt-5": (1.25, 10.00),
    "openai:gpt-5-mini": (0.25, 2.00),
    # Google Gemini 2.5
    "google-gla:gemini-2.5-pro": (1.25, 10.00),
    "google-gla:gemini-2.5-flash": (0.30, 2.50),
}

_CACHE_READ_DISCOUNT = 0.10   # cache reads pay 10% of the input rate
_CACHE_WRITE_PREMIUM = 1.25   # cache writes pay 125% of the input rate (one-time)


def estimate_cost_usd(usage: LensUsage) -> float:
    """Return the estimated cost in USD for the given LensUsage.

    Returns 0.0 when the model isn't in the pricing table — operators
    can recompute later by updating the table and reading the token
    counts off the run record.
    """
    rates = _PRICING_PER_MILLION.get(usage.model_id)
    if rates is None:
        return 0.0
    input_rate, output_rate = rates
    base_input_cost = (usage.input_tokens / 1_000_000) * input_rate
    cache_read_cost = (
        (usage.cache_read_tokens / 1_000_000) * input_rate * _CACHE_READ_DISCOUNT
    )
    cache_write_cost = (
        (usage.cache_write_tokens / 1_000_000) * input_rate * _CACHE_WRITE_PREMIUM
    )
    output_cost = (usage.output_tokens / 1_000_000) * output_rate
    return round(
        base_input_cost + cache_read_cost + cache_write_cost + output_cost,
        6,  # microdollars — finer than any pricing page, enough for budgets
    )


def cache_hit_rate(usage: LensUsage) -> float | None:
    """Return cache hit rate in [0.0, 1.0], or None when there's no data to divide.

    Defined as: cache_read_tokens / (input_tokens + cache_read_tokens + cache_write_tokens).
    Higher = more of the prompt was reused from cache, which is the
    cost-discipline lever [principle §8] tracks.
    """
    denominator = usage.input_tokens + usage.cache_read_tokens + usage.cache_write_tokens
    if denominator == 0:
        return None
    return round(usage.cache_read_tokens / denominator, 4)
