---
tags:
  - reference
  - pricing
---

# Pricing

`packages/loupe-core/loupe_core/pricing.py` is the single source of truth for token-cost estimation. Its job is to convert the token counts a lens reports for one model call into a USD figure that `RunRecord.cost_usd_estimate` can record. The point of recording it is auditability: every run lands with the model id and the per-modality token counts attached, so an external observer can re-cost later if a pricing page moves.

## What it covers

- LLM token costs for the seven model ids in the pricing table.
- The Anthropic prompt-caching cost model: cache reads pay 10 % of the input rate, cache writes pay 125 % of the input rate. See [D-10](decisions.md#d-10) for why prompt caching is the headline cost lever.

## What it does not cover

- Subprocess time: `syft`, `grype`, `osv-scanner`, `git`. Those are CPU time on the runner, not LLM tokens. The runner pays for them; Loupe does not estimate them.
- Storage and bandwidth. Loupe writes a few KB per run; not worth modelling.
- Self-hosted local models (Ollama, llama.cpp). The function returns `0.0` when the model id is not in the table, which is the right answer for a model that does not cost dollars per token.

## The price table

The table is denominated in USD per 1,000,000 tokens, the way every provider's pricing page expresses rates as of 2026-05-15.

```python title="loupe_core/pricing.py — price table"
--8<-- "packages/loupe-core/loupe_core/pricing.py:price_table"
```

Seven model ids ship in v1: three from Anthropic, two from OpenAI, two from Google. The mapping key follows the `provider:model` convention PydanticAI uses everywhere else, so the same string flows from `config.yaml` through `LensUsage.model_id` into the pricing lookup unchanged.

When a model id is not in the table, `estimate_cost_usd` returns `0.0`. This is a soft miss, not an error. The `RunRecord` still has the token counts attached, and an operator who notices the zero can either add the missing model to the table or re-cost externally.

## Helpers

### estimate_cost_usd

::: loupe_core.pricing.estimate_cost_usd

The function reads `model_id`, `input_tokens`, `output_tokens`, `cache_read_tokens`, and `cache_write_tokens` off a `LensUsage` instance and returns the summed cost rounded to six decimal places. Six places is finer than any pricing page expresses rates, but it preserves enough precision that summing many small calls does not accrue rounding error against the per-run budget.

### cache_hit_rate

::: loupe_core.pricing.cache_hit_rate

Cache hit rate is reported alongside cost on every `RunRecord` so a reviewer can tell at a glance whether prompt caching is doing its job. The denominator is the total tokens that passed through the prompt-cache region (input + cache reads + cache writes); a high ratio means most of the prompt was reused, which is exactly what the cost-discipline lever in [principles.md § Cost discipline](../principles.md) tracks.

When there is nothing to divide (a run that ran zero LLM calls, or a model that does not support prompt caching) the function returns `None`. Downstream consumers treat `None` as "not applicable" rather than coercing to zero.

## How to add a model

1. Look up the per-million input and output rates on the provider's current pricing page.
2. Add one line to `_PRICING_PER_MILLION` in `pricing.py`. The key is `provider:model`; the value is `(input_rate, output_rate)`.
3. Ship a CHANGELOG entry under "Added" calling out the new model id and the date the rates were captured.
4. No schema change is needed. `model_id` is a free-form string everywhere in the artefacts, and an unknown id simply falls back to `0.0` until the table catches up.

The table is small and the surface area is narrow on purpose: pricing data drifts, and the cost of getting one number wrong is a small accounting error on one `RunRecord`, not a correctness bug.

## See also

- [`reference/schemas/run-record.md`](schemas/run-record.md) — where `cost_usd_estimate` lives.
- [`reference/decisions.md#d-10`](decisions.md#d-10) — the three cost levers, with prompt caching as the headline.
- [`principles.md`](../principles.md) — Principle 8, cost discipline.
