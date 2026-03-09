"""Phase 10.1 — cost regression fixture.

Locks in [principle §8 "Cost discipline"][1] with a deterministic test:
parse the recorded VCR cassette, sum the Anthropic API token counts,
fail if they regress past documented budgets.

The test runs without any network call and without an API key — it
inspects the on-disk cassette only. A growth in tokens here is a
prompt-cache regression, a prompt-bloat regression, or a sign that the
agent is generating more output than expected.

To consciously raise the budgets (e.g., after adding a new prompt
section), bump the numbers in this file in the SAME commit as the
prompt-builder change and add a CHANGELOG line under "Cost".

[1]: ../docs/principles.md#principle-8
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

CASSETTE_PATH = (
    Path(__file__).parent
    / "cassettes"
    / "test_threatlens_proposes_threats_on_diff.yaml"
)

# ---------------------------------------------------------------------------
# Budgets — bump only with deliberate evaluation per [principle §8]
# ---------------------------------------------------------------------------

# Recorded on 2026-05-15 against anthropic:claude-haiku-4-5:
#   interaction 0: 2959 input + 1083 output
#   interaction 1: 4169 input + 249 output
#   total: 7128 input, 1332 output
# Headroom: roughly 40% on input, 85% on output.
MAX_INPUT_TOKENS = 10_000
MAX_OUTPUT_TOKENS = 2_500

# Haiku 4.5 pricing as of 2026-05-15:
#   $0.80 per 1M input tokens, $4.00 per 1M output tokens.
# At the budget caps above: 10000 * 0.80 / 1e6 + 2500 * 4.00 / 1e6 = $0.018
HAIKU_INPUT_USD_PER_TOKEN = 0.80 / 1_000_000
HAIKU_OUTPUT_USD_PER_TOKEN = 4.00 / 1_000_000
MAX_COST_USD = 0.025  # leaves ~30% headroom above the strict token budget


def _load_usage_from_cassette() -> tuple[int, int]:
    """Return (total_input_tokens, total_output_tokens) summed across interactions."""
    if not CASSETTE_PATH.exists():
        pytest.skip(f"cassette missing at {CASSETTE_PATH}")
    data = yaml.safe_load(CASSETTE_PATH.read_text())
    total_in, total_out = 0, 0
    for interaction in data.get("interactions", []):
        body_str = interaction.get("response", {}).get("body", {}).get("string", "")
        try:
            body = json.loads(body_str)
        except (json.JSONDecodeError, TypeError):
            continue
        usage = body.get("usage") or {}
        total_in += int(usage.get("input_tokens", 0) or 0)
        total_in += int(usage.get("cache_creation_input_tokens", 0) or 0)
        # cache_read_input_tokens is intentionally NOT added — those are
        # the cached tokens we paid ~10% for; counting them at full price
        # would punish the very cache-friendly behaviour §8 mandates.
        total_out += int(usage.get("output_tokens", 0) or 0)
    return total_in, total_out


def test_recorded_cassette_input_tokens_under_budget():
    """Input-token regression check.

    If this fires, ask: did the system prompt grow? Did `build_user_prompt`
    start including more context? Is the stable prefix being rebuilt per
    call (defeating Anthropic prompt cache)?
    """
    total_in, _ = _load_usage_from_cassette()
    assert total_in < MAX_INPUT_TOKENS, (
        f"input-token budget regression: recorded {total_in}, "
        f"budget {MAX_INPUT_TOKENS}. To raise, bump MAX_INPUT_TOKENS in "
        f"this file and document the cause in CHANGELOG."
    )


def test_recorded_cassette_output_tokens_under_budget():
    """Output-token regression check.

    Output growth usually means the agent is being chatty in its final
    free-text summary, or the system prompt is asking for more
    `propose_threat` calls than it should.
    """
    _, total_out = _load_usage_from_cassette()
    assert total_out < MAX_OUTPUT_TOKENS, (
        f"output-token budget regression: recorded {total_out}, "
        f"budget {MAX_OUTPUT_TOKENS}."
    )


def test_recorded_cassette_estimated_cost_under_cap():
    """End-to-end USD cost cap (Haiku 4.5 pricing as of 2026-05-15)."""
    total_in, total_out = _load_usage_from_cassette()
    estimated_cost = (
        total_in * HAIKU_INPUT_USD_PER_TOKEN
        + total_out * HAIKU_OUTPUT_USD_PER_TOKEN
    )
    assert estimated_cost < MAX_COST_USD, (
        f"recorded scenario estimated cost ${estimated_cost:.4f} exceeds "
        f"cap ${MAX_COST_USD}. Either the prompt grew or Haiku pricing "
        f"changed — investigate before bumping the cap."
    )


def test_cassette_has_at_least_one_interaction():
    """Sanity check: an empty cassette would pass the budget tests trivially."""
    data = yaml.safe_load(CASSETTE_PATH.read_text())
    assert len(data.get("interactions", [])) >= 1, (
        "cassette is empty — recording may have failed"
    )


def test_cassette_carries_no_secret_strings():
    """Defence-in-depth check: filter_headers in conftest should have stripped any auth."""
    body = CASSETTE_PATH.read_text()
    for needle in ("sk-ant", "x-api-key", "authorization", "bearer "):
        assert needle.lower() not in body.lower(), (
            f"cassette appears to leak '{needle}' — verify conftest.py "
            f"filter_headers and re-record"
        )
