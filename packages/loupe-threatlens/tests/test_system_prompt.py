"""Regression test for load-bearing safety rules in ThreatLens's system prompt.

`loupe_threatlens/prompts/system.md` carries the rules that constrain the
agent's behaviour. A silent edit that drops one (a refactor, a "tighten the
wording" sweep, an LLM-assisted prompt rewrite) would not be caught by any
of the other tests — none of them assert on prompt CONTENT.

This test pins specific verbatim substrings from the prompt. Updating the
prompt is fine; the test then forces an explicit decision: either the rule
is still there (verbatim or paraphrased — update the substring), or the
rule has been intentionally retired (remove it from the list).

Source of truth: `prompts/system.md` `## Hard rules` and `## What you must NOT do`.
"""

from __future__ import annotations

from pathlib import Path

_SYSTEM_PROMPT = Path(__file__).parent.parent / "loupe_threatlens" / "prompts" / "system.md"


def test_system_prompt_contains_key_safety_rules():
    """If any of these load-bearing rules disappear, fail loudly.

    Pre-flight rule changes against this list; if a rule is intentionally
    retired, remove the corresponding substring with the same commit.
    """
    text = _SYSTEM_PROMPT.read_text()
    required_substrings = [
        # Hard rule 1: anchoring to the project's authoritative context.md.
        "Do not invent assets",
        # Hard rule 2: severity must be tied to the project's own assets,
        # not generic web heuristics.
        "Severity is relative to *this* project's assets",
        # Hard rule 3: no speculation outside the inputs.
        "Do not propose threats that aren't supported by the inputs",
        # Hard rule 4: avoid re-proposing existing threats.
        "Do not duplicate existing threats",
        # Hard rule 5: one threat per call (granular audit trail).
        "One threat per `propose_threat` call",
        # NOT-rule: the agent must never edit human-owned context.md.
        "Modify `context.md`",
    ]
    missing = [s for s in required_substrings if s not in text]
    assert not missing, (
        f"system.md is missing load-bearing safety rules: {missing}. "
        "If a rule was intentionally retired, remove the substring from this "
        "test's required list in the SAME commit that removes the rule."
    )


def test_system_prompt_has_hard_rules_section():
    """The `## Hard rules` section header is itself load-bearing — it's what
    auditors grep for when reviewing the prompt's safety posture.
    """
    text = _SYSTEM_PROMPT.read_text()
    assert "## Hard rules" in text, "system.md must retain a `## Hard rules` section header"
