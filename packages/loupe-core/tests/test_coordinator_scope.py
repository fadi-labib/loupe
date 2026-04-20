"""Tests for the scope-aware behaviour of build_run_plan (D-15).

In diff mode (default), the coordinator filters lenses by is_relevant() score
against the per-lens minimum_relevance threshold.

In scan / scoped mode, the user has explicitly invoked the lens — the
coordinator must NOT suppress it via relevance filtering. The lens's
is_relevant() is still called for the reason string in the run record,
but the score is overridden.
"""

from datetime import datetime

from loupe_core.config import LensActivation, LoupeConfig
from loupe_core.coordinator import build_run_plan
from loupe_core.lens_api import LensCapabilities
from loupe_core.run_context import CodeDiff, RelevanceScore, RunContext


class _MakeLens:
    def __init__(self, name: str, score: float):
        self.capabilities = LensCapabilities(
            name=name,
            domain="x",
            artifact_paths=[f".loupe/{name}.yaml"],
        )
        self._score = score

    def build_agent(self, t):
        return None

    def mcp_tools(self):
        return []

    def mcp_workflows(self):
        return []

    def is_relevant(self, c):
        return RelevanceScore(score=self._score, reason="t")

    async def run(self, ctx, p, b, d):
        return None


def _ctx(scope: str = "diff", diff_paths=None) -> RunContext:
    diff = None
    if diff_paths is not None:
        diff = CodeDiff(
            base_sha="a",
            head_sha="b",
            changed_paths=diff_paths,
            added_lines=1,
            removed_lines=0,
            raw_unified="",
        )
    return RunContext(
        run_id="r",
        mode="ci",
        started_at=datetime(2026, 5, 14),
        user_intent="",
        diff=diff,
        sbom_delta=None,
        project=None,
        plan=[],
        knowledge=None,
        scope=scope,
    )


def _cfg(threshold: float) -> LoupeConfig:
    return LoupeConfig(
        lenses={"a": LensActivation(enabled=True, minimum_relevance=threshold)},
    )


def test_diff_mode_filters_by_relevance():
    """Baseline: in diff mode a low-relevance lens is still skipped."""
    ctx = _ctx(scope="diff", diff_paths=["doc.md"])
    lens = _MakeLens("a", 0.05)
    plan = build_run_plan(ctx, [lens], _cfg(0.3))
    assert plan == []


def test_full_scope_overrides_relevance_filter():
    """scope=full means user explicitly invoked the lens — include it
    regardless of is_relevant() score."""
    ctx = _ctx(scope="full")  # no diff, no paths to score against
    lens = _MakeLens("a", 0.01)  # would normally be filtered
    plan = build_run_plan(ctx, [lens], _cfg(0.3))
    assert len(plan) == 1
    assert plan[0].lens_name == "a"


def test_scoped_mode_overrides_relevance_filter():
    """scope=scoped (specific paths) also bypasses relevance filtering."""
    ctx = _ctx(scope="scoped")
    lens = _MakeLens("a", 0.0)
    plan = build_run_plan(ctx, [lens], _cfg(0.3))
    assert len(plan) == 1


def test_disabled_lens_still_skipped_in_scan_mode():
    """Explicit enable=False in config still wins over scope.

    The user opted out of this lens at config time. Scan mode doesn't
    override config-level disabling.
    """
    ctx = _ctx(scope="full")
    lens = _MakeLens("a", 0.99)
    cfg = LoupeConfig(
        lenses={"a": LensActivation(enabled=False, minimum_relevance=0.0)},
    )
    plan = build_run_plan(ctx, [lens], cfg)
    assert plan == []


def test_relevance_reason_preserved_in_scan_mode():
    """Even when relevance score is overridden by scope, the lens's reason
    string must end up in the plan entry — auditors will want to see it."""
    ctx = _ctx(scope="full")
    lens = _MakeLens("a", 0.0)
    plan = build_run_plan(ctx, [lens], _cfg(0.3))
    assert len(plan) == 1
    # Reason should be a non-empty string from the lens
    assert plan[0].relevance.reason != ""
