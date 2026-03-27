from datetime import datetime

import pytest
from loupe_core.config import LensActivation, LoupeConfig
from loupe_core.coordinator import build_run_plan
from loupe_core.lens_api import LensCapabilities
from loupe_core.run_context import CodeDiff, RelevanceScore, RunContext


def _ctx(paths: list[str]) -> RunContext:
    return RunContext(
        run_id="r", mode="ci", started_at=datetime(2026, 5, 13),
        user_intent="",
        diff=CodeDiff(
            base_sha="a", head_sha="b", changed_paths=paths,
            added_lines=1, removed_lines=0, raw_unified="",
        ),
        sbom_delta=None, project=None, plan=[], knowledge=None,
    )


class _MakeLens:
    def __init__(self, name: str, score: float, depends_on: list[str] | None = None):
        self.capabilities = LensCapabilities(
            name=name, domain="x",
            artifact_paths=[f".loupe/{name}.yaml"],
            requires_lenses=depends_on or [],
        )
        self._score = score

    def build_agent(self, t): return None
    def mcp_tools(self): return []
    def mcp_workflows(self): return []
    def is_relevant(self, c): return RelevanceScore(score=self._score, reason="t")
    async def run(self, ctx, p, b, d): return None


def _cfg(lenses: dict[str, float]) -> LoupeConfig:
    return LoupeConfig(
        lenses={n: LensActivation(enabled=True, minimum_relevance=t) for n, t in lenses.items()}
    )


def test_includes_only_relevant_lenses():
    ctx = _ctx(["x.py"])
    lenses = [_MakeLens("a", 0.9), _MakeLens("b", 0.1)]
    cfg = _cfg({"a": 0.3, "b": 0.3})
    plan = build_run_plan(ctx, lenses, cfg)
    assert [p.lens_name for p in plan] == ["a"]


def test_topological_order_with_dependency():
    ctx = _ctx(["x.py"])
    lens_a = _MakeLens("a", 0.9, depends_on=["b"])
    lens_b = _MakeLens("b", 0.9)
    cfg = _cfg({"a": 0.3, "b": 0.3})
    plan = build_run_plan(ctx, [lens_a, lens_b], cfg)
    assert [p.lens_name for p in plan] == ["b", "a"]


def test_empty_plan_when_no_lens_relevant():
    ctx = _ctx([])
    lenses = [_MakeLens("a", 0.05)]
    cfg = _cfg({"a": 0.3})
    plan = build_run_plan(ctx, lenses, cfg)
    assert plan == []


def test_dependent_lens_dropped_if_dependency_not_in_plan():
    """If lens A requires B but B is below threshold or disabled, A must also be dropped.

    Running a dependent lens without its declared predecessor would silently
    violate the contract — the dependent lens expects findings from the
    predecessor that won't exist.
    """
    ctx = _ctx(["x.py"])
    lens_a = _MakeLens("a", 0.9, depends_on=["b"])
    lens_b = _MakeLens("b", 0.1)  # below threshold
    cfg = _cfg({"a": 0.3, "b": 0.3})
    plan = build_run_plan(ctx, [lens_a, lens_b], cfg)
    assert plan == [], "Expected empty plan: A requires B, but B is below threshold"


def test_dependent_lens_dropped_if_dependency_disabled():
    ctx = _ctx(["x.py"])
    lens_a = _MakeLens("a", 0.9, depends_on=["b"])
    lens_b = _MakeLens("b", 0.9)
    cfg = LoupeConfig(
        lenses={
            "a": LensActivation(enabled=True, minimum_relevance=0.3),
            "b": LensActivation(enabled=False, minimum_relevance=0.3),
        }
    )
    plan = build_run_plan(ctx, [lens_a, lens_b], cfg)
    assert plan == [], "Expected empty plan: A requires B, but B is disabled"


def test_coordinator_rejects_dependency_cycle():
    """Two lenses each declaring depends_on the other must raise a descriptive
    error, not silently produce a plan that violates ordering or deadlock.

    The cycle is detectable at plan-build time; the coordinator must refuse
    to schedule rather than running lenses in an order that violates a
    declared `requires_lenses` edge.
    """
    ctx = _ctx(["x.py"])
    lens_a = _MakeLens("a", 0.9, depends_on=["b"])
    lens_b = _MakeLens("b", 0.9, depends_on=["a"])
    cfg = _cfg({"a": 0.3, "b": 0.3})
    with pytest.raises(ValueError, match="cycle"):
        build_run_plan(ctx, [lens_a, lens_b], cfg)


def test_coordinator_rejects_self_dependency_cycle():
    """A lens depending on itself is a degenerate cycle and must also be rejected."""
    ctx = _ctx(["x.py"])
    lens_a = _MakeLens("a", 0.9, depends_on=["a"])
    cfg = _cfg({"a": 0.3})
    with pytest.raises(ValueError, match="cycle"):
        build_run_plan(ctx, [lens_a], cfg)


def test_is_relevant_called_once_per_lens():
    """Avoid double-billing for relevance checks (matters when relevance becomes LLM-backed)."""
    call_counts: dict[str, int] = {}

    class _CountingLens:
        def __init__(self, name: str, score: float):
            self.capabilities = LensCapabilities(
                name=name, domain="x",
                artifact_paths=[f".loupe/{name}.yaml"],
            )
            self._score = score
            call_counts[name] = 0

        def build_agent(self, t): return None
        def mcp_tools(self): return []
        def mcp_workflows(self): return []
        def is_relevant(self, c):
            call_counts[self.capabilities.name] += 1
            return RelevanceScore(score=self._score, reason="t")
        async def run(self, ctx, p, b, d): return None

    ctx = _ctx(["x.py"])
    lenses = [_CountingLens("a", 0.9), _CountingLens("b", 0.9)]
    cfg = _cfg({"a": 0.3, "b": 0.3})
    build_run_plan(ctx, lenses, cfg)
    assert call_counts == {"a": 1, "b": 1}, (
        f"is_relevant should be called once per lens, got {call_counts}"
    )
