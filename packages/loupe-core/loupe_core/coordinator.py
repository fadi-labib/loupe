from __future__ import annotations

from loupe_core.config import LoupeConfig
from loupe_core.lens_api import Lens
from loupe_core.run_context import LensRunPlan, RelevanceScore, RunContext


def build_run_plan(ctx: RunContext, lenses: list[Lens], config: LoupeConfig) -> list[LensRunPlan]:
    """Build the per-invocation run plan.

    Properties:
    1. is_relevant() is called at most once per lens per build_run_plan call
       (it may become LLM-backed in the future — see D-10 lever 3 in DESIGN-DECISIONS.md).
    2. A lens with `requires_lenses=[X]` is included only if X is also in the
       resulting plan. Dependent lenses with unmet dependencies are dropped.
    3. The plan respects topological order: dependencies precede dependents.
    """
    # 1. Score every lens once
    scores: dict[str, tuple[Lens, RelevanceScore]] = {}
    for lens in lenses:
        name = lens.capabilities.name
        activation = config.lenses.get(name)
        if activation is None or not activation.enabled:
            continue
        score = lens.is_relevant(ctx)
        scores[name] = (lens, score)

    # 2. Filter by relevance threshold
    selected: dict[str, tuple[Lens, RelevanceScore]] = {}
    for name, (lens, score) in scores.items():
        activation = config.lenses[name]
        if score.score >= activation.minimum_relevance:
            selected[name] = (lens, score)

    if not selected:
        return []

    # 3. Drop lenses whose dependencies aren't in the selected set
    selected = _drop_unmet_dependents(selected)
    if not selected:
        return []

    # 4. Topological sort
    ordered = _topo_sort(selected)

    # 5. Build plan entries using cached scores (no second is_relevant() call)
    return [
        LensRunPlan(
            lens_name=lens.capabilities.name,
            relevance=score,
            depends_on=list(lens.capabilities.requires_lenses),
            sub_prompt="",  # filled by PromptBuilder
        )
        for lens, score in ordered
    ]


def _drop_unmet_dependents(
    selected: dict[str, tuple[Lens, RelevanceScore]],
) -> dict[str, tuple[Lens, RelevanceScore]]:
    """Iteratively remove any lens whose `requires_lenses` are not all in the set.

    Iteration is needed because removing A may cascade — if B depended on A,
    B must now be removed too.
    """
    changed = True
    while changed:
        changed = False
        for name, (lens, _) in list(selected.items()):
            for dep in lens.capabilities.requires_lenses:
                if dep not in selected:
                    selected.pop(name)
                    changed = True
                    break
    return selected


def _topo_sort(
    selected: dict[str, tuple[Lens, RelevanceScore]],
) -> list[tuple[Lens, RelevanceScore]]:
    visited: set[str] = set()
    result: list[tuple[Lens, RelevanceScore]] = []

    def visit(name: str) -> None:
        if name in visited or name not in selected:
            return
        visited.add(name)
        lens, _ = selected[name]
        for dep in lens.capabilities.requires_lenses:
            visit(dep)
        result.append(selected[name])

    for name in selected:
        visit(name)
    return result
