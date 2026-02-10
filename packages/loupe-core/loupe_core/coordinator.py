from __future__ import annotations
from loupe_core.run_context import RunContext, LensRunPlan
from loupe_core.lens_api import Lens
from loupe_core.config import LoupeConfig


def build_run_plan(ctx: RunContext, lenses: list[Lens], config: LoupeConfig) -> list[LensRunPlan]:
    # 1. Relevance filter
    candidates: list[tuple[Lens, float]] = []
    for lens in lenses:
        name = lens.capabilities.name
        activation = config.lenses.get(name)
        if activation is None or not activation.enabled:
            continue
        score = lens.is_relevant(ctx)
        if score.score < activation.minimum_relevance:
            continue
        candidates.append((lens, score.score))

    if not candidates:
        return []

    # 2. Topological sort by requires_lenses
    ordered = _topo_sort(candidates)

    # 3. Build plans
    return [
        LensRunPlan(
            lens_name=lens.capabilities.name,
            relevance=lens.is_relevant(ctx),
            depends_on=list(lens.capabilities.requires_lenses),
            sub_prompt="",  # filled by PromptBuilder
        )
        for lens, _ in ordered
    ]


def _topo_sort(candidates: list[tuple[Lens, float]]) -> list[tuple[Lens, float]]:
    name_to_pair = {l.capabilities.name: (l, s) for l, s in candidates}
    visited: set[str] = set()
    result: list[tuple[Lens, float]] = []

    def visit(name: str) -> None:
        if name in visited or name not in name_to_pair:
            return
        visited.add(name)
        lens, _ = name_to_pair[name]
        for dep in lens.capabilities.requires_lenses:
            visit(dep)
        result.append(name_to_pair[name])

    for name in name_to_pair:
        visit(name)
    return result
