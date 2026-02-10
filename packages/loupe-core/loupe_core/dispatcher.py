from __future__ import annotations
from pathlib import Path
from loupe_core.run_context import RunContext
from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.lens_api import Lens


async def dispatch_plan(
    ctx: RunContext,
    lenses: list[Lens],
    boundary: PathBoundary,
    loupe_dir: Path,
) -> None:
    """Run every lens in ctx.plan in order.

    Each lens must implement `async def run(self, ctx, plan_entry, boundary, loupe_dir)`.
    Lenses are looked up by name from the provided list.
    """
    by_name = {l.capabilities.name: l for l in lenses}
    for plan_entry in ctx.plan:
        lens = by_name[plan_entry.lens_name]
        await lens.run(ctx, plan_entry, boundary, loupe_dir)
