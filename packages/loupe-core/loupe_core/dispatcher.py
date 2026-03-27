from __future__ import annotations

import logging
import traceback
from pathlib import Path

from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.lens_api import Lens
from loupe_core.run_context import RunContext

_LOG = logging.getLogger(__name__)


async def dispatch_plan(
    ctx: RunContext,
    lenses: list[Lens],
    boundary: PathBoundary,
    loupe_dir: Path,
) -> None:
    """Run every lens in ctx.plan in order.

    Each lens must implement `async def run(self, ctx, plan_entry, boundary, loupe_dir)`.
    Lenses are looked up by name from the provided list.

    Error isolation: a single lens raising in `run()` must not abort sibling
    lenses. The exception is logged, the failure is recorded on
    `ctx.findings[<lens_name>]['lens_error']` (so the run record retains
    visibility), and the loop continues to the next plan entry.
    """
    by_name = {lens.capabilities.name: lens for lens in lenses}
    for plan_entry in ctx.plan:
        lens = by_name[plan_entry.lens_name]
        try:
            await lens.run(ctx, plan_entry, boundary, loupe_dir)
        except Exception as exc:  # noqa: BLE001 — deliberate broad catch for isolation
            _LOG.exception("Lens %r raised; continuing with remaining lenses.", plan_entry.lens_name)
            ctx.record_finding(
                plan_entry.lens_name,
                "lens_error",
                {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
            )
