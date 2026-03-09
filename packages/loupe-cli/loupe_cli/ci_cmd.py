"""`loupe ci` — non-interactive run, mode='ci', on a unified diff.

End-to-end:
1. Verify .loupe/ exists (else point user at `loupe init`)
2. Load config.yaml; build PathBoundary from agent_writable_paths
3. Discover lenses via entry points (loupe-core's lens_registry)
4. Bootstrap RunContext from the diff + context.md + knowledge.yaml
5. Build the run plan (relevance filter + topo sort + dep validity)
6. If plan is empty: log + exit 0 (this is a normal outcome, not a failure)
7. Bootstrap capabilities (SBOM, CVE, secret-detect, static-analysis) once
   per run, populating typed slots on ctx for every lens to read.
8. Dispatch lenses in order; each lens's tools enforce Layer 1.
9. Write runs/<id>.json with the hash chain.
10. Exit with the gate-determined status (currently always 0; gate logic
    per config.yaml's ci.fail_on will be wired in a follow-up).
"""
from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import UTC, datetime
from pathlib import Path

import typer
from loupe_core.artifacts.run_record import (
    LensConsidered,
    RunRecord,
    load_run_records,
    save_run_record,
)
from loupe_core.capabilities.bootstrap import bootstrap_capabilities
from loupe_core.capabilities.errors import CapabilityError
from loupe_core.capabilities.registry import CapabilityRegistry
from loupe_core.config import LoupeConfig, load_config
from loupe_core.coordinator import build_run_plan
from loupe_core.dispatcher import dispatch_plan
from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.lens_api import Lens
from loupe_core.lens_registry import discover_lenses
from loupe_core.run_context import BootstrapInputs, RunContext


def ci_command(
    diff: str,
    base_sha: str | None,
    head_sha: str | None,
    config_path: Path,
) -> int:
    cwd = Path.cwd()
    loupe = cwd / ".loupe"
    if not loupe.exists():
        typer.echo(
            "Error: .loupe/ not found in the current directory.\n"
            "Run `loupe init` first.",
            err=True,
        )
        return 2

    cfg = load_config(config_path)
    boundary = PathBoundary(writable_globs=cfg.agent_writable_paths)
    lenses = discover_lenses()

    started_at = datetime.now(UTC).replace(tzinfo=None)
    run_id = f"run-{uuid.uuid4().hex[:8]}"

    ctx = RunContext.bootstrap(BootstrapInputs(
        run_id=run_id,
        mode="ci",
        started_at=started_at,
        user_intent="ci diff analysis",
        loupe_dir=loupe,
        unified_diff=diff,
        base_sha=base_sha,
        head_sha=head_sha,
    ))
    ctx.plan = build_run_plan(ctx, lenses, cfg)

    if not ctx.plan:
        typer.echo("No relevant lens for this diff. Exiting clean.")
        _write_run_record(ctx, loupe, considered=lenses, cfg=cfg)
        return 0

    # Run the SBOM / CVE / secret / static capabilities ONCE before any
    # lens executes. The typed results land on ctx.sbom, ctx.cve_findings,
    # ctx.secrets, ctx.static_findings — every lens reads the same cached
    # values off the shared blackboard. Cost-discipline lever (D-10 §2).
    planned_lenses = _planned_lenses(lenses, ctx)
    if any(getattr(l.capabilities, "requires_capabilities", []) for l in planned_lenses):
        registry = CapabilityRegistry.discover()
        try:
            asyncio.run(bootstrap_capabilities(
                ctx=ctx,
                lenses=planned_lenses,
                config=cfg,
                registry=registry,
                repo_path=cwd,
            ))
        except CapabilityError as exc:
            # Surface the specific capability error so the operator can
            # fix config.yaml or install the missing backend, then continue
            # with whatever capability slots got populated. The lens layer
            # treats `None`-valued slots as "capability did not run" and
            # carries on rather than failing the whole CI invocation.
            typer.echo(
                f"warning: capability bootstrap failed — {exc}. "
                f"Lenses will see partial capability results.",
                err=True,
            )

    asyncio.run(dispatch_plan(ctx, lenses, boundary, loupe))
    _write_run_record(ctx, loupe, considered=lenses, cfg=cfg)

    typer.echo(f"Loupe CI complete. Run: {run_id}.")
    typer.echo(f"Lenses run: {[p.lens_name for p in ctx.plan]}")
    return 0


def _planned_lenses(lenses: list[Lens], ctx: RunContext) -> list[Lens]:
    """Filter discovered lenses to those actually in the run plan.

    The capability bootstrap should only run for lenses that will execute —
    a docs-only PR with no relevant lens shouldn't trigger Syft + Grype.
    """
    planned_names = {p.lens_name for p in ctx.plan}
    return [l for l in lenses if l.capabilities.name in planned_names]


def _write_run_record(
    ctx: RunContext,
    loupe_dir: Path,
    *,
    considered: list[Lens],
    cfg: LoupeConfig,
) -> None:
    """Write runs/<id>.json with hash chain pointer.

    Calls is_relevant() once per considered lens (cached locally) — must NOT
    introduce the double-call regression we fixed in the coordinator.
    """
    runs_dir = loupe_dir / "runs"
    existing = load_run_records(runs_dir)
    prev_hash = existing[-1].self_hash if existing else None

    diff_bytes = (ctx.diff.raw_unified if ctx.diff else "").encode()
    context_bytes = (loupe_dir / "context.md").read_bytes()

    considered_records: list[LensConsidered] = []
    for lens in considered:
        score = lens.is_relevant(ctx)
        considered_records.append(LensConsidered(
            name=lens.capabilities.name,
            score=score.score,
            reason=score.reason,
        ))

    record = RunRecord(
        run_id=ctx.run_id,
        timestamp=ctx.started_at,
        mode=ctx.mode,
        invoked_by="loupe-cli",
        trigger="manual_ci",
        base_sha=ctx.diff.base_sha if ctx.diff else None,
        head_sha=ctx.diff.head_sha if ctx.diff else None,
        diff_hash=hashlib.sha256(diff_bytes).hexdigest(),
        context_md_hash=hashlib.sha256(context_bytes).hexdigest(),
        lenses_considered=considered_records,
        lenses_run=[p.lens_name for p in ctx.plan],
        models_used={},
        total_tokens_in=0,
        total_tokens_out=0,
        cost_usd_estimate=0.0,
        cache_hit_rate=None,
        artifacts_changed=[],
        proposed_patches=[p.location for p in ctx.proposed_patches],
        pending_decisions=[d.id for d in ctx.pending_decisions],
        prev_run_hash=prev_hash,
        self_hash="",
    )
    save_run_record(runs_dir, record)
    # cfg will be consumed by gate-logic (ci.fail_on / ci.warn_on) in a
    # follow-up commit. Kept in the signature so callers don't need to
    # change when that lands.
    del cfg
