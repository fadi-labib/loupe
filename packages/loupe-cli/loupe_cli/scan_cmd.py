"""`loupe scan` — D-15 full-repo / scoped scan mode.

Unlike `loupe ci` (incremental, diff-driven), `loupe scan` analyses the
whole codebase from scratch (or a subset specified by `--paths`). The
coordinator's relevance filter is bypassed in scan mode — the user has
explicitly invoked the lens, so the platform must run it.

Cost note: full-repo scans are materially more expensive than diff-mode
runs. The per-run limits in config.yaml still apply. A `--budget-usd`
override flag is planned for the case where users want a one-off
scan to exceed the configured ceiling. Not yet implemented.

When to use:
- First-time onboarding to an existing codebase (`loupe scan`)
- Periodic re-baseline (quarterly-ish)
- Architectural review of a specific subsystem (`loupe scan --paths …`)
- Audit kickoff
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

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

# BSD sysexits.h EX_USAGE — operator-config / usage errors.
USAGE_ERROR = 64


def scan_command(
    paths: list[str],
    config_path: Path,
) -> int:
    cwd = Path.cwd()
    loupe = cwd / ".loupe"
    if not loupe.exists():
        typer.echo(
            "Error: .loupe/ not found in the current directory.\nRun `loupe init` first.",
            err=True,
        )
        return USAGE_ERROR

    cfg = load_config(config_path)
    boundary = PathBoundary(writable_globs=cfg.agent_writable_paths)
    lenses = discover_lenses()

    scope: Literal["full", "scoped"] = "scoped" if paths else "full"
    # Timezone-aware UTC: RunRecord.timestamp rejects naive datetimes
    # because the on-disk filename appends a literal 'Z' (Phase 7).
    started_at = datetime.now(UTC)
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    user_intent = f"scan scoped to {paths}" if paths else "full-repo scan"

    ctx = RunContext.bootstrap(
        BootstrapInputs(
            run_id=run_id,
            mode="ci",  # scan is a non-interactive flow
            started_at=started_at,
            user_intent=user_intent,
            loupe_dir=loupe,
            unified_diff="",  # no diff in scan mode
            base_sha=None,
            head_sha=None,
            scope=scope,
            scope_paths=list(paths),
        )
    )
    ctx.plan = build_run_plan(ctx, lenses, cfg)

    if not ctx.plan:
        typer.echo("No enabled lenses to run. Check config.yaml.")
        _write_run_record(ctx, loupe, considered=lenses, cfg=cfg, scope=scope)
        return 0

    # Run capability bootstrap ONCE before any lens executes — mirror of
    # ci_cmd. ThreatLens declares requires_capabilities=["sbom", "cve"];
    # without this, full-repo scans saw ctx.sbom/ctx.cve_findings as None
    # and silently produced threat output without any vulnerability context.
    planned_lenses = _planned_lenses(lenses, ctx)
    if any(getattr(lens.capabilities, "requires_capabilities", []) for lens in planned_lenses):
        registry = CapabilityRegistry.discover()
        try:
            asyncio.run(
                bootstrap_capabilities(
                    ctx=ctx,
                    lenses=planned_lenses,
                    config=cfg,
                    registry=registry,
                    repo_path=cwd,
                )
            )
        except CapabilityError as exc:
            # Same policy as ci_cmd: surface the misconfiguration and
            # let lenses run with whatever slots got populated. The
            # alternative (hard-fail the scan) would block onboarding
            # runs where the operator hasn't wired up Syft/Grype yet.
            typer.echo(
                f"warning: capability bootstrap failed — {exc}. "
                f"Lenses will see partial capability results.",
                err=True,
            )

    asyncio.run(dispatch_plan(ctx, lenses, boundary, loupe))
    _write_run_record(ctx, loupe, considered=lenses, cfg=cfg, scope=scope)

    typer.echo(f"Loupe scan complete. Run: {run_id} (scope={scope}).")
    typer.echo(f"Lenses run: {[p.lens_name for p in ctx.plan]}")
    return 0


def _planned_lenses(lenses: list[Lens], ctx: RunContext) -> list[Lens]:
    """Filter discovered lenses to those actually in the run plan.

    Mirror of ci_cmd._planned_lenses — kept duplicated for now rather than
    extracted, because there's no third caller yet (D-21: extract on the
    third instance, not the second).
    """
    planned_names = {p.lens_name for p in ctx.plan}
    return [lens for lens in lenses if lens.capabilities.name in planned_names]


def _write_run_record(
    ctx: RunContext,
    loupe_dir: Path,
    *,
    considered: list[Lens],
    cfg: LoupeConfig,
    scope: str,
) -> None:
    runs_dir = loupe_dir / "runs"
    existing = load_run_records(runs_dir)
    prev_hash = existing[-1].self_hash if existing else None

    context_bytes = (loupe_dir / "context.md").read_bytes()

    considered_records: list[LensConsidered] = []
    for lens in considered:
        score = lens.is_relevant(ctx)
        considered_records.append(
            LensConsidered(
                name=lens.capabilities.name,
                score=score.score,
                reason=score.reason,
            )
        )

    record = RunRecord(
        run_id=ctx.run_id,
        timestamp=ctx.started_at,
        mode=ctx.mode,
        invoked_by="loupe-cli",
        trigger=f"manual_scan_{scope}",
        base_sha=None,
        head_sha=None,
        diff_hash=hashlib.sha256(b"").hexdigest(),  # no diff
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
    del cfg  # reserved for future gate logic
