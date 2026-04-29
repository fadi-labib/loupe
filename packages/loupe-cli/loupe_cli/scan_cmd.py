"""`loupe scan` — D-15 full-repo / scoped scan mode.

Unlike `loupe ci` (incremental, diff-driven), `loupe scan` is the
no-diff entry point: the coordinator's relevance filter is bypassed
because the user has explicitly invoked the lens, so the platform must
run it.

TODO(F-09 / D-24): today this command attaches `scope_paths` to the
RunContext but the prompt builder reads only `ctx.diff` /
`ctx.project` / `ctx.sbom` / `ctx.cve_findings` / `ctx.knowledge`. The
agent therefore receives NO source bytes for the paths the operator
scoped, only `context.md` and the "no diff provided" placeholder. The
fix wires a `ctx.scoped_sources` field + `_sources_section` in the
prompt builder. See `docs/plans/2026-05-16-mongoose-validation-fix-plan.md`
Phase B and the D-24 decision entry.

Cost note: scoped scans are materially more expensive than diff-mode
runs. The per-run limits in config.yaml still apply. A `--budget-usd`
override flag is planned for the case where users want a one-off
scan to exceed the configured ceiling. Not yet implemented.

When to use:
- First-time onboarding to an existing codebase (`loupe scan`)
- Periodic re-baseline (quarterly-ish)
- Architectural review of a specific subsystem (`loupe scan --paths …`,
  after F-09 ships — until then, use `loupe ci --diff-file`)
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
from loupe_core.artifacts.run_record_writer import build_run_record
from loupe_core.capabilities.bootstrap import bootstrap_capabilities
from loupe_core.capabilities.errors import CapabilityError
from loupe_core.capabilities.registry import CapabilityRegistry
from loupe_core.config import LoupeConfig, load_config
from loupe_core.coordinator import build_run_plan
from loupe_core.dispatcher import dispatch_plan
from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.gating import check_lens_liveness, format_liveness_failure
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
    boundary = PathBoundary(
        writable_globs=cfg.agent_writable_paths,
        project_root=cwd.resolve(),
    )
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

    # Mirror loupe ci's liveness contract: a crashed lens (lens_error
    # finding) must trip the gate even though scan has no fail_on/warn_on
    # severity gate of its own. Before this check, scans silently exited 0
    # on crashes — a scheduled scan in CI would never alert the operator
    # that ThreatLens died, the run record on disk being the only trace.
    liveness_failure = check_lens_liveness(ctx)
    if liveness_failure is not None:
        typer.echo(format_liveness_failure(liveness_failure), err=True)
        return 1

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
    """Delegate to `build_run_record` with scan-mode origin parameters.

    `cfg` is unused today; kept in the signature for symmetry with
    `ci_cmd._write_run_record` and for future gate-logic wiring.
    """
    del cfg
    build_run_record(
        ctx=ctx,
        loupe_dir=loupe_dir,
        considered=considered,
        trigger=f"manual_scan_{scope}",
        base_sha=None,
        head_sha=None,
        diff_hash=hashlib.sha256(b"").hexdigest(),
    )
