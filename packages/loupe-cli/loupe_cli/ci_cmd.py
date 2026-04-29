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
    extract_lens_errors,
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
from loupe_core.gating import check_lens_liveness, format_liveness_failure
from loupe_core.lens_api import Lens
from loupe_core.lens_registry import discover_lenses
from loupe_core.run_context import BootstrapInputs, RunContext

# BSD sysexits.h EX_USAGE — operator-config / usage errors.
# Gate failures (cfg.ci.fail_on triggered) keep exit 1 by contract.
USAGE_ERROR = 64


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

    # Timezone-aware UTC: RunRecord.timestamp rejects naive datetimes
    # because the on-disk filename appends a literal 'Z' that would
    # otherwise lie about the timezone (Phase 7).
    started_at = datetime.now(UTC)
    run_id = f"run-{uuid.uuid4().hex[:8]}"

    ctx = RunContext.bootstrap(
        BootstrapInputs(
            run_id=run_id,
            mode="ci",
            started_at=started_at,
            user_intent="ci diff analysis",
            loupe_dir=loupe,
            unified_diff=diff,
            base_sha=base_sha,
            head_sha=head_sha,
        )
    )
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
    return _gate_exit_code(ctx, cfg)


def _gate_exit_code(ctx: RunContext, cfg: LoupeConfig) -> int:
    """Compute exit code from cfg.ci.fail_on / warn_on against ctx findings.

    Reads from `ctx.findings["threatlens"]` so the gate fires on the same
    in-memory data the lens wrote during this run — no need to round-trip
    through threats.yaml on disk. The GitHub Action wrapper applies the
    same fail_on rule against the on-disk file for sanity at the workflow
    step level; both must agree, and tests in test_ci_real.py and
    test_entrypoint.py pin the contract on each side.

    Behaviour:
    - Threats whose severity is in `fail_on` print a "Gate failure" block
      and the function returns 1.
    - Threats whose severity is in `warn_on` (but NOT in `fail_on` — fail
      takes precedence on overlap) print a "Warning" block but do not
      change the exit code.
    - Empty fail_on AND empty warn_on means report-only mode; the function
      returns 0 silently.
    - A `lens_error` finding (written by the dispatcher's isolation handler
      when a lens raises in `run()`) ALWAYS fails the gate. Missing
      evidence beats a false-green: the operator configured fail_on for
      threat severity, but lens liveness is non-negotiable — if a lens
      never produced output we cannot claim CI verified its concern.
    """
    # Liveness check: short-circuit BEFORE the threat-severity gate so
    # even fail_on=[] (report-only) still trips on a crashed lens. The
    # helper lives in loupe_core.gating so `loupe scan` enforces the
    # same contract from the same code path.
    liveness_failure = check_lens_liveness(ctx)
    if liveness_failure is not None:
        typer.echo(format_liveness_failure(liveness_failure), err=True)
        return 1

    fail_severities = set(cfg.ci.fail_on)
    warn_severities = set(cfg.ci.warn_on) - fail_severities

    fail_triggered: list[tuple[str, str]] = []
    warn_triggered: list[tuple[str, str]] = []
    for key, finding in ctx.findings.get("threatlens", {}).items():
        if not key.startswith("threat:"):
            continue
        payload = finding.payload
        severity = payload.get("severity")
        threat_id = payload.get("id", key.removeprefix("threat:"))
        if severity in fail_severities:
            fail_triggered.append((threat_id, severity))
        elif severity in warn_severities:
            warn_triggered.append((threat_id, severity))

    if warn_triggered:
        typer.echo(
            f"Warning: {len(warn_triggered)} threat(s) at warn_on severities "
            f"({', '.join(sorted(warn_severities))}):",
            err=True,
        )
        for threat_id, severity in warn_triggered:
            typer.echo(f"  - {threat_id}: {severity}", err=True)

    if not fail_triggered:
        return 0

    typer.echo(
        f"Gate failure: {len(fail_triggered)} threat(s) at fail_on severities "
        f"({', '.join(sorted(fail_severities))}):",
        err=True,
    )
    for threat_id, severity in fail_triggered:
        typer.echo(f"  - {threat_id}: {severity}", err=True)
    return 1


def _planned_lenses(lenses: list[Lens], ctx: RunContext) -> list[Lens]:
    """Filter discovered lenses to those actually in the run plan.

    The capability bootstrap should only run for lenses that will execute —
    a docs-only PR with no relevant lens shouldn't trigger Syft + Grype.
    """
    planned_names = {p.lens_name for p in ctx.plan}
    return [lens for lens in lenses if lens.capabilities.name in planned_names]


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
        considered_records.append(
            LensConsidered(
                name=lens.capabilities.name,
                score=score.score,
                reason=score.reason,
            )
        )

    # Aggregate per-lens usage into workspace-level totals for the run
    # record. Cache reads count toward total_tokens_in because they ARE
    # input the model saw — just paid at the discounted rate. The
    # cache_hit_rate field reports the discount separately.
    models_used = {name: u.model_id for name, u in ctx.lens_usage.items()}
    total_in = sum(
        u.input_tokens + u.cache_read_tokens + u.cache_write_tokens for u in ctx.lens_usage.values()
    )
    total_out = sum(u.output_tokens for u in ctx.lens_usage.values())
    cost_total = round(sum(u.cost_usd_estimate for u in ctx.lens_usage.values()), 6)
    # Aggregate cache hit rate: total cache reads / total input across all lenses.
    # None when no lens ran (or no token data captured) to distinguish "zero
    # cache hits" (0.0) from "no LLM call happened" (None).
    cache_read = sum(u.cache_read_tokens for u in ctx.lens_usage.values())
    cache_denom = sum(
        u.input_tokens + u.cache_read_tokens + u.cache_write_tokens for u in ctx.lens_usage.values()
    )
    cache_hit = round(cache_read / cache_denom, 4) if cache_denom else None

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
        models_used=models_used,
        total_tokens_in=total_in,
        total_tokens_out=total_out,
        cost_usd_estimate=cost_total,
        cache_hit_rate=cache_hit,
        artifacts_changed=sorted(
            set().union(
                *(
                    set(threat_keys)
                    for lens_findings in ctx.findings.values()
                    for threat_keys in [list(lens_findings.keys())]
                )
            )
            | {p.location for p in ctx.proposed_patches}
        ),
        proposed_patches=[p.location for p in ctx.proposed_patches],
        pending_decisions=[d.id for d in ctx.pending_decisions],
        errors=extract_lens_errors(ctx.findings),
        prev_run_hash=prev_hash,
        self_hash="",
    )
    save_run_record(runs_dir, record)
    # cfg will be consumed by gate-logic (ci.fail_on / ci.warn_on) in a
    # follow-up commit. Kept in the signature so callers don't need to
    # change when that lands.
    del cfg
