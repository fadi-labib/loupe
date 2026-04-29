"""Build and persist `runs/<id>.json` records.

Single source of truth for the per-lens telemetry aggregation that both
`loupe ci` and `loupe scan` write into the hash-chained run record
(D-12). Before this module existed the aggregation block was duplicated
in `ci_cmd._write_run_record` and `scan_cmd._write_run_record`; the
two had already diverged once (F-04: scan shipped zeros for tokens /
cost / artifacts for several weeks before the divergence was caught).

The four parameters that differ between ci-mode and scan-mode runs —
`trigger`, `base_sha`, `head_sha`, `diff_hash` — describe what
triggered this run. Everything else (token aggregation, cache-hit
math, considered-lens scoring, artifacts-changed union, hash chain
linkage) is invariant across modes and lives here.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from loupe_core.artifacts.run_record import (
    LensConsidered,
    RunRecord,
    extract_lens_errors,
    load_run_records,
    save_run_record,
)
from loupe_core.lens_api import Lens
from loupe_core.run_context import RunContext


def build_run_record(
    ctx: RunContext,
    loupe_dir: Path,
    *,
    considered: list[Lens],
    trigger: str,
    base_sha: str | None,
    head_sha: str | None,
    diff_hash: str,
) -> RunRecord:
    """Aggregate per-lens telemetry, assemble a `RunRecord`, persist it.

    Returns the saved record so callers can introspect (e.g. for stdout
    summaries or test assertions). The `prev_run_hash` link is computed
    from `loupe_dir/runs/` so callers don't need to manage chain state.
    """
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

    # Cache reads count toward total_tokens_in because they ARE input
    # the model saw — just paid at the discounted rate. cache_hit_rate
    # reports the discount separately.
    models_used = {name: u.model_id for name, u in ctx.lens_usage.items()}
    total_in = sum(
        u.input_tokens + u.cache_read_tokens + u.cache_write_tokens for u in ctx.lens_usage.values()
    )
    total_out = sum(u.output_tokens for u in ctx.lens_usage.values())
    cost_total = round(sum(u.cost_usd_estimate for u in ctx.lens_usage.values()), 6)
    # None when no LLM call happened, to distinguish from a real 0.0
    # cache-hit-rate (the lens ran but cache missed entirely).
    cache_read = sum(u.cache_read_tokens for u in ctx.lens_usage.values())
    cache_denom = sum(
        u.input_tokens + u.cache_read_tokens + u.cache_write_tokens for u in ctx.lens_usage.values()
    )
    cache_hit = round(cache_read / cache_denom, 4) if cache_denom else None

    artifacts_changed = sorted(
        set().union(
            *(
                set(threat_keys)
                for lens_findings in ctx.findings.values()
                for threat_keys in [list(lens_findings.keys())]
            )
        )
        | {p.location for p in ctx.proposed_patches}
    )

    record = RunRecord(
        run_id=ctx.run_id,
        timestamp=ctx.started_at,
        mode=ctx.mode,
        invoked_by="loupe-cli",
        trigger=trigger,
        base_sha=base_sha,
        head_sha=head_sha,
        diff_hash=diff_hash,
        context_md_hash=hashlib.sha256(context_bytes).hexdigest(),
        lenses_considered=considered_records,
        lenses_run=[p.lens_name for p in ctx.plan],
        models_used=models_used,
        total_tokens_in=total_in,
        total_tokens_out=total_out,
        cost_usd_estimate=cost_total,
        cache_hit_rate=cache_hit,
        artifacts_changed=artifacts_changed,
        proposed_patches=[p.location for p in ctx.proposed_patches],
        pending_decisions=[d.id for d in ctx.pending_decisions],
        errors=extract_lens_errors(ctx.findings),
        capability_degraded=list(ctx.capability_degradations),
        prev_run_hash=prev_hash,
        self_hash="",
    )
    # save_run_record returns the record with self_hash populated (it
    # computes the hash during persistence); return that so callers see
    # a record that matches what landed on disk.
    return save_run_record(runs_dir, record)
