from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field, field_validator

from loupe_core.artifacts.merkle import compute_artefact_merkle_root
from loupe_core.capabilities.degradation import CapabilityDegradation

if TYPE_CHECKING:
    # Type-check-only import keeps run_record.py loadable before run_context,
    # which matters for tooling that imports artifacts in isolation
    # (e.g., docs/reference/schemas/*.schema.json generation).
    from loupe_core.run_context import Finding


class LensConsidered(BaseModel):
    """One lens the coordinator considered, with its relevance score."""

    name: str = Field(description="Lens name, e.g., `threatlens`.")
    score: float = Field(description="Score from `is_relevant()`.")
    reason: str = Field(description="Free-text reason from `is_relevant()`.")


# Maximum bytes of formatted traceback to persist in the run record.
# A full traceback can run tens of KB on a nested exception; truncate to
# keep the on-disk record auditor-readable and reduce hash-chain pressure.
# The tail (most recent frames) is the diagnostic-useful half.
_TRACEBACK_EXCERPT_BYTES = 2048


class LensError(BaseModel):
    """One lens-crash record from `ctx.findings[<lens>]['lens_error']`.

    Populated by the dispatcher's error-isolation handler and surfaced
    into the run record so auditors can reconstruct what went wrong from
    the audit trail alone — terminal output is ephemeral, the run record
    is not. The shape mirrors the payload the dispatcher writes into
    `Finding.payload`; `request_id` is opportunistically extracted from
    `pydantic_ai.exceptions.ModelHTTPError` when present.
    """

    lens: str = Field(description="Lens name that crashed (e.g., `threatlens`).")
    kind: str = Field(description="Exception class name (e.g., `UserError`, `ModelHTTPError`).")
    message: str = Field(description="The exception's string form.")
    request_id: str | None = Field(
        default=None,
        description="Provider request id when the exception carries one; null otherwise.",
    )
    traceback_excerpt: str | None = Field(
        default=None,
        description=(
            f"Tail of the formatted traceback, truncated to {_TRACEBACK_EXCERPT_BYTES} bytes "
            "to keep the on-disk record bounded."
        ),
    )


class RunRecord(BaseModel):
    """Tamper-evident audit entry for one Loupe invocation.

    Written to `.loupe/runs/<timestamp>-<run_id>.json` as canonical JSON (sorted
    keys, no whitespace) so `self_hash` is reproducible. Each record's
    `prev_run_hash` points at the previous record's `self_hash`, forming the
    chain that `loupe verify` walks.
    """

    run_id: str = Field(description="Unique identifier such as `run-a3f2b1c4`.")
    timestamp: datetime = Field(description="UTC, microsecond precision.")
    mode: Literal["ci", "interactive"] = Field(description="Which frontend invoked Loupe.")
    invoked_by: str = Field(description="Bot identity (CI) or user email (interactive).")
    trigger: str = Field(description="What started the run: github_pr / manual_ci / chat_session.")
    base_sha: str | None = Field(description="Base git SHA; null for `loupe scan`.")
    head_sha: str | None = Field(description="Head git SHA.")
    diff_hash: str = Field(description="SHA-256 of the unified-diff text.")
    context_md_hash: str = Field(description="SHA-256 of `context.md` at run time.")
    lenses_considered: list[LensConsidered] = Field(
        description="Every enabled lens with its triage result."
    )
    lenses_run: list[str] = Field(description="Subset of `lenses_considered` that ran.")
    models_used: dict[str, str] = Field(description="Map lens-name to model identifier.")
    total_tokens_in: int = Field(description="Sum across all LLM calls this run.")
    total_tokens_out: int = Field(description="Sum across all LLM calls this run.")
    cost_usd_estimate: float = Field(description="Estimated cost in USD.")
    cache_hit_rate: float | None = Field(description="Prompt-cache hit rate; null if unmeasurable.")
    artifacts_changed: list[str] = Field(description="Paths in `.loupe/` written this run.")
    proposed_patches: list[str] = Field(
        description="Paths in `.loupe/.proposed/` created this run."
    )
    pending_decisions: list[str] = Field(description="Decisions awaiting human sign-off.")
    errors: list[LensError] = Field(
        default_factory=list,
        description=(
            "Structured lens-crash records for this run, one per lens that raised in "
            "`dispatch_plan`. Empty on a clean run. Part of the canonical JSON, so two "
            "runs that differ only by their `errors` get different `self_hash` values — "
            "an auditor can distinguish a clean run from a lens-crash run by hash alone."
        ),
    )
    capability_degraded: list[CapabilityDegradation] = Field(
        default_factory=list,
        description=(
            "D-23: preferred capabilities that could not be made available. Each entry "
            "names the lens that wanted the capability, the capability itself, the "
            "failure kind, and a human-readable detail. Empty on a clean run. Required-"
            "but-unavailable capabilities never reach this list — they raise "
            "RequiredCapabilityUnavailable at bootstrap and the CLI exits 64 before "
            "dispatch runs. The field is included in the canonical hash so a run that "
            "degraded gracefully gets a different self_hash from one that did not."
        ),
    )
    artifact_hashes: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Map of path → SHA-256 (lowercase hex) for every artefact this "
            "run wrote. Keys are paths relative to `.loupe/`; values are the "
            "content hash captured at write time. Empty on legacy records."
        ),
    )
    artifacts_merkle_root: str = Field(
        default="",
        description=(
            "SHA-256 Merkle root over the sorted (path, sha256) leaves in "
            "`artifact_hashes`. Empty string when no artefacts were written "
            "(or on legacy records). Computed by `save_run_record` so "
            "callers cannot forget."
        ),
    )
    prev_run_hash: str | None = Field(
        description="Previous record's `self_hash`; null on first run."
    )
    self_hash: str = Field(
        default="", description="SHA-256 of this record's content excluding `self_hash`."
    )

    @field_validator("timestamp")
    @classmethod
    def _timestamp_must_be_utc_aware(cls, v: datetime) -> datetime:
        """Reject naive datetimes outright.

        The on-disk filename format appends a literal 'Z' suffix, which
        promises UTC. A naive datetime would slip in whatever the local
        clock said and lie about the timezone — corrupting the hash chain
        if two runs from different machines wrote records the auditor
        later compared. Coerce to UTC explicitly to keep that promise.
        """
        if v.tzinfo is None:
            raise ValueError(
                "RunRecord.timestamp must be timezone-aware (use datetime.now(UTC) "
                "or attach tzinfo before constructing the record)."
            )
        return v.astimezone(UTC)

    def compute_self_hash(self) -> str:
        data = self.model_dump(mode="json", exclude={"self_hash"})
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


def extract_lens_errors(findings: dict[str, dict[str, Finding]]) -> list[LensError]:
    """Project per-lens `lens_error` findings into `LensError` records.

    The dispatcher's error-isolation branch writes the same payload shape
    every time: ``{"type": ..., "message": ..., "traceback": ...}``. The
    optional ``request_id`` is set by the friendliness pass in
    `loupe_core.dispatcher` for provider errors that carry one
    (``pydantic_ai.exceptions.ModelHTTPError``). Lenses are returned in
    deterministic sorted-by-name order so two runs with the same crash
    set produce the same canonical JSON.
    """
    out: list[LensError] = []
    for lens_name in sorted(findings.keys()):
        finding = findings[lens_name].get("lens_error")
        if finding is None:
            continue
        payload = finding.payload
        traceback_text = payload.get("traceback") or None
        if traceback_text and len(traceback_text) > _TRACEBACK_EXCERPT_BYTES:
            traceback_text = traceback_text[-_TRACEBACK_EXCERPT_BYTES:]
        out.append(
            LensError(
                lens=lens_name,
                kind=str(payload.get("type", "Exception")),
                message=str(payload.get("message", "")),
                request_id=payload.get("request_id"),
                traceback_excerpt=traceback_text,
            )
        )
    return out


def save_run_record(runs_dir: Path, record: RunRecord) -> RunRecord:
    record = record.model_copy(
        update={
            "self_hash": "",
            "artifacts_merkle_root": compute_artefact_merkle_root(record.artifact_hashes),
        }
    )
    record.self_hash = record.compute_self_hash()
    runs_dir.mkdir(parents=True, exist_ok=True)
    # Microsecond precision ensures two runs in the same wall-clock second
    # still sort chronologically by filename. Lexical filename sort then
    # matches chain order; no need for hash-chain traversal at load time.
    filename = record.timestamp.strftime("%Y-%m-%dT%H-%M-%S-%fZ") + f"-{record.run_id}.json"
    out = runs_dir / filename
    # Atomic write: a crash mid-write must not leave a truncated JSON file at
    # the destination — that would break the entire hash chain.
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(record.model_dump(mode="json"), indent=2, sort_keys=True))
    os.replace(tmp, out)
    return record


def load_run_records(runs_dir: Path) -> list[RunRecord]:
    if not runs_dir.exists():
        return []
    return [RunRecord.model_validate_json(p.read_text()) for p in sorted(runs_dir.glob("*.json"))]
