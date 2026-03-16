from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class LensConsidered(BaseModel):
    """One lens the coordinator considered, with its relevance score."""

    name: str = Field(description="Lens name, e.g., `threatlens`.")
    score: float = Field(description="Score from `is_relevant()`.")
    reason: str = Field(description="Free-text reason from `is_relevant()`.")


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
    prev_run_hash: str | None = Field(
        description="Previous record's `self_hash`; null on first run."
    )
    self_hash: str = Field(
        default="", description="SHA-256 of this record's content excluding `self_hash`."
    )

    def compute_self_hash(self) -> str:
        data = self.model_dump(mode="json", exclude={"self_hash"})
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


def save_run_record(runs_dir: Path, record: RunRecord) -> RunRecord:
    record = record.model_copy(update={"self_hash": ""})
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
    return [
        RunRecord.model_validate_json(p.read_text())
        for p in sorted(runs_dir.glob("*.json"))
    ]
