from __future__ import annotations
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Literal
from pydantic import BaseModel


class LensConsidered(BaseModel):
    name: str
    score: float
    reason: str


class RunRecord(BaseModel):
    run_id: str
    timestamp: datetime
    mode: Literal["ci", "interactive"]
    invoked_by: str
    trigger: str
    base_sha: str | None
    head_sha: str | None
    diff_hash: str
    context_md_hash: str
    lenses_considered: list[LensConsidered]
    lenses_run: list[str]
    models_used: dict[str, str]
    total_tokens_in: int
    total_tokens_out: int
    cost_usd_estimate: float
    cache_hit_rate: float | None
    artifacts_changed: list[str]
    proposed_patches: list[str]
    pending_decisions: list[str]
    prev_run_hash: str | None
    self_hash: str = ""

    def compute_self_hash(self) -> str:
        data = self.model_dump(mode="json", exclude={"self_hash"})
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


def save_run_record(runs_dir: Path, record: RunRecord) -> RunRecord:
    record = record.model_copy(update={"self_hash": ""})
    record.self_hash = record.compute_self_hash()
    runs_dir.mkdir(parents=True, exist_ok=True)
    filename = record.timestamp.strftime("%Y-%m-%dT%H-%M-%SZ") + f"-{record.run_id}.json"
    out = runs_dir / filename
    out.write_text(json.dumps(record.model_dump(mode="json"), indent=2, sort_keys=True))
    return record


def load_run_records(runs_dir: Path) -> list[RunRecord]:
    if not runs_dir.exists():
        return []
    return [
        RunRecord.model_validate_json(p.read_text())
        for p in sorted(runs_dir.glob("*.json"))
    ]
