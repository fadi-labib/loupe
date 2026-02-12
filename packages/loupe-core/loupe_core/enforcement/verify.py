"""Layer 3 enforcement — `loupe verify` implementation.

Independent of the CLI; can be invoked from any context (pre-commit hook,
CI step, programmatic use) to validate the integrity of .loupe/.

Currently checks:
- Run-record hash chain: every record's prev_run_hash must equal the
  previous record's self_hash, and every record's self_hash must equal
  the SHA-256 of its own content (excluding self_hash).

Future checks (documented in the spec but not yet wired here):
- Authorship of protected paths (D-08 Layer 2 / D-15 verify)
- Artefact schema consistency
- threats <-> mitigations cross-reference integrity
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from loupe_core.artifacts.run_record import load_run_records


@dataclass
class VerifyFailure:
    kind: str
    detail: str
    run_id: str | None = None


def check_run_record_chain(runs_dir: Path) -> list[VerifyFailure]:
    """Walk the run-record chain; report breaks in prev_run_hash or self_hash."""
    records = load_run_records(runs_dir)
    failures: list[VerifyFailure] = []
    expected_prev: str | None = None
    for r in records:
        if r.prev_run_hash != expected_prev:
            failures.append(VerifyFailure(
                kind="run_chain_broken",
                run_id=r.run_id,
                detail=f"prev_run_hash={r.prev_run_hash} but expected {expected_prev}",
            ))
        if r.self_hash != r.compute_self_hash():
            failures.append(VerifyFailure(
                kind="run_self_hash_mismatch",
                run_id=r.run_id,
                detail="content does not match self_hash",
            ))
        expected_prev = r.self_hash
    return failures


def verify_repo(repo_root: Path) -> list[VerifyFailure]:
    """Top-level entry point — runs every check and returns combined failures."""
    loupe = repo_root / ".loupe"
    failures: list[VerifyFailure] = []
    failures.extend(check_run_record_chain(loupe / "runs"))
    return failures
