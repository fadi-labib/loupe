"""Unit tests for loupe_core.enforcement.verify — Layer 3 enforcement core.

Exercises check_run_record_chain in isolation against in-process run records,
without going through the CLI or filesystem-watcher path.
"""
from datetime import UTC, datetime
from pathlib import Path

from loupe_core.artifacts.run_record import LensConsidered, RunRecord, save_run_record
from loupe_core.enforcement.verify import check_run_record_chain


def _record(run_id: str, prev: str | None) -> RunRecord:
    return RunRecord(
        run_id=run_id,
        timestamp=datetime(2026, 5, 14, 12, 0, 0, 0, tzinfo=UTC),
        mode="ci",
        invoked_by="bot",
        trigger="t",
        base_sha=None,
        head_sha=None,
        diff_hash="0" * 64,
        context_md_hash="1" * 64,
        lenses_considered=[LensConsidered(name="x", score=0.5, reason="")],
        lenses_run=[],
        models_used={},
        total_tokens_in=0,
        total_tokens_out=0,
        cost_usd_estimate=0.0,
        cache_hit_rate=None,
        artifacts_changed=[],
        proposed_patches=[],
        pending_decisions=[],
        prev_run_hash=prev,
        self_hash="",
    )


def test_chain_valid(tmp_path: Path) -> None:
    r1 = save_run_record(tmp_path, _record("r1", None))
    save_run_record(tmp_path, _record("r2", r1.self_hash))
    failures = check_run_record_chain(tmp_path)
    assert failures == []


def test_chain_broken_detected(tmp_path: Path) -> None:
    save_run_record(tmp_path, _record("r1", None))
    save_run_record(tmp_path, _record("r2", "WRONG"))
    failures = check_run_record_chain(tmp_path)
    assert len(failures) >= 1
    assert failures[0].kind == "run_chain_broken"


def test_self_hash_mismatch_detected(tmp_path: Path) -> None:
    """If a record's content is mutated, its self_hash no longer matches."""
    r1 = save_run_record(tmp_path, _record("r1", None))
    files = sorted(tmp_path.glob("*.json"))
    assert len(files) == 1
    # Corrupt: change the invoked_by field but not self_hash
    import json
    data = json.loads(files[0].read_text())
    data["invoked_by"] = "TAMPERED"
    files[0].write_text(json.dumps(data, indent=2, sort_keys=True))

    failures = check_run_record_chain(tmp_path)
    assert any(f.kind == "run_self_hash_mismatch" for f in failures)
    _ = r1  # silence unused-result
