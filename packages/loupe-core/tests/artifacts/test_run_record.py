from datetime import datetime

from loupe_core.artifacts.run_record import (
    LensConsidered,
    RunRecord,
    load_run_records,
    save_run_record,
)


def _record(run_id: str, prev: str | None) -> RunRecord:
    return RunRecord(
        run_id=run_id,
        timestamp=datetime(2026, 5, 13, 14, 32),
        mode="ci",
        invoked_by="loupe-bot",
        trigger="pull_request_opened",
        base_sha="abc123",
        head_sha="def456",
        diff_hash="0" * 64,
        context_md_hash="1" * 64,
        lenses_considered=[LensConsidered(name="threatlens", score=0.95, reason="code changes")],
        lenses_run=["threatlens"],
        models_used={"threatlens": "anthropic:claude-opus-4-7"},
        total_tokens_in=12000,
        total_tokens_out=800,
        cost_usd_estimate=0.05,
        cache_hit_rate=0.85,
        artifacts_changed=[".loupe/threats.yaml"],
        proposed_patches=[],
        pending_decisions=[],
        prev_run_hash=prev,
        self_hash="",  # filled in by save_run_record
    )


def test_self_hash_deterministic(tmp_path):
    r1 = save_run_record(tmp_path, _record("run-1", prev=None))
    r2 = save_run_record(tmp_path, _record("run-1", prev=None))
    assert r1.self_hash == r2.self_hash != ""


def test_chain_is_built(tmp_path):
    r1 = save_run_record(tmp_path, _record("run-1", prev=None))
    r2 = save_run_record(tmp_path, _record("run-2", prev=r1.self_hash))
    records = load_run_records(tmp_path)
    assert len(records) == 2
    assert records[0].prev_run_hash is None
    assert records[1].prev_run_hash == r1.self_hash
