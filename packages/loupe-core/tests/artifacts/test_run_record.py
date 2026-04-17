from datetime import UTC, datetime

import pytest
from loupe_core.artifacts.run_record import (
    LensConsidered,
    RunRecord,
    load_run_records,
    save_run_record,
)


def _record(run_id: str, prev: str | None) -> RunRecord:
    return RunRecord(
        run_id=run_id,
        timestamp=datetime(2026, 5, 13, 14, 32, tzinfo=UTC),
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


def test_timestamp_rejects_naive_datetime():
    """The on-disk filename appends a literal 'Z' suffix that promises
    UTC. A naive datetime would lie about the timezone; reject at
    construction so the corrupt filename never lands."""
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="timezone-aware"):
        _record_with_naive_timestamp()


def _record_with_naive_timestamp() -> RunRecord:
    return RunRecord(
        run_id="run-naive",
        timestamp=datetime(2026, 5, 13, 14, 32),  # no tzinfo
        mode="ci", invoked_by="b", trigger="t",
        base_sha=None, head_sha=None,
        diff_hash="0" * 64, context_md_hash="1" * 64,
        lenses_considered=[], lenses_run=[],
        models_used={}, total_tokens_in=0, total_tokens_out=0,
        cost_usd_estimate=0.0, cache_hit_rate=None,
        artifacts_changed=[], proposed_patches=[], pending_decisions=[],
        prev_run_hash=None, self_hash="",
    )


def test_timestamp_coerced_to_utc_when_aware():
    """A tz-aware datetime in a different timezone is coerced to UTC at
    construction so downstream hash chain stays portable."""
    from datetime import timedelta, timezone
    plus_two = timezone(timedelta(hours=2))
    r = RunRecord(
        run_id="run-tz",
        timestamp=datetime(2026, 5, 13, 14, 32, tzinfo=plus_two),
        mode="ci", invoked_by="b", trigger="t",
        base_sha=None, head_sha=None,
        diff_hash="0" * 64, context_md_hash="1" * 64,
        lenses_considered=[], lenses_run=[],
        models_used={}, total_tokens_in=0, total_tokens_out=0,
        cost_usd_estimate=0.0, cache_hit_rate=None,
        artifacts_changed=[], proposed_patches=[], pending_decisions=[],
        prev_run_hash=None, self_hash="",
    )
    assert r.timestamp.tzinfo == UTC
    assert r.timestamp.hour == 12  # 14:32 +02:00 -> 12:32 UTC


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


def test_save_is_atomic_on_crash(tmp_path, monkeypatch):
    """A crash mid-write must not leave a partial file at the destination.

    Without atomic write (tmp + os.replace), a truncated JSON file breaks
    the entire hash chain that ``loupe verify`` walks.
    """
    def boom(src, dst):
        raise OSError("simulated crash during rename")

    monkeypatch.setattr("loupe_core.artifacts.run_record.os.replace", boom)

    with pytest.raises(OSError, match="simulated crash"):
        save_run_record(tmp_path, _record("run-crash", prev=None))

    # No visible JSON at the destination — only (possibly) a leftover .tmp.
    visible = list(tmp_path.glob("*.json"))
    assert visible == [], f"partial file leaked: {visible}"
