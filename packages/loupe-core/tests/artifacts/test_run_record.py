from datetime import UTC, datetime

import pytest
from loupe_core.artifacts.run_record import (
    LensConsidered,
    LensError,
    RunRecord,
    extract_lens_errors,
    load_run_records,
    save_run_record,
)
from loupe_core.run_context import Finding


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
        mode="ci",
        invoked_by="b",
        trigger="t",
        base_sha=None,
        head_sha=None,
        diff_hash="0" * 64,
        context_md_hash="1" * 64,
        lenses_considered=[],
        lenses_run=[],
        models_used={},
        total_tokens_in=0,
        total_tokens_out=0,
        cost_usd_estimate=0.0,
        cache_hit_rate=None,
        artifacts_changed=[],
        proposed_patches=[],
        pending_decisions=[],
        prev_run_hash=None,
        self_hash="",
    )


def test_timestamp_coerced_to_utc_when_aware():
    """A tz-aware datetime in a different timezone is coerced to UTC at
    construction so downstream hash chain stays portable."""
    from datetime import timedelta, timezone

    plus_two = timezone(timedelta(hours=2))
    r = RunRecord(
        run_id="run-tz",
        timestamp=datetime(2026, 5, 13, 14, 32, tzinfo=plus_two),
        mode="ci",
        invoked_by="b",
        trigger="t",
        base_sha=None,
        head_sha=None,
        diff_hash="0" * 64,
        context_md_hash="1" * 64,
        lenses_considered=[],
        lenses_run=[],
        models_used={},
        total_tokens_in=0,
        total_tokens_out=0,
        cost_usd_estimate=0.0,
        cache_hit_rate=None,
        artifacts_changed=[],
        proposed_patches=[],
        pending_decisions=[],
        prev_run_hash=None,
        self_hash="",
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


# ---------------------------------------------------------------------------
# LensError / extract_lens_errors (G-4)
# ---------------------------------------------------------------------------


def _err_finding(payload: dict) -> Finding:
    return Finding(posted_by="dispatcher", payload=payload)


def test_extract_lens_errors_empty_when_no_lens_error_finding():
    findings = {"threatlens": {"threat:T-001": _err_finding({"id": "T-001"})}}
    assert extract_lens_errors(findings) == []


def test_extract_lens_errors_maps_dispatcher_payload_shape():
    """Mirror the exact payload the dispatcher writes for a crash."""
    findings = {
        "threatlens": {
            "lens_error": _err_finding(
                {
                    "type": "UserError",
                    "message": "Set the ANTHROPIC_API_KEY env variable",
                    "traceback": "Traceback (most recent call last):\n  ...",
                }
            )
        }
    }
    errors = extract_lens_errors(findings)
    assert len(errors) == 1
    assert errors[0] == LensError(
        lens="threatlens",
        kind="UserError",
        message="Set the ANTHROPIC_API_KEY env variable",
        request_id=None,
        traceback_excerpt="Traceback (most recent call last):\n  ...",
    )


def test_extract_lens_errors_truncates_long_traceback():
    long_traceback = "x" * 5000
    findings = {
        "threatlens": {
            "lens_error": _err_finding(
                {"type": "RuntimeError", "message": "boom", "traceback": long_traceback}
            )
        }
    }
    excerpt = extract_lens_errors(findings)[0].traceback_excerpt
    assert excerpt is not None
    assert len(excerpt) == 2048
    # Tail-preserving truncation — the most recent frames matter most.
    assert excerpt == long_traceback[-2048:]


def test_extract_lens_errors_picks_up_request_id_when_present():
    """The friendliness pass in dispatcher attaches request_id for
    ModelHTTPError 401/403; the helper must surface it."""
    findings = {
        "threatlens": {
            "lens_error": _err_finding(
                {
                    "type": "ModelHTTPError",
                    "message": "status_code: 401, model_name: claude-opus-4-7",
                    "traceback": "",
                    "request_id": "req_011Cb68Z24U5W4aWfL9nkHet",
                }
            )
        }
    }
    err = extract_lens_errors(findings)[0]
    assert err.request_id == "req_011Cb68Z24U5W4aWfL9nkHet"


def test_extract_lens_errors_sorted_by_lens_name_for_determinism():
    """Two runs with the same crash set must produce the same canonical
    JSON — ergo the same self_hash. Sort the output."""
    findings = {
        "zlens": {
            "lens_error": _err_finding({"type": "RuntimeError", "message": "z", "traceback": ""})
        },
        "alens": {
            "lens_error": _err_finding({"type": "RuntimeError", "message": "a", "traceback": ""})
        },
    }
    errors = extract_lens_errors(findings)
    assert [e.lens for e in errors] == ["alens", "zlens"]


def test_errors_field_is_part_of_self_hash(tmp_path):
    """Two runs identical except for `errors` must have different hashes —
    an auditor needs to distinguish clean from crashed runs by hash alone."""
    clean = _record("run-clean", prev=None)
    crashed = _record("run-clean", prev=None)
    crashed = crashed.model_copy(
        update={
            "errors": [
                LensError(
                    lens="threatlens",
                    kind="UserError",
                    message="missing API key",
                )
            ]
        }
    )
    h_clean = save_run_record(tmp_path, clean).self_hash
    # Different runs_dir so save doesn't clobber.
    other = tmp_path / "other"
    other.mkdir()
    h_crashed = save_run_record(other, crashed).self_hash
    assert h_clean != h_crashed


def test_errors_field_defaults_empty_and_backward_compat(tmp_path):
    """Pre-G-4 run records on disk have no `errors` key. Pydantic's default
    extra='ignore' plus a field default keeps `load_run_records` working."""
    legacy_json = """{
        "run_id": "legacy-run",
        "timestamp": "2026-05-01T10:00:00+00:00",
        "mode": "ci",
        "invoked_by": "loupe-cli",
        "trigger": "manual_ci",
        "base_sha": null,
        "head_sha": null,
        "diff_hash": "abc",
        "context_md_hash": "def",
        "lenses_considered": [],
        "lenses_run": [],
        "models_used": {},
        "total_tokens_in": 0,
        "total_tokens_out": 0,
        "cost_usd_estimate": 0.0,
        "cache_hit_rate": null,
        "artifacts_changed": [],
        "proposed_patches": [],
        "pending_decisions": [],
        "prev_run_hash": null,
        "self_hash": "legacy-hash"
    }"""
    (tmp_path / "2026-05-01T10-00-00-000000Z-legacy-run.json").write_text(legacy_json)
    records = load_run_records(tmp_path)
    assert len(records) == 1
    assert records[0].errors == []


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


# ---------------------------------------------------------------------------
# Merkle root fields (Task 2)
# ---------------------------------------------------------------------------


class TestArtefactMerkleFields:
    def test_defaults_are_empty(self) -> None:
        r = _record("run-defaults", prev=None)
        assert r.artifact_hashes == {}
        assert r.artifacts_merkle_root == ""

    def test_record_accepts_populated_hashes(self) -> None:
        hashes = {"sbom.cdx.json": "a" * 64, "threats.yaml": "b" * 64}
        r = _record("run-with-hashes", prev=None).model_copy(update={"artifact_hashes": hashes})
        assert r.artifact_hashes == hashes

    def test_old_record_json_still_loads(self) -> None:
        """JSON written by a pre-Merkle Loupe lacks the new fields entirely.
        The defaults must accept that and keep loading working."""
        import json as _json

        legacy = {
            "run_id": "run-legacy",
            "timestamp": "2026-01-01T00:00:00.000000+00:00",
            "mode": "ci",
            "invoked_by": "test@example.com",
            "trigger": "manual_ci",
            "base_sha": None,
            "head_sha": None,
            "diff_hash": "0" * 64,
            "context_md_hash": "0" * 64,
            "lenses_considered": [],
            "lenses_run": [],
            "models_used": {},
            "total_tokens_in": 0,
            "total_tokens_out": 0,
            "cost_usd_estimate": 0.0,
            "cache_hit_rate": None,
            "artifacts_changed": [],
            "proposed_patches": [],
            "pending_decisions": [],
            "errors": [],
            "capability_degraded": [],
            "prev_run_hash": None,
            "self_hash": "deadbeef",
        }
        r = RunRecord.model_validate_json(_json.dumps(legacy))
        assert r.artifact_hashes == {}
        assert r.artifacts_merkle_root == ""


class TestSaveRunRecordComputesMerkleRoot:
    def test_root_is_filled_in_at_save(self, tmp_path) -> None:
        from loupe_core.artifacts.merkle import compute_artefact_merkle_root

        hashes = {"sbom.cdx.json": "a" * 64, "threats.yaml": "b" * 64}
        r = _record("run-save", prev=None).model_copy(update={"artifact_hashes": hashes})
        saved = save_run_record(tmp_path, r)
        assert saved.artifacts_merkle_root == compute_artefact_merkle_root(hashes)

    def test_empty_hashes_yield_empty_root(self, tmp_path) -> None:
        r = _record("run-empty", prev=None)
        saved = save_run_record(tmp_path, r)
        assert saved.artifact_hashes == {}
        assert saved.artifacts_merkle_root == ""

    def test_self_hash_covers_merkle_root(self, tmp_path) -> None:
        """If an attacker rewrites artifacts_merkle_root post-hoc, the
        canonical-JSON self_hash must reveal the tampering."""
        hashes = {"a.json": "1" * 64}
        r = _record("run-coverage", prev=None).model_copy(update={"artifact_hashes": hashes})
        saved = save_run_record(tmp_path, r)
        tampered = saved.model_copy(update={"artifacts_merkle_root": "0" * 64})
        assert tampered.compute_self_hash() != saved.self_hash
