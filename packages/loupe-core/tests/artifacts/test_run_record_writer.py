"""Parity tests for `build_run_record`.

Pins the contract that ci-mode and scan-mode produce equivalent
`RunRecord` shapes modulo the four origin parameters (trigger,
base_sha, head_sha, diff_hash). Before this helper existed, the
aggregation block was duplicated across two `_write_run_record`
functions and they diverged once (F-04: scan shipped zeros for
tokens / cost / artifacts). This test makes any future divergence
caught at the helper layer, not after rotting in two places.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from loupe_core.artifacts.run_record import load_run_records
from loupe_core.artifacts.run_record_writer import build_run_record
from loupe_core.run_context import LensUsage, RunContext


def _ctx_with_usage(loupe_dir: Path) -> RunContext:
    ctx = RunContext(
        run_id="run-parity",
        mode="ci",
        started_at=datetime(2026, 5, 16, 14, 0, tzinfo=UTC),
        user_intent="parity test",
        diff=None,
        sbom_delta=None,
        project=None,
        plan=[],
        knowledge=None,
    )
    ctx.lens_usage["threatlens"] = LensUsage(
        model_id="anthropic:claude-opus-4-7",
        input_tokens=5000,
        output_tokens=800,
        cache_read_tokens=400,
        cache_write_tokens=200,
        cost_usd_estimate=0.082,
    )
    (loupe_dir / "context.md").write_text("# context\n\nProduct: parity test fixture.\n")
    return ctx


@pytest.fixture
def loupe_dir(tmp_path: Path) -> Path:
    d = tmp_path / ".loupe"
    d.mkdir()
    (d / "runs").mkdir()
    return d


def test_build_run_record_persists_ci_record(loupe_dir: Path):
    """Round-trip: ci-mode build → file on disk → load back → fields preserved."""
    ctx = _ctx_with_usage(loupe_dir)

    record = build_run_record(
        ctx=ctx,
        loupe_dir=loupe_dir,
        considered=[],
        trigger="manual_ci",
        base_sha="abc123",
        head_sha="def456",
        diff_hash="0" * 64,
    )

    on_disk = load_run_records(loupe_dir / "runs")
    assert len(on_disk) == 1
    assert on_disk[0].run_id == record.run_id
    assert on_disk[0].trigger == "manual_ci"
    assert on_disk[0].base_sha == "abc123"
    assert on_disk[0].head_sha == "def456"
    assert on_disk[0].diff_hash == "0" * 64
    # Telemetry aggregated: total_in = input + cache_read + cache_write.
    assert on_disk[0].total_tokens_in == 5000 + 400 + 200
    assert on_disk[0].total_tokens_out == 800
    assert on_disk[0].cost_usd_estimate == pytest.approx(0.082, abs=1e-6)


def test_build_run_record_persists_scan_record(tmp_path: Path):
    """Scan-mode parameters: empty diff_hash, null base/head_sha, scan trigger."""
    d = tmp_path / ".loupe"
    d.mkdir()
    (d / "runs").mkdir()
    ctx = _ctx_with_usage(d)

    record = build_run_record(
        ctx=ctx,
        loupe_dir=d,
        considered=[],
        trigger="manual_scan_scoped",
        base_sha=None,
        head_sha=None,
        diff_hash=hashlib.sha256(b"").hexdigest(),
    )

    on_disk = load_run_records(d / "runs")
    assert on_disk[0].trigger == "manual_scan_scoped"
    assert on_disk[0].base_sha is None
    assert on_disk[0].head_sha is None
    assert on_disk[0].diff_hash == hashlib.sha256(b"").hexdigest()
    # Same aggregation logic as ci-mode → same totals from the same usage.
    assert on_disk[0].total_tokens_in == record.total_tokens_in == 5000 + 400 + 200


def test_ci_and_scan_records_equivalent_modulo_origin(tmp_path: Path):
    """The contract: aggregation logic is invariant across modes.

    Two fresh .loupe/ directories, same ctx usage, different origin
    parameters. Stripping the four origin fields plus run_id / self_hash
    / prev_run_hash (chain state), the two records must be field-equal.
    """
    ci_dir = tmp_path / "ci" / ".loupe"
    scan_dir = tmp_path / "scan" / ".loupe"
    for d in (ci_dir, scan_dir):
        d.mkdir(parents=True)
        (d / "runs").mkdir()

    ci_ctx = _ctx_with_usage(ci_dir)
    scan_ctx = _ctx_with_usage(scan_dir)

    ci_record = build_run_record(
        ctx=ci_ctx,
        loupe_dir=ci_dir,
        considered=[],
        trigger="manual_ci",
        base_sha="abc",
        head_sha="def",
        diff_hash="a" * 64,
    )
    scan_record = build_run_record(
        ctx=scan_ctx,
        loupe_dir=scan_dir,
        considered=[],
        trigger="manual_scan_full",
        base_sha=None,
        head_sha=None,
        diff_hash=hashlib.sha256(b"").hexdigest(),
    )

    # Strip the fields that legitimately differ. Everything else must
    # match — that's the parity guarantee callers rely on.
    origin_fields = {"trigger", "base_sha", "head_sha", "diff_hash"}
    chain_fields = {"run_id", "self_hash", "prev_run_hash"}
    ignore = origin_fields | chain_fields

    ci_dump = {k: v for k, v in ci_record.model_dump().items() if k not in ignore}
    scan_dump = {k: v for k, v in scan_record.model_dump().items() if k not in ignore}
    assert ci_dump == scan_dump


def test_chain_link_pickup_across_invocations(loupe_dir: Path):
    """Second invocation in the same .loupe/ picks up the first record's
    self_hash as its prev_run_hash. Verifies the helper handles chain
    state correctly without callers needing to thread prev_hash manually.
    """
    ctx_a = _ctx_with_usage(loupe_dir)
    first = build_run_record(
        ctx=ctx_a,
        loupe_dir=loupe_dir,
        considered=[],
        trigger="manual_ci",
        base_sha="aaa",
        head_sha="bbb",
        diff_hash="1" * 64,
    )

    ctx_b = _ctx_with_usage(loupe_dir)
    ctx_b.run_id = "run-parity-2"
    second = build_run_record(
        ctx=ctx_b,
        loupe_dir=loupe_dir,
        considered=[],
        trigger="manual_ci",
        base_sha="bbb",
        head_sha="ccc",
        diff_hash="2" * 64,
    )

    assert second.prev_run_hash == first.self_hash
    assert first.prev_run_hash is None
