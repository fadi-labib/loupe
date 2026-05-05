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
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from loupe_core.artifacts.merkle import compute_artefact_merkle_root
from loupe_core.artifacts.run_record import load_run_records
from loupe_core.artifacts.run_record_writer import (
    build_run_record,
    enumerate_artefact_files,
)
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


def test_capability_degradations_persist_into_run_record(loupe_dir: Path):
    """D-23 / A.5: preferred-capability degradations on the RunContext
    land on disk in the run record's `capability_degraded` list. Required-
    but-unavailable capabilities never reach the writer (the CLI exits 64
    at bootstrap), so this test only covers the soft-failure persistence
    path. Empty list on a clean run."""
    from loupe_core.capabilities.degradation import CapabilityDegradation

    ctx = _ctx_with_usage(loupe_dir)
    ctx.capability_degradations = [
        CapabilityDegradation(
            lens_name="future_lens",
            capability="secret_detect",
            kind="unconfigured",
            detail="Capability 'secret_detect' is required but no backends are configured.",
        )
    ]

    build_run_record(
        ctx=ctx,
        loupe_dir=loupe_dir,
        considered=[],
        trigger="manual_ci",
        base_sha="abc",
        head_sha="def",
        diff_hash="0" * 64,
    )

    on_disk = load_run_records(loupe_dir / "runs")[0]
    assert len(on_disk.capability_degraded) == 1
    entry = on_disk.capability_degraded[0]
    assert entry.lens_name == "future_lens"
    assert entry.capability == "secret_detect"
    assert entry.kind == "unconfigured"
    assert "secret_detect" in entry.detail


def test_capability_degradations_change_self_hash(loupe_dir: Path):
    """A run that degraded gracefully gets a different self_hash from
    one that did not. Auditors can distinguish a clean ThreatLens run
    from one that ran without (e.g.) Grype just by walking the chain."""
    from loupe_core.capabilities.degradation import CapabilityDegradation

    clean = build_run_record(
        ctx=_ctx_with_usage(loupe_dir),
        loupe_dir=loupe_dir,
        considered=[],
        trigger="manual_ci",
        base_sha="a",
        head_sha="b",
        diff_hash="0" * 64,
    )

    # Fresh second .loupe so we don't drag prev_run_hash into the comparison.
    other_dir = loupe_dir.parent.parent / "other" / ".loupe"
    other_dir.mkdir(parents=True)
    (other_dir / "runs").mkdir()
    degraded_ctx = _ctx_with_usage(other_dir)
    degraded_ctx.capability_degradations = [
        CapabilityDegradation(
            lens_name="threatlens",
            capability="cve",
            kind="unconfigured",
            detail="Grype not wired",
        )
    ]
    degraded = build_run_record(
        ctx=degraded_ctx,
        loupe_dir=other_dir,
        considered=[],
        trigger="manual_ci",
        base_sha="a",
        head_sha="b",
        diff_hash="0" * 64,
    )

    assert clean.self_hash != degraded.self_hash


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


class TestEnumerateArtefactFiles:
    """Tests for enumerate_artefact_files filesystem walk + filter logic."""

    def test_includes_yaml_json_md_at_root(self, loupe_dir: Path) -> None:
        (loupe_dir / "threats.yaml").write_text("threats: []\n")
        (loupe_dir / "sbom.cdx.json").write_text("{}")
        # context.md is created implicitly
        (loupe_dir / "context.md").write_text("# context\n")
        found = {p.name for p in enumerate_artefact_files(loupe_dir)}
        assert found == {"context.md", "threats.yaml", "sbom.cdx.json"}

    def test_excludes_runs_directory(self, loupe_dir: Path) -> None:
        (loupe_dir / "context.md").write_text("# context\n")
        (loupe_dir / "runs" / "old.json").write_text("{}")
        found = {p.name for p in enumerate_artefact_files(loupe_dir)}
        assert "old.json" not in found

    def test_excludes_proposed_directory(self, loupe_dir: Path) -> None:
        (loupe_dir / "context.md").write_text("# context\n")
        proposed = loupe_dir / ".proposed"
        proposed.mkdir()
        (proposed / "draft.yaml").write_text("")
        found = {p.name for p in enumerate_artefact_files(loupe_dir)}
        assert "draft.yaml" not in found

    def test_includes_decisions_subdirectory(self, loupe_dir: Path) -> None:
        (loupe_dir / "context.md").write_text("# context\n")
        decisions = loupe_dir / "decisions"
        decisions.mkdir()
        (decisions / "D-001.md").write_text("# accept\n")
        found = {p.relative_to(loupe_dir).as_posix() for p in enumerate_artefact_files(loupe_dir)}
        assert "decisions/D-001.md" in found

    def test_excludes_non_artefact_extensions(self, loupe_dir: Path) -> None:
        (loupe_dir / "context.md").write_text("# context\n")
        (loupe_dir / "scratch.log").write_text("noise")
        (loupe_dir / "temp.tmp").write_text("temp")
        found = {p.name for p in enumerate_artefact_files(loupe_dir)}
        assert "scratch.log" not in found
        assert "temp.tmp" not in found

    def test_results_sorted_by_relative_path(self, loupe_dir: Path) -> None:
        (loupe_dir / "context.md").write_text("# context\n")
        (loupe_dir / "z.yaml").write_text("")
        (loupe_dir / "a.json").write_text("{}")
        rels = [p.relative_to(loupe_dir).as_posix() for p in enumerate_artefact_files(loupe_dir)]
        assert rels == sorted(rels)

    def test_includes_yml_extension(self, loupe_dir: Path) -> None:
        (loupe_dir / "context.md").write_text("# context\n")
        (loupe_dir / "mitigations.yml").write_text("")
        found = {p.name for p in enumerate_artefact_files(loupe_dir)}
        assert "mitigations.yml" in found


class TestBuildRunRecordPopulatesArtefactHashes:
    """Tests for artifact_hashes population in build_run_record."""

    def test_hashes_present_for_every_enumerated_file(self, loupe_dir: Path) -> None:
        (loupe_dir / "context.md").write_text("# context\n")
        (loupe_dir / "threats.yaml").write_text("threats: []\n")
        (loupe_dir / "sbom.cdx.json").write_text("{}")

        ctx = _ctx_with_usage(loupe_dir)
        record = build_run_record(
            ctx,
            loupe_dir,
            considered=[],
            trigger="manual_ci",
            base_sha=None,
            head_sha=None,
            diff_hash="0" * 64,
        )

        expected_paths = {"context.md", "threats.yaml", "sbom.cdx.json"}
        assert set(record.artifact_hashes.keys()) == expected_paths
        # Hashes are 64-char lowercase hex
        for sha in record.artifact_hashes.values():
            assert len(sha) == 64
            assert all(c in "0123456789abcdef" for c in sha)

    def test_merkle_root_matches_recomputed(self, loupe_dir: Path) -> None:
        (loupe_dir / "context.md").write_text("# context\n")
        (loupe_dir / "threats.yaml").write_text("threats: []\n")
        ctx = _ctx_with_usage(loupe_dir)
        record = build_run_record(
            ctx,
            loupe_dir,
            considered=[],
            trigger="manual_ci",
            base_sha=None,
            head_sha=None,
            diff_hash="0" * 64,
        )
        assert record.artifacts_merkle_root == compute_artefact_merkle_root(record.artifact_hashes)
        assert record.artifacts_merkle_root is not None  # non-null when files exist

    def test_empty_loupe_yields_only_context(self, loupe_dir: Path) -> None:
        # Fixture only created context.md implicitly via _ctx_with_usage
        ctx = _ctx_with_usage(loupe_dir)
        record = build_run_record(
            ctx,
            loupe_dir,
            considered=[],
            trigger="manual_ci",
            base_sha=None,
            head_sha=None,
            diff_hash="0" * 64,
        )
        assert set(record.artifact_hashes.keys()) == {"context.md"}

    def test_record_persisted_with_hashes_on_disk(self, loupe_dir: Path) -> None:
        (loupe_dir / "context.md").write_text("# context\n")
        (loupe_dir / "threats.yaml").write_text("threats: []\n")
        ctx = _ctx_with_usage(loupe_dir)
        record = build_run_record(
            ctx,
            loupe_dir,
            considered=[],
            trigger="manual_ci",
            base_sha=None,
            head_sha=None,
            diff_hash="0" * 64,
        )
        runs = sorted((loupe_dir / "runs").glob("*.json"))
        assert len(runs) == 1
        on_disk = json.loads(runs[0].read_text())
        assert on_disk["artifact_hashes"] == record.artifact_hashes
        assert on_disk["artifacts_merkle_root"] == record.artifacts_merkle_root

    def test_hash_values_match_file_content(self, loupe_dir: Path) -> None:
        """Verify hashes are actually computed from file contents, not just placeholders."""
        (loupe_dir / "context.md").write_text("# context\n")
        content1 = "threat_a: severity-high\n"
        (loupe_dir / "threats.yaml").write_text(content1)
        ctx = _ctx_with_usage(loupe_dir)
        record = build_run_record(
            ctx,
            loupe_dir,
            considered=[],
            trigger="manual_ci",
            base_sha=None,
            head_sha=None,
            diff_hash="0" * 64,
        )
        expected_hash = hashlib.sha256(content1.encode()).hexdigest()
        assert record.artifact_hashes["threats.yaml"] == expected_hash
