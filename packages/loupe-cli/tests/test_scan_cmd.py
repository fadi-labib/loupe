"""Tests for `loupe scan` — D-15 full-repo / scoped scan mode."""

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from loupe_cli.__main__ import app
from loupe_core.artifacts.run_record import load_run_records
from loupe_core.config import LoupeConfig
from loupe_core.run_context import LensUsage, RunContext
from typer.testing import CliRunner

from .conftest import minimal_config_yaml

runner = CliRunner()
FIXTURES = Path(__file__).parent.parent.parent / "loupe-core" / "tests" / "artifacts" / "fixtures"


def _init_project(tmp_path: Path) -> Path:
    """A .loupe/ with threatlens at a high relevance threshold so diff mode
    would normally filter it out — proving that scan mode bypasses the filter."""
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    shutil.copy(FIXTURES / "valid_context.md", loupe / "context.md")
    # Impossible-for-diff-mode threshold — only scan mode can include this lens.
    (loupe / "config.yaml").write_text(minimal_config_yaml(threatlens_min_relevance=0.99))
    (loupe / "runs").mkdir()
    return loupe


def test_scan_runs_lens_despite_high_relevance_threshold(tmp_path, monkeypatch):
    """In scan mode, threatlens runs even though its real diff-mode relevance
    would be far below the configured 0.99 threshold."""
    monkeypatch.chdir(tmp_path)
    loupe = _init_project(tmp_path)

    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0, result.stdout

    runs = load_run_records(loupe / "runs")
    assert len(runs) == 1
    assert "threatlens" in runs[0].lenses_run


def test_scan_records_scope_full_in_run_record(tmp_path, monkeypatch):
    """The run record (or its trigger field) should reflect that this was a scan, not a diff."""
    monkeypatch.chdir(tmp_path)
    loupe = _init_project(tmp_path)

    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0

    runs = load_run_records(loupe / "runs")
    # The trigger string carries the mode signal in the record
    assert "scan" in runs[0].trigger.lower()


def test_scan_scoped_with_paths(tmp_path, monkeypatch):
    """`loupe scan --paths src/payments/` runs in scoped mode (D-15)."""
    monkeypatch.chdir(tmp_path)
    loupe = _init_project(tmp_path)

    result = runner.invoke(
        app,
        ["scan", "--paths", "src/payments/", "--paths", "src/api/"],
    )
    assert result.exit_code == 0, result.stdout

    runs = load_run_records(loupe / "runs")
    assert len(runs) == 1
    assert "threatlens" in runs[0].lenses_run


def test_scan_fails_when_loupe_dir_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan"])
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "loupe init" in combined.lower() or ".loupe" in combined


def test_scan_lens_error_fails_gate(tmp_path, monkeypatch):
    """A lens that crashes during dispatch (`lens_error` finding) must
    cause `loupe scan` to exit 1 — same liveness contract as `loupe ci`.

    Before this fix, scan returned 0 unconditionally, so a scheduled
    nightly scan would silently mask catastrophic ThreatLens failures.
    """
    monkeypatch.chdir(tmp_path)
    loupe = _init_project(tmp_path)

    async def _crash_dispatch(ctx, lenses, boundary, loupe_dir):  # noqa: ARG001
        ctx.record_finding(
            "threatlens",
            "lens_error",
            {
                "type": "RuntimeError",
                "message": "trufflehog exceeded budget",
                "traceback": "Traceback (most recent call last):\n  ...",
            },
        )

    # Override the autouse `stub_dispatch` from conftest: that one sets
    # a no-op binding; this test needs the binding to record a lens_error.
    monkeypatch.setattr("loupe_cli.scan_cmd.dispatch_plan", _crash_dispatch)

    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 1, (result.exit_code, result.stdout, result.stderr)
    combined = (result.stdout or "") + (result.stderr or "")
    assert "lens 'threatlens' crashed" in combined.lower() or "missing evidence" in combined

    # The audit trail must still be written even on a lens crash —
    # the run record carries the errors[] entry for the auditor.
    runs = load_run_records(loupe / "runs")
    assert len(runs) == 1
    assert len(runs[0].errors) == 1
    assert runs[0].errors[0].lens == "threatlens"
    assert runs[0].errors[0].kind == "RuntimeError"


def test_scan_bootstraps_capabilities_before_dispatch(tmp_path, monkeypatch):
    """`loupe scan` must call bootstrap_capabilities() so lenses have their
    declared SBOM/CVE/etc inputs available. ci_cmd does this; scan_cmd
    historically skipped it, so ThreatLens (requires sbom+cve) ran with
    empty capability slots on every full-repo scan.
    """
    monkeypatch.chdir(tmp_path)
    _init_project(tmp_path)

    calls: list[dict] = []

    async def _spy(**kwargs):
        # Capture the kwargs so we can assert ctx/lenses/config were threaded.
        calls.append(kwargs)
        # D-23 contract: bootstrap_capabilities returns list[CapabilityDegradation];
        # empty list means "everything bootstrapped cleanly".
        return []

    monkeypatch.setattr("loupe_cli.scan_cmd.bootstrap_capabilities", _spy)

    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0, result.stdout
    assert len(calls) == 1, "bootstrap_capabilities was not called by loupe scan"
    # Sanity: scan threaded the planned lenses through so the bootstrap
    # only runs caps for what will actually execute.
    assert "lenses" in calls[0]
    assert any(
        getattr(lens.capabilities, "name", None) == "threatlens" for lens in calls[0]["lenses"]
    )


# ---------------------------------------------------------------------------
# Run-record telemetry parity with `loupe ci`
# ---------------------------------------------------------------------------


def _ctx_with_scan_usage(loupe_dir: Path, usages: dict[str, LensUsage]) -> RunContext:
    ctx = RunContext(
        run_id="run-scan-test",
        mode="ci",  # scan keeps mode=ci by schema; trigger + scope discriminate
        started_at=datetime(2026, 5, 16, 10, 0, tzinfo=UTC),
        user_intent="full-repo scan",
        diff=None,
        sbom_delta=None,
        project=None,
        plan=[],
        knowledge=None,
    )
    for lens_name, usage in usages.items():
        ctx.lens_usage[lens_name] = usage
    (loupe_dir / "context.md").write_text("# context")
    return ctx


@pytest.fixture
def scan_loupe_dir(tmp_path: Path) -> Path:
    d = tmp_path / ".loupe"
    d.mkdir()
    (d / "runs").mkdir()
    return d


def test_scan_run_record_aggregates_lens_usage(scan_loupe_dir: Path):
    """The scan-side `_write_run_record` MUST aggregate per-lens token/
    cost telemetry into the on-disk run record, exactly like the ci-side
    record builder does. Before this fix, scan records always shipped
    `total_tokens_in=0`, `cost_usd_estimate=0.0`, `models_used={}` even
    when the lens consumed real tokens — making cost tracking and audit
    replay impossible for scan-mode runs.
    """
    from loupe_cli.scan_cmd import _write_run_record

    ctx = _ctx_with_scan_usage(
        scan_loupe_dir,
        {
            "threatlens": LensUsage(
                model_id="anthropic:claude-opus-4-7",
                input_tokens=12000,
                output_tokens=3500,
                cache_read_tokens=8000,
                cache_write_tokens=400,
                cost_usd_estimate=0.42,
            ),
        },
    )
    _write_run_record(ctx, scan_loupe_dir, considered=[], cfg=LoupeConfig(), scope="full")
    record = load_run_records(scan_loupe_dir / "runs")[0]

    assert record.models_used == {"threatlens": "anthropic:claude-opus-4-7"}
    # Same accounting as ci: input + cache_read + cache_write count
    # toward total_tokens_in (cache reads ARE input the model saw).
    assert record.total_tokens_in == 12000 + 8000 + 400
    assert record.total_tokens_out == 3500
    assert record.cost_usd_estimate == pytest.approx(0.42, abs=1e-6)
    assert record.cache_hit_rate == round(8000 / (12000 + 8000 + 400), 4)
    assert "scan" in record.trigger.lower()


def test_scan_run_record_artifacts_changed_reflects_proposed_findings(
    scan_loupe_dir: Path,
) -> None:
    """`artifacts_changed` in the scan run record must surface the threats
    that were actually proposed, so an auditor walking `.loupe/runs/*.json`
    can see *what* changed in each scan without diffing threats.yaml by
    hand. Before this fix scan always wrote `artifacts_changed=[]`.
    """
    from loupe_cli.scan_cmd import _write_run_record
    from loupe_core.run_context import Finding

    ctx = _ctx_with_scan_usage(scan_loupe_dir, {})
    # Mimic the dispatcher's blackboard population from a successful
    # propose_threat tool call.
    ctx.findings["threatlens"] = {
        "threat:T-001": Finding(
            posted_by="threatlens",
            payload={"id": "T-001", "severity": "high"},
            timestamp=datetime(2026, 5, 16, 10, 5, tzinfo=UTC),
        ),
        "threat:T-002": Finding(
            posted_by="threatlens",
            payload={"id": "T-002", "severity": "medium"},
            timestamp=datetime(2026, 5, 16, 10, 5, tzinfo=UTC),
        ),
    }
    _write_run_record(ctx, scan_loupe_dir, considered=[], cfg=LoupeConfig(), scope="full")
    record = load_run_records(scan_loupe_dir / "runs")[0]
    assert "threat:T-001" in record.artifacts_changed
    assert "threat:T-002" in record.artifacts_changed
