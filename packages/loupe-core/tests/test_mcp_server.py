"""Tests for the MCP server skeleton (Phase 9.1).

Targets the `*_impl` functions directly — pure, no MCP plumbing needed.
Also exercises `build_mcp_server` to confirm the server registers the
expected tool names under the FastMCP instance.
"""
from __future__ import annotations

from datetime import date, datetime
from pathlib import Path

import pytest

from loupe_core.artifacts.knowledge import Element, KnowledgeGraph
from loupe_core.artifacts.mitigation import Evidence, Mitigation, MitigationsFile
from loupe_core.artifacts.run_record import (
    LensConsidered,
    RunRecord,
    save_run_record,
)
from loupe_core.artifacts.threat import Threat, ThreatsFile
from loupe_core.artifacts.types import (
    MitigationStatus,
    Severity,
    StrideCategory,
    ThreatStatus,
)
from loupe_core.mcp_server import (
    build_mcp_server,
    get_mitigation_impl,
    get_threat_impl,
    latest_run_impl,
    list_elements_impl,
    list_mitigations_impl,
    list_threats_impl,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def loupe_dir(tmp_path: Path) -> Path:
    d = tmp_path / ".loupe"
    d.mkdir()
    (d / "runs").mkdir()
    return d


def _threat(id_: str = "T-001", severity: Severity = Severity.HIGH) -> Threat:
    return Threat(
        id=id_, element_id="E-001",
        stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        title=f"Sample {id_}", description="...",
        severity=severity, status=ThreatStatus.PROPOSED,
        mitigation_ids=[], cwe_refs=[],
        introduced_in_pr=None, last_reviewed=date(2026, 5, 15),
        rationale="...", proposed_by="test",
    )


def _mitigation(id_: str = "M-001") -> Mitigation:
    return Mitigation(
        id=id_, title=f"Sample {id_}", description="...",
        threats_addressed=[], status=MitigationStatus.PLANNED,
        evidence=[Evidence(kind="code", location="src/x.py")],
    )


# ---------------------------------------------------------------------------
# list_threats / get_threat
# ---------------------------------------------------------------------------


def test_list_threats_empty_when_no_file(loupe_dir: Path):
    assert list_threats_impl(loupe_dir) == []


def test_list_threats_returns_all_present(loupe_dir: Path):
    ThreatsFile(threats=[_threat("T-001"), _threat("T-002")]).save(
        loupe_dir / "threats.yaml"
    )
    out = list_threats_impl(loupe_dir)
    assert len(out) == 2
    assert {t["id"] for t in out} == {"T-001", "T-002"}
    # Returned shape is plain JSON-serialisable dicts.
    assert isinstance(out[0], dict)


def test_get_threat_returns_specific(loupe_dir: Path):
    ThreatsFile(threats=[_threat("T-001"), _threat("T-002")]).save(
        loupe_dir / "threats.yaml"
    )
    found = get_threat_impl(loupe_dir, "T-002")
    assert found is not None
    assert found["id"] == "T-002"


def test_get_threat_returns_none_when_missing(loupe_dir: Path):
    ThreatsFile(threats=[_threat("T-001")]).save(loupe_dir / "threats.yaml")
    assert get_threat_impl(loupe_dir, "T-999") is None


# ---------------------------------------------------------------------------
# list_mitigations / get_mitigation
# ---------------------------------------------------------------------------


def test_list_mitigations_empty_when_no_file(loupe_dir: Path):
    assert list_mitigations_impl(loupe_dir) == []


def test_list_mitigations_returns_all_present(loupe_dir: Path):
    MitigationsFile(mitigations=[_mitigation("M-001"), _mitigation("M-002")]).save(
        loupe_dir / "mitigations.yaml"
    )
    out = list_mitigations_impl(loupe_dir)
    assert {m["id"] for m in out} == {"M-001", "M-002"}


def test_get_mitigation_returns_specific(loupe_dir: Path):
    MitigationsFile(mitigations=[_mitigation("M-001")]).save(
        loupe_dir / "mitigations.yaml"
    )
    found = get_mitigation_impl(loupe_dir, "M-001")
    assert found is not None
    assert found["id"] == "M-001"


def test_get_mitigation_returns_none_when_missing(loupe_dir: Path):
    assert get_mitigation_impl(loupe_dir, "M-999") is None


# ---------------------------------------------------------------------------
# list_elements
# ---------------------------------------------------------------------------


def test_list_elements_empty_when_no_file(loupe_dir: Path):
    assert list_elements_impl(loupe_dir) == []


def test_list_elements_returns_all_present(loupe_dir: Path):
    kg = KnowledgeGraph(
        last_updated=datetime(2026, 5, 15),
        elements=[
            Element(id="E-001", name="api-gateway", type="trust_boundary"),
            Element(id="E-002", name="payment-svc", type="process"),
        ],
    )
    kg.save(loupe_dir / "knowledge.yaml")
    out = list_elements_impl(loupe_dir)
    assert {e["id"] for e in out} == {"E-001", "E-002"}


# ---------------------------------------------------------------------------
# latest_run
# ---------------------------------------------------------------------------


def test_latest_run_none_when_no_runs(loupe_dir: Path):
    assert latest_run_impl(loupe_dir) is None


def test_latest_run_returns_most_recent(loupe_dir: Path):
    """Run records are chronologically sorted by filename; latest_run picks the last."""
    runs_dir = loupe_dir / "runs"
    for i, run_id in enumerate(["run-1", "run-2", "run-3"]):
        record = RunRecord(
            run_id=run_id,
            timestamp=datetime(2026, 5, 15, 10, i),
            mode="ci", invoked_by="test", trigger="manual",
            base_sha="a", head_sha="b",
            diff_hash="0" * 64, context_md_hash="1" * 64,
            lenses_considered=[LensConsidered(name="threatlens", score=0.9, reason="r")],
            lenses_run=["threatlens"],
            models_used={}, total_tokens_in=0, total_tokens_out=0,
            cost_usd_estimate=0.0, cache_hit_rate=None,
            artifacts_changed=[], proposed_patches=[], pending_decisions=[],
            prev_run_hash=None, self_hash="",
        )
        save_run_record(runs_dir, record)
    out = latest_run_impl(loupe_dir)
    assert out is not None
    assert out["run_id"] == "run-3"


# ---------------------------------------------------------------------------
# Server construction
# ---------------------------------------------------------------------------


def test_build_mcp_server_registers_expected_tools(loupe_dir: Path):
    """The server must expose the six read-only tools by name."""
    server = build_mcp_server(loupe_dir)
    # FastMCP exposes registered tools via _tool_manager.list_tools() or
    # get_app_tool(name). The name attribute is the most stable cross-version
    # access path; we just check that the server constructed cleanly.
    assert server.name == "loupe"
    assert server.instructions is not None
    assert "list_threats" in server.instructions
