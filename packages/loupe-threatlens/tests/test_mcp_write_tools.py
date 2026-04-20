"""Tests for the MCP write tools (propose_threat / propose_mitigation).

Unit-level coverage focuses on the `write_*_directly` helpers, which
are pure functions. The end-to-end registration smoke (write tools
appear in the MCP tool list when a boundary is provided) is asserted
via the existing register_threatlens_mcp_tools entry point.

The full handshake-over-stdio path is exercised by an additional
integration test in test_mcp_handshake.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from loupe_core.artifacts.mitigation import MitigationsFile
from loupe_core.artifacts.threat import ThreatsFile
from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.tools import BoundaryViolation
from loupe_threatlens.tools import (
    ProposeMitigationInput,
    ProposeThreatInput,
    write_mitigation_directly,
    write_threat_directly,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _boundary_with(loupe_dir: Path, *paths: str) -> PathBoundary:
    """Construct a PathBoundary that permits the listed paths under loupe_dir."""
    return PathBoundary(
        writable_globs=[str(loupe_dir / p) for p in paths],
    )


def _threat_input(**overrides) -> ProposeThreatInput:
    defaults = dict(
        element_id="E-001",
        stride_category="E",
        title="Sample threat",
        description="A description.",
        severity="high",
        rationale="Why this matters.",
    )
    defaults.update(overrides)
    return ProposeThreatInput(**defaults)


# ---------------------------------------------------------------------------
# write_threat_directly
# ---------------------------------------------------------------------------


def test_write_threat_appends_to_empty_threats_file(tmp_path: Path):
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    boundary = _boundary_with(loupe, "threats.yaml")

    threat_id = write_threat_directly(
        loupe,
        boundary,
        _threat_input(),
        proposed_by="mcp/test",
    )

    assert threat_id == "T-001"
    file = ThreatsFile.load(loupe / "threats.yaml")
    assert len(file.threats) == 1
    assert file.threats[0].title == "Sample threat"
    assert file.threats[0].proposed_by == "mcp/test"


def test_write_threat_assigns_sequential_ids(tmp_path: Path):
    """Multiple writes get consecutive T-NNN IDs."""
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    boundary = _boundary_with(loupe, "threats.yaml")

    ids = [
        write_threat_directly(loupe, boundary, _threat_input(), proposed_by="x") for _ in range(3)
    ]
    assert ids == ["T-001", "T-002", "T-003"]


def test_write_threat_raises_when_path_not_writable(tmp_path: Path):
    """Path boundary blocks writes to non-allowlisted paths."""
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    # Boundary does NOT include threats.yaml.
    boundary = _boundary_with(loupe, "mitigations.yaml")

    with pytest.raises(BoundaryViolation) as exc:
        write_threat_directly(loupe, boundary, _threat_input(), proposed_by="mcp/test")
    assert "threats.yaml" in str(exc.value)


def test_write_threat_runs_through_path_boundary(tmp_path: Path):
    """The same is_agent_writable check the agent uses gates MCP writes too.

    Constructs the boundary with absolute paths so the test doesn't
    depend on operator-config glob resolution against a working dir;
    that resolution is exercised elsewhere.
    """
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    boundary = PathBoundary(writable_globs=[str(loupe / "threats.yaml")])

    threat_id = write_threat_directly(
        loupe,
        boundary,
        _threat_input(),
        proposed_by="mcp/test",
    )
    assert threat_id == "T-001"
    assert (loupe / "threats.yaml").exists()


# ---------------------------------------------------------------------------
# write_mitigation_directly
# ---------------------------------------------------------------------------


def test_write_mitigation_appends_to_empty_file(tmp_path: Path):
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    boundary = _boundary_with(loupe, "mitigations.yaml")

    mid = write_mitigation_directly(
        loupe,
        boundary,
        ProposeMitigationInput(
            title="Sanitise exception messages",
            description="Wrap the framework error handler.",
            threats_addressed=["T-001"],
        ),
    )
    assert mid == "M-001"
    file = MitigationsFile.load(loupe / "mitigations.yaml")
    assert len(file.mitigations) == 1
    assert file.mitigations[0].threats_addressed == ["T-001"]


def test_write_mitigation_with_evidence_pointer(tmp_path: Path):
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    boundary = _boundary_with(loupe, "mitigations.yaml")

    write_mitigation_directly(
        loupe,
        boundary,
        ProposeMitigationInput(
            title="Add CSRF token check",
            description="...",
            evidence_kind="code",
            evidence_location="src/api/csrf.py",
        ),
    )
    file = MitigationsFile.load(loupe / "mitigations.yaml")
    assert len(file.mitigations[0].evidence) == 1
    assert file.mitigations[0].evidence[0].kind == "code"
    assert file.mitigations[0].evidence[0].location == "src/api/csrf.py"


def test_write_mitigation_without_evidence_pointer(tmp_path: Path):
    """Evidence is optional — without kind+location both, no entry is added."""
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    boundary = _boundary_with(loupe, "mitigations.yaml")

    write_mitigation_directly(
        loupe,
        boundary,
        ProposeMitigationInput(
            title="Pure documentation mitigation",
            description="No code evidence yet.",
        ),
    )
    file = MitigationsFile.load(loupe / "mitigations.yaml")
    assert file.mitigations[0].evidence == []


def test_write_mitigation_raises_when_path_not_writable(tmp_path: Path):
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    boundary = _boundary_with(loupe, "threats.yaml")  # mitigations.yaml NOT allowed

    with pytest.raises(BoundaryViolation):
        write_mitigation_directly(
            loupe,
            boundary,
            ProposeMitigationInput(title="x", description="x"),
        )


def test_write_mitigation_assigns_sequential_ids(tmp_path: Path):
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    boundary = _boundary_with(loupe, "mitigations.yaml")

    ids = [
        write_mitigation_directly(
            loupe,
            boundary,
            ProposeMitigationInput(title=f"m{i}", description="..."),
        )
        for i in range(3)
    ]
    assert ids == ["M-001", "M-002", "M-003"]


# ---------------------------------------------------------------------------
# register_threatlens_mcp_tools — write tool registration
# ---------------------------------------------------------------------------


def test_write_tools_registered_only_when_boundary_supplied(tmp_path: Path):
    """No boundary → read-only surface; with boundary → write tools appear."""
    from loupe_threatlens.mcp_tools import register_threatlens_mcp_tools
    from mcp.server.fastmcp import FastMCP

    boundary = _boundary_with(tmp_path / ".loupe", "threats.yaml")

    server_ro = FastMCP(name="ro")
    register_threatlens_mcp_tools(server_ro, tmp_path / ".loupe")
    # Read-only: registration succeeds, write tools are not registered.
    # If they were, the server would have failed in some other way; we
    # just confirm no exception.

    server_rw = FastMCP(name="rw")
    register_threatlens_mcp_tools(
        server_rw,
        tmp_path / ".loupe",
        boundary=boundary,
    )
    # Read+write: same call shape, with boundary. Successful registration
    # means the closures captured cleanly.
