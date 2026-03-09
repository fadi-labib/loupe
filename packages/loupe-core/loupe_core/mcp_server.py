"""MCP server skeleton — third frontend after ``loupe ci`` and ``loupe chat``.

Exposes read-only views of Loupe artefacts as MCP tools so any MCP-aware
client (Claude Code, Cursor, custom IDE plugins) can query the project's
threat model, mitigations, run history, and architectural elements via
JSON-RPC. Read-only by design at v1 — writes still flow through the
existing Layer 1 path-boundary surface, not over MCP, until the v1.x
write-tool contract is hardened.

Per [D-09], the MCP server is the third frontend and shares the same
core engine — no separate codepath, no separate enforcement. Mounting
extra writes here later is additive; nothing structural changes.

Two-layer design:
- The `*_impl` functions take a `Path` to `.loupe/` and return plain
  Python data. They are pure, deterministic, fully testable without
  any MCP plumbing.
- `build_mcp_server()` wraps each impl in a FastMCP tool, registering
  it under the canonical ``loupe.<resource>`` naming convention.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

# We import the high-level server API from the OFFICIAL `mcp` SDK
# (`mcp.server.fastmcp`), not the third-party `fastmcp` package. The two
# have similar names and a near-identical surface, but only the official
# one is governed by the MCP spec maintainers — see D-21 in the
# decisions log for the rationale.
from mcp.server.fastmcp import FastMCP

from loupe_core.artifacts.knowledge import KnowledgeGraph
from loupe_core.artifacts.mitigation import MitigationsFile
from loupe_core.artifacts.run_record import load_run_records
from loupe_core.artifacts.threat import ThreatsFile

# ---------------------------------------------------------------------------
# Tool implementations — pure, no MCP dependency.
# ---------------------------------------------------------------------------


def list_threats_impl(loupe_dir: Path) -> list[dict[str, Any]]:
    """Return every threat in ``threats.yaml`` as a list of plain dicts.

    Returns an empty list when the file doesn't exist (a freshly-initialised
    project) rather than raising — clients should treat absence as "no
    threats proposed yet".
    """
    path = loupe_dir / "threats.yaml"
    if not path.exists():
        return []
    return [t.model_dump(mode="json") for t in ThreatsFile.load(path).threats]


def get_threat_impl(loupe_dir: Path, threat_id: str) -> dict[str, Any] | None:
    """Return one threat by ID, or ``None`` when the ID is unknown."""
    for threat in list_threats_impl(loupe_dir):
        if threat.get("id") == threat_id:
            return threat
    return None


def list_mitigations_impl(loupe_dir: Path) -> list[dict[str, Any]]:
    path = loupe_dir / "mitigations.yaml"
    if not path.exists():
        return []
    return [m.model_dump(mode="json") for m in MitigationsFile.load(path).mitigations]


def get_mitigation_impl(loupe_dir: Path, mitigation_id: str) -> dict[str, Any] | None:
    for mitigation in list_mitigations_impl(loupe_dir):
        if mitigation.get("id") == mitigation_id:
            return mitigation
    return None


def list_elements_impl(loupe_dir: Path) -> list[dict[str, Any]]:
    """Return architectural elements from ``knowledge.yaml``."""
    path = loupe_dir / "knowledge.yaml"
    if not path.exists():
        return []
    return [e.model_dump(mode="json") for e in KnowledgeGraph.load(path).elements]


def latest_run_impl(loupe_dir: Path) -> dict[str, Any] | None:
    """Return the most recent run record, or ``None`` when no runs exist."""
    runs_dir = loupe_dir / "runs"
    if not runs_dir.exists():
        return None
    records = load_run_records(runs_dir)
    if not records:
        return None
    return records[-1].model_dump(mode="json")


# ---------------------------------------------------------------------------
# Server construction
# ---------------------------------------------------------------------------


def build_mcp_server(loupe_dir: Path) -> FastMCP:
    """Construct the FastMCP server bound to a specific ``.loupe/`` directory.

    Each registered tool closes over ``loupe_dir`` so the server can be
    instantiated once at process start and serve many requests against
    the same project. To serve a different project, build a second
    server — the closure binding is intentional and prevents one tool
    call from accidentally reading another project's artefacts.
    """
    mcp = FastMCP(
        name="loupe",
        instructions=(
            "Read-only access to Loupe artefacts. Use `list_threats` and "
            "`list_mitigations` to browse the project's threat model; "
            "`get_threat` and `get_mitigation` to drill into one item; "
            "`list_elements` for architectural elements from "
            "knowledge.yaml; `latest_run` for the most recent run record."
        ),
    )

    @mcp.tool()
    def list_threats() -> list[dict[str, Any]]:
        """List all threats in the project's threats.yaml."""
        return list_threats_impl(loupe_dir)

    @mcp.tool()
    def get_threat(threat_id: str) -> dict[str, Any] | None:
        """Get one threat by ID (e.g., 'T-001'). Returns None if not found."""
        return get_threat_impl(loupe_dir, threat_id)

    @mcp.tool()
    def list_mitigations() -> list[dict[str, Any]]:
        """List all mitigations in the project's mitigations.yaml."""
        return list_mitigations_impl(loupe_dir)

    @mcp.tool()
    def get_mitigation(mitigation_id: str) -> dict[str, Any] | None:
        """Get one mitigation by ID (e.g., 'M-005'). Returns None if not found."""
        return get_mitigation_impl(loupe_dir, mitigation_id)

    @mcp.tool()
    def list_elements() -> list[dict[str, Any]]:
        """List architectural elements from the project's knowledge.yaml."""
        return list_elements_impl(loupe_dir)

    @mcp.tool()
    def latest_run() -> dict[str, Any] | None:
        """Get the most recent run record. Returns None if no runs exist yet."""
        return latest_run_impl(loupe_dir)

    return mcp
