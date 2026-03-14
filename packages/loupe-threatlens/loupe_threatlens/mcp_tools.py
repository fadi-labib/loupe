"""ThreatLens-specific MCP tool implementations.

Tools registered here let MCP clients (Claude Code, Cursor, custom
IDE plugins) ask ThreatLens-specific questions that aren't covered by
the generic `loupe.list_threats` / `loupe.get_threat` tools in
loupe_core.mcp_server.

Read tools (always registered):
- `threatlens_query_by_stride` — filter by STRIDE category letter
- `threatlens_query_by_severity` — filter by severity level
- `threatlens_summary` — aggregate counts

Write tools (registered only when a PathBoundary is provided):
- `threatlens_propose_threat` — append to threats.yaml via Layer 1
- `threatlens_propose_mitigation` — append to mitigations.yaml via Layer 1

Writes use the same `write_agent_artifact` path the in-process agent
uses, so the Layer 1 PathBoundary still gates them. An MCP client
attempting to write to a protected path (one absent from
`agent_writable_paths`) gets a BoundaryViolation, surfaced over the
JSON-RPC tool-call error channel.

Pattern: each read tool is a separate plain function for testability
(`*_impl`), then `register_threatlens_mcp_tools` decorates a closure
over `loupe_dir` and (when present) `boundary`, registering it with
the FastMCP server. The split mirrors `loupe_core.mcp_server` so the
tools can be unit-tested without spinning up the server.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Literal

from loupe_core.artifacts.threat import ThreatsFile
from loupe_core.enforcement.path_boundary import PathBoundary

from loupe_threatlens.tools import (
    ProposeMitigationInput,
    ProposeThreatInput,
    write_mitigation_directly,
    write_threat_directly,
)

# Single source of truth for the literal STRIDE category letters. The
# Literal type is used directly in the MCP tool signature so FastMCP can
# render the constraint into the input schema clients see.
StrideLetter = Literal["S", "T", "R", "I", "D", "E"]


def query_threats_by_stride_impl(
    loupe_dir: Path, stride_category: str,
) -> list[dict[str, Any]]:
    """Return threats whose `stride_category` matches.

    Comparison is case-sensitive on the single letter; clients should
    pass uppercase per the STRIDE convention.
    """
    threats_path = loupe_dir / "threats.yaml"
    if not threats_path.exists():
        return []
    threats = ThreatsFile.load(threats_path).threats
    matching = [t for t in threats if t.stride_category.value == stride_category]
    return [t.model_dump(mode="json") for t in matching]


def query_threats_by_severity_impl(
    loupe_dir: Path, severity: str,
) -> list[dict[str, Any]]:
    """Return threats at exactly the given severity level."""
    threats_path = loupe_dir / "threats.yaml"
    if not threats_path.exists():
        return []
    threats = ThreatsFile.load(threats_path).threats
    matching = [t for t in threats if t.severity.value == severity]
    return [t.model_dump(mode="json") for t in matching]


def threat_model_summary_impl(loupe_dir: Path) -> dict[str, Any]:
    """Return aggregate counts: total, by severity, by STRIDE, by status."""
    threats_path = loupe_dir / "threats.yaml"
    if not threats_path.exists():
        return {
            "total": 0,
            "by_severity": {},
            "by_stride": {},
            "by_status": {},
        }
    threats = ThreatsFile.load(threats_path).threats
    return {
        "total": len(threats),
        "by_severity": dict(Counter(t.severity.value for t in threats)),
        "by_stride": dict(Counter(t.stride_category.value for t in threats)),
        "by_status": dict(Counter(t.status.value for t in threats)),
    }


def register_threatlens_mcp_tools(
    server: Any,
    loupe_dir: Path,
    *,
    boundary: PathBoundary | None = None,
) -> None:
    """Register ThreatLens-specific tools with the given FastMCP server.

    Called by `ThreatLens.register_to_mcp(server, loupe_dir, boundary=...)`
    once the server has been built. Each closure captures `loupe_dir`
    (and `boundary` for write tools) so the handlers don't need MCP
    clients to pass them on every call.

    Read tools are always registered. Write tools (propose_threat,
    propose_mitigation) are only registered when a ``boundary`` is
    provided — read-only mode (e.g., in unit tests that don't construct
    a boundary) gets a strictly read-only surface.

    The `server` parameter is typed `Any` because lens packages should
    not take a hard import on the MCP SDK — the choice of framework is
    made once in `loupe-core` per D-21. At runtime `server` is an
    `mcp.server.fastmcp.FastMCP` instance; the `.tool()` method works
    polymorphically over either the official or any compatible API.
    """
    @server.tool()
    def threatlens_query_by_stride(stride_category: StrideLetter) -> list[dict[str, Any]]:
        """Filter threats by STRIDE category letter (S, T, R, I, D, E).

        S=Spoofing, T=Tampering, R=Repudiation, I=Information disclosure,
        D=Denial of service, E=Elevation of privilege.
        """
        return query_threats_by_stride_impl(loupe_dir, stride_category)

    @server.tool()
    def threatlens_query_by_severity(
        severity: Literal["critical", "high", "medium", "low", "informational"],
    ) -> list[dict[str, Any]]:
        """Filter threats by severity level."""
        return query_threats_by_severity_impl(loupe_dir, severity)

    @server.tool()
    def threatlens_summary() -> dict[str, Any]:
        """Aggregate threat-model summary: total + counts by severity / STRIDE / status."""
        return threat_model_summary_impl(loupe_dir)

    if boundary is None:
        return  # Read-only mode — skip the write-tool registrations.

    @server.tool()
    def threatlens_propose_threat(
        element_id: str,
        stride_category: StrideLetter,
        title: str,
        description: str,
        severity: Literal["low", "medium", "high", "critical"],
        rationale: str,
        cwe_refs: list[str] | None = None,
        mitigation_ids: list[str] | None = None,
    ) -> dict[str, str]:
        """Propose a new threat. Writes to threats.yaml via Layer 1 PathBoundary.

        Raises BoundaryViolation (surfaced over MCP as a tool error) if
        threats.yaml is not in the operator's `agent_writable_paths`.
        Cite an architectural element from the project's knowledge.yaml
        in `element_id` (e.g., 'E-001'); the threat fails validation if
        the element_id format is invalid.
        """
        threat_input = ProposeThreatInput(
            element_id=element_id,
            stride_category=stride_category,
            title=title,
            description=description,
            severity=severity,
            rationale=rationale,
            cwe_refs=cwe_refs or [],
            mitigation_ids=mitigation_ids or [],
        )
        threat_id = write_threat_directly(
            loupe_dir, boundary,
            threat_input, proposed_by="mcp/client",
        )
        return {"threat_id": threat_id, "status": "written"}

    @server.tool()
    def threatlens_propose_mitigation(
        title: str,
        description: str,
        threats_addressed: list[str] | None = None,
        status: Literal["proposed", "planned", "implemented", "verified", "retired"] = (
            "proposed"
        ),
        evidence_kind: Literal["code", "doc", "test", "config", "external"] | None = None,
        evidence_location: str | None = None,
    ) -> dict[str, str]:
        """Propose a new mitigation. Writes to mitigations.yaml via Layer 1.

        Cite the threats this mitigation addresses by ID in
        `threats_addressed` (e.g., ['T-001']). Optionally attach a
        single evidence pointer; richer evidence editing happens
        through human review of the YAML.
        """
        mit_input = ProposeMitigationInput(
            title=title,
            description=description,
            threats_addressed=threats_addressed or [],
            status=status,
            evidence_kind=evidence_kind,
            evidence_location=evidence_location,
        )
        mitigation_id = write_mitigation_directly(loupe_dir, boundary, mit_input)
        return {"mitigation_id": mitigation_id, "status": "written"}
