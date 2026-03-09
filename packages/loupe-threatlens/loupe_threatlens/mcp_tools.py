"""ThreatLens-specific MCP tool implementations.

Tools registered here let MCP clients (Claude Code, Cursor, custom
IDE plugins) ask ThreatLens-specific questions that aren't covered by
the generic `loupe.list_threats` / `loupe.get_threat` tools in
loupe_core.mcp_server. Examples: filter by STRIDE category, summarise
the threat model as text, count threats by severity.

Read-only at v1. Write tools (e.g., "transition this threat to
mitigated") wait until the cross-frontend Layer-1 / Layer-4 contract
for MCP-driven writes is hardened — same gate the loupe chat REPL
goes through.

Pattern: each tool is a separate plain function for testability
(`*_impl`), then `register_threatlens_mcp_tools` decorates a closure
over `loupe_dir` and registers it with the FastMCP server. The split
mirrors `loupe_core.mcp_server` so the tools can be unit-tested
without spinning up the server.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Literal

from loupe_core.artifacts.threat import ThreatsFile

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


def register_threatlens_mcp_tools(server: Any, loupe_dir: Path) -> None:
    """Register ThreatLens-specific tools with the given FastMCP server.

    Called by `ThreatLens.register_to_mcp(server, loupe_dir)` once the
    server has been built. Each closure captures `loupe_dir` so the
    handlers don't need MCP clients to pass it on every call.

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
