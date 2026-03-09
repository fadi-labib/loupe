"""`loupe mcp` — Model Context Protocol server frontend.

Launches the MCP server defined in `loupe_core.mcp_server` over stdio
transport (the default for MCP). Clients (Claude Code, Cursor, custom
IDE plugins) attach by spawning ``loupe mcp`` and communicating over
its stdin/stdout.

Per [D-09], no extra enforcement work here — the server only exposes
read-only tools. Writes still flow through the existing Layer 1 path
boundary in ``loupe ci`` and ``loupe chat``. When writes land in v1.x,
they reuse the same `PathBoundary` + `confirm_with_diff` machinery so
MCP clients are subject to the same gates as the local CLI.
"""
from __future__ import annotations

from pathlib import Path

import typer
from loupe_core.lens_registry import discover_lenses
from loupe_core.mcp_server import build_mcp_server


def mcp_command(loupe_dir: Path) -> int:
    """Build and run the MCP server bound to ``loupe_dir``.

    Discovers installed lenses so each can contribute domain-specific
    tools to the same server (e.g., ThreatLens adds
    ``threatlens.query_by_stride``). Lens registration runs at server-
    build time, before the first MCP request arrives.

    Returns the exit code. Under normal operation the server runs until
    the client disconnects (closes stdin); we return 0 in that case.
    Returns 2 when ``loupe_dir`` doesn't exist, matching the convention
    used by ``loupe ci`` / ``loupe verify``.
    """
    if not loupe_dir.exists():
        typer.echo(
            f"Error: {loupe_dir} not found. Run `loupe init` first or pass "
            f"--loupe-dir.",
            err=True,
        )
        return 2

    lenses = discover_lenses()
    server = build_mcp_server(loupe_dir, lenses=lenses)
    # FastMCP.run() defaults to stdio transport — exactly what MCP clients
    # spawn-and-pipe expect. Errors during run propagate to the caller; a
    # clean client disconnect returns normally.
    server.run()
    return 0
