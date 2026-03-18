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
from loupe_core.config import load_config
from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.lens_registry import discover_lenses
from loupe_core.mcp_server import build_mcp_server

# BSD sysexits.h EX_USAGE — operator-config / usage errors.
USAGE_ERROR = 64


def mcp_command(loupe_dir: Path) -> int:
    """Build and run the MCP server bound to ``loupe_dir``.

    Discovers installed lenses so each can contribute domain-specific
    tools to the same server (e.g., ThreatLens adds
    ``threatlens.query_by_stride``). Lens registration runs at server-
    build time, before the first MCP request arrives.

    Returns the exit code. Under normal operation the server runs until
    the client disconnects (closes stdin); we return 0 in that case.
    Returns 64 (sysexits.h EX_USAGE) when ``loupe_dir`` doesn't exist,
    matching the convention used by ``loupe ci`` / ``loupe verify``.
    """
    if not loupe_dir.exists():
        typer.echo(
            f"Error: {loupe_dir} not found. Run `loupe init` first or pass "
            f"--loupe-dir.",
            err=True,
        )
        return USAGE_ERROR

    lenses = discover_lenses()
    # Load the operator's config so the same agent_writable_paths allow-list
    # that gates loupe ci also gates MCP write tools. A missing config_yaml
    # falls back to a no-write surface — strictly read-only, which is the
    # safer default if config is broken.
    config_path = loupe_dir / "config.yaml"
    boundary: PathBoundary | None = None
    if config_path.exists():
        try:
            cfg = load_config(config_path)
            boundary = PathBoundary(writable_globs=cfg.agent_writable_paths)
        except Exception as exc:  # pragma: no cover — defensive
            typer.echo(
                f"warning: could not load {config_path} ({exc}); "
                f"MCP write tools disabled.",
                err=True,
            )
    server = build_mcp_server(loupe_dir, lenses=lenses, boundary=boundary)
    # FastMCP.run() defaults to stdio transport — exactly what MCP clients
    # spawn-and-pipe expect. Errors during run propagate to the caller; a
    # clean client disconnect returns normally.
    server.run()
    return 0
