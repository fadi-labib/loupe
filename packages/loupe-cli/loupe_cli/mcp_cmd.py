"""`loupe mcp` — Model Context Protocol server frontend.

Launches the MCP server defined in `loupe_core.mcp_server`. Two
transports:

- ``stdio`` (the default). Process-local — clients (Claude Code, Cursor,
  custom IDE plugins) attach by spawning ``loupe mcp`` and communicating
  over its stdin/stdout. No network port, no auth.
- ``sse``. Opt-in remote transport over HTTP. Per [D-09] / [D-28], this
  requires a bearer token (``--token`` or ``LOUPE_MCP_TOKEN``) — the
  server refuses to start without one rather than falling back to an
  unauthenticated listener.

Per [D-09], no extra enforcement work here beyond the transport-level
auth above — the server only exposes read-only tools by default. Writes
still flow through the existing Layer 1 path boundary in ``loupe ci``
and ``loupe chat``. When writes land in v1.x, they reuse the same
`PathBoundary` + `confirm_with_diff` machinery so MCP clients are
subject to the same gates as the local CLI.
"""

from __future__ import annotations

from pathlib import Path

import typer
from loupe_core.config import load_config
from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.lens_registry import discover_lenses
from loupe_core.mcp_server import build_mcp_server
from pydantic import ValidationError

from loupe_cli.mcp_transport import StaticTokenVerifier, build_auth_settings, resolve_token

# BSD sysexits.h EX_USAGE — operator-config / usage errors.
USAGE_ERROR = 64

_VALID_TRANSPORTS = ("stdio", "sse")


def mcp_command(
    loupe_dir: Path,
    *,
    transport: str = "stdio",
    host: str = "127.0.0.1",
    port: int = 8000,
    token: str | None = None,
) -> int:
    """Build and run the MCP server bound to ``loupe_dir``.

    Discovers installed lenses so each can contribute domain-specific
    tools to the same server (e.g., ThreatLens adds
    ``threatlens.query_by_stride``). Lens registration runs at server-
    build time, before the first MCP request arrives.

    Returns the exit code. Under normal operation the server runs until
    the client disconnects (closes stdin); we return 0 in that case.
    Returns 64 (sysexits.h EX_USAGE) when ``loupe_dir`` doesn't exist,
    ``transport`` is unrecognized, or ``transport="sse"`` has no token
    resolved from either ``token`` or ``LOUPE_MCP_TOKEN`` — all checked
    before any lens discovery, config load, or server construction so a
    misconfigured invocation never gets close to binding a socket.
    """
    if transport not in _VALID_TRANSPORTS:
        typer.echo(
            f"Error: --transport must be one of {_VALID_TRANSPORTS}, got {transport!r}.",
            err=True,
        )
        return USAGE_ERROR

    resolved_token: str | None = None
    if transport == "sse":
        resolved_token = resolve_token(token)
        if resolved_token is None:
            typer.echo(
                "Error: --transport sse requires a bearer token. Pass --token or "
                "set LOUPE_MCP_TOKEN. The remote transport refuses to start "
                "unauthenticated.",
                err=True,
            )
            return USAGE_ERROR

    if not loupe_dir.exists():
        typer.echo(
            f"Error: {loupe_dir} not found. Run `loupe init` first or pass --loupe-dir.",
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
            boundary = PathBoundary(
                writable_globs=cfg.agent_writable_paths,
                project_root=loupe_dir.parent.resolve(),
            )
        except (ValidationError, OSError) as exc:
            # Narrow catch: schema-validation failures (pydantic) or I/O
            # errors (file vanished, permission denied, encoding glitch).
            # Project has no dedicated `ConfigError` yet; widen this tuple
            # if one is introduced. Everything else (programming bugs,
            # KeyboardInterrupt, etc.) propagates so we don't silently
            # mask real defects behind a "MCP write tools disabled" line.
            typer.echo(
                f"warning: could not load {config_path} ({exc}); MCP write tools disabled.",
                err=True,
            )
    if transport == "sse":
        assert resolved_token is not None  # checked above; narrows for mypy
        server = build_mcp_server(
            loupe_dir,
            lenses=lenses,
            boundary=boundary,
            token_verifier=StaticTokenVerifier(resolved_token),
            auth_settings=build_auth_settings(host, port),
        )
        server.settings.host = host
        server.settings.port = port
        if host not in ("127.0.0.1", "localhost", "::1"):
            # The SDK's DNS-rebinding protection auto-enables only for
            # loopback hosts. A non-loopback --host is explicit operator
            # opt-in to remote reachability (D-09) — widen the allow-list
            # rather than leaving it half-on, which would otherwise 421
            # legitimate remote requests. The bearer token, not the host
            # allow-list, is the real defense once this is widened.
            from mcp.server.transport_security import TransportSecuritySettings

            server.settings.transport_security = TransportSecuritySettings(
                allowed_hosts=["*"], allowed_origins=["*"]
            )
    else:
        server = build_mcp_server(loupe_dir, lenses=lenses, boundary=boundary)
    # FastMCP.run() defaults to stdio transport — exactly what MCP clients
    # spawn-and-pipe expect. KeyboardInterrupt during stdio read is a
    # clean shutdown (Ctrl-C from a TTY-attached client); other unexpected
    # exceptions surface a one-line summary and exit 1 so MCP clients see
    # a real error code instead of a raw traceback.
    try:
        server.run(transport=transport)  # type: ignore[arg-type]
    except KeyboardInterrupt:
        typer.echo("loupe mcp: clean shutdown", err=True)
        return 0
    except Exception as exc:
        typer.echo(f"loupe mcp: {exc}", err=True)
        return 1
    return 0
