"""End-to-end auth contract for `loupe mcp --transport sse`.

Spawns a real uvicorn server bound to a loopback port (not
`httpx.ASGITransport` in-process — that hangs on the success path for
this SDK's SSE app, since the anyio task that streams events doesn't
get scheduled the same way under the mock transport) and drives it with
a real `httpx.Client` over a real socket. This is also the more
faithful test: a remote MCP client connects exactly this way.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import uvicorn
from loupe_cli.mcp_transport import StaticTokenVerifier, build_auth_settings
from loupe_core.mcp_server import build_mcp_server

_TOKEN = "test-secret-token"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def sse_server_url(tmp_path: Path) -> Iterator[str]:
    """Start a real SSE-transport `loupe` MCP server on a loopback port."""
    loupe_dir = tmp_path / ".loupe"
    loupe_dir.mkdir()
    port = _free_port()
    host = "127.0.0.1"

    server = build_mcp_server(
        loupe_dir,
        token_verifier=StaticTokenVerifier(_TOKEN),
        auth_settings=build_auth_settings(host, port),
    )
    server.settings.host = host
    server.settings.port = port
    app = server.sse_app()
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    uv_server = uvicorn.Server(config)

    thread = threading.Thread(target=uv_server.run, daemon=True)
    thread.start()
    # Poll instead of a fixed sleep: bind+startup time varies under load.
    deadline = time.monotonic() + 5.0
    while not uv_server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert uv_server.started, "uvicorn did not report startup within 5s"

    try:
        yield f"http://{host}:{port}"
    finally:
        uv_server.should_exit = True
        thread.join(timeout=5.0)


def test_sse_rejects_missing_authorization_header(sse_server_url: str):
    with httpx.Client(timeout=3.0) as client:
        response = client.get(f"{sse_server_url}/sse")
    assert response.status_code == 401


def test_sse_rejects_wrong_token(sse_server_url: str):
    with httpx.Client(timeout=3.0) as client:
        response = client.get(
            f"{sse_server_url}/sse", headers={"Authorization": "Bearer wrong-token"}
        )
    assert response.status_code == 401


def test_sse_accepts_correct_token(sse_server_url: str):
    with (
        httpx.Client(timeout=3.0) as client,
        client.stream(
            "GET",
            f"{sse_server_url}/sse",
            headers={"Authorization": f"Bearer {_TOKEN}"},
        ) as response,
    ):
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
