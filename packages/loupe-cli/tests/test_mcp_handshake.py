"""End-to-end MCP handshake against `loupe mcp`.

Spawns the actual `loupe mcp --loupe-dir <tmp>` subprocess, walks the
full MCP handshake using the official `mcp` SDK's stdio client, lists
tools, calls one, and asserts the response shape. Hermetic: no
network, no LLM, no third-party services. The test exercises the
protocol-level contract `loupe mcp` exposes to any MCP client (Claude
Code, Cursor, custom IDE plugins).

Why not VCR-style cassettes here: MCP traffic is local stdio with
strict newline-delimited JSON-RPC framing. The cost of recording vs.
re-running is identical; running for real also validates the SDK
version we ship against still likes our payloads. If MCP ever moves
to HTTP transport for some flow, that flow would benefit from
cassette-style recording — until then, the subprocess pattern is
strictly better.
"""

from __future__ import annotations

import shutil
from datetime import date
from pathlib import Path

import pytest
from loupe_core.artifacts.threat import Threat, ThreatsFile
from loupe_core.artifacts.types import (
    Severity,
    StrideCategory,
    ThreatStatus,
)
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

_INIT_CONFIG = """\
schema_version: 1
agent_writable_paths:
  - .loupe/threats.yaml
  - .loupe/mitigations.yaml
lenses:
  threatlens:
    enabled: true
"""


def _loupe_executable() -> str:
    """Locate the installed `loupe` script.

    The workspace's `uv sync --all-packages` installs it under .venv/bin.
    Test skips cleanly when the binary isn't found (e.g., someone runs
    `pytest` against an installed wheel without dev sync).
    """
    found = shutil.which("loupe")
    if found is None:
        pytest.skip("`loupe` not on PATH; run `uv sync --all-packages` first")
    return found


def _make_loupe_dir(root: Path, *, write_config: bool = False) -> Path:
    """Build a minimal .loupe/ for the handshake tests.

    When ``write_config=True``, also writes a config.yaml that lists
    threats.yaml + mitigations.yaml as agent-writable. With a config
    present, `loupe mcp` constructs a PathBoundary at startup and the
    write tools register.
    """
    loupe = root / ".loupe"
    loupe.mkdir()
    (loupe / "runs").mkdir()
    ThreatsFile(
        threats=[
            Threat(
                id="T-001",
                element_id="E-001",
                stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                title="Sample handshake threat",
                description="Used by the MCP handshake test fixture.",
                severity=Severity.HIGH,
                status=ThreatStatus.PROPOSED,
                mitigation_ids=[],
                cwe_refs=[],
                introduced_in_pr=None,
                last_reviewed=date(2026, 5, 15),
                rationale="Test data.",
                proposed_by="test",
            ),
        ]
    ).save(loupe / "threats.yaml")
    if write_config:
        # Use the same project-root-relative globs that `loupe init`
        # scaffolds. `loupe mcp` constructs a PathBoundary with
        # `project_root=loupe_dir.parent.resolve()`, so the absolute
        # write targets the lens produces are relativised before the
        # glob comparison. No absolute-rewriting workaround needed.
        (loupe / "config.yaml").write_text(_INIT_CONFIG)
    return loupe


@pytest.mark.asyncio
async def test_mcp_handshake_initialises_and_lists_tools(tmp_path: Path):
    """`loupe mcp` accepts initialize and exposes its read-only tools.

    The full contract here:
    1. The subprocess starts cleanly within ~2s
    2. MCP `initialize` returns server info (`name == "loupe"`)
    3. `tools/list` includes every read-only tool defined in build_mcp_server
       plus the three ThreatLens-contributed tools
    4. The session closes cleanly on context exit (no zombie processes)
    """
    loupe_path = _make_loupe_dir(tmp_path)
    params = StdioServerParameters(
        command=_loupe_executable(),
        args=["mcp", "--loupe-dir", str(loupe_path)],
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init_result = await session.initialize()
            assert init_result.serverInfo.name == "loupe"

            tools = await session.list_tools()
            tool_names = {t.name for t in tools.tools}

            # Core tools registered by build_mcp_server in loupe_core.
            assert "list_threats" in tool_names
            assert "get_threat" in tool_names
            assert "list_mitigations" in tool_names
            assert "get_mitigation" in tool_names
            assert "list_elements" in tool_names
            assert "latest_run" in tool_names

            # Lens-contributed tools from register_to_mcp on ThreatLens.
            assert "threatlens_query_by_stride" in tool_names
            assert "threatlens_query_by_severity" in tool_names
            assert "threatlens_summary" in tool_names


@pytest.mark.asyncio
async def test_mcp_call_list_threats_returns_fixture_data(tmp_path: Path):
    """Invoking `list_threats` over MCP returns the seeded fixture threat."""
    loupe_path = _make_loupe_dir(tmp_path)
    params = StdioServerParameters(
        command=_loupe_executable(),
        args=["mcp", "--loupe-dir", str(loupe_path)],
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("list_threats")

            # MCP tool results come back as content items; FastMCP serialises
            # the Python return value as a structured `text` content block
            # whose body is JSON. We don't need to parse it here — the
            # presence of the seeded threat ID is enough to confirm the
            # round-trip works.
            blob = "".join(getattr(c, "text", "") for c in result.content)
            assert "T-001" in blob
            assert "Sample handshake threat" in blob


@pytest.mark.asyncio
async def test_mcp_call_threatlens_query_by_stride(tmp_path: Path):
    """The lens-contributed `threatlens_query_by_stride` accepts the STRIDE arg."""
    loupe_path = _make_loupe_dir(tmp_path)
    params = StdioServerParameters(
        command=_loupe_executable(),
        args=["mcp", "--loupe-dir", str(loupe_path)],
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # Fixture threat is StrideCategory.ELEVATION_OF_PRIVILEGE which
            # serialises to "E".
            result = await session.call_tool(
                "threatlens_query_by_stride",
                arguments={"stride_category": "E"},
            )
            blob = "".join(getattr(c, "text", "") for c in result.content)
            assert "T-001" in blob


@pytest.mark.asyncio
async def test_mcp_call_threatlens_summary(tmp_path: Path):
    """The summary tool returns aggregate counts that include the fixture."""
    loupe_path = _make_loupe_dir(tmp_path)
    params = StdioServerParameters(
        command=_loupe_executable(),
        args=["mcp", "--loupe-dir", str(loupe_path)],
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("threatlens_summary")
            blob = "".join(getattr(c, "text", "") for c in result.content)
            # Aggregate response should reflect our one seeded high-severity
            # E-category threat.
            assert "high" in blob.lower()
            assert "total" in blob.lower()


@pytest.mark.asyncio
async def test_mcp_write_tools_registered_when_config_present(tmp_path: Path):
    """`loupe mcp` registers write tools when config.yaml lists agent_writable_paths.

    Without a config the surface stays read-only; with one, the
    threatlens_propose_threat and threatlens_propose_mitigation tools
    appear in tools/list.
    """
    loupe_path = _make_loupe_dir(tmp_path, write_config=True)
    params = StdioServerParameters(
        command=_loupe_executable(),
        args=["mcp", "--loupe-dir", str(loupe_path)],
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            tool_names = {t.name for t in tools.tools}
            assert "threatlens_propose_threat" in tool_names
            assert "threatlens_propose_mitigation" in tool_names


@pytest.mark.asyncio
async def test_mcp_propose_threat_writes_to_threats_yaml(tmp_path: Path):
    """Calling propose_threat over MCP appends to threats.yaml via Layer 1."""
    loupe_path = _make_loupe_dir(tmp_path, write_config=True)
    params = StdioServerParameters(
        command=_loupe_executable(),
        args=["mcp", "--loupe-dir", str(loupe_path)],
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "threatlens_propose_threat",
                arguments={
                    "element_id": "E-001",
                    "stride_category": "T",
                    "title": "MCP-proposed tampering risk",
                    "description": "An external MCP client proposed this threat.",
                    "severity": "high",
                    "rationale": "Test rationale.",
                },
            )
            blob = "".join(getattr(c, "text", "") for c in result.content)
            # The response carries the assigned threat_id; the fixture
            # already has T-001, so this one should be T-002.
            assert "T-002" in blob

    # And the threat actually landed on disk via the PathBoundary write.
    threats = ThreatsFile.load(loupe_path / "threats.yaml").threats
    assert len(threats) == 2
    assert threats[1].title == "MCP-proposed tampering risk"
    assert threats[1].proposed_by == "mcp/client"
