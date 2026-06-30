"""Unit-level tests for `loupe mcp` error handling.

End-to-end MCP behavior is covered by test_mcp_handshake.py (spawns the
real subprocess and walks the MCP protocol). These tests pin the smaller
contracts the CLI guarantees around server lifecycle:

- Missing loupe_dir returns 64 (sysexits.h EX_USAGE).
- A broken config.yaml falls back to read-only with a warning, NOT a
  silent swallow — but only for ValidationError / OSError, not arbitrary
  Exception (programming bugs must still surface).
- KeyboardInterrupt during server.run() is a clean shutdown -> 0.
- Other server.run() exceptions surface a one-line summary -> 1.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from loupe_cli.mcp_cmd import mcp_command


def test_mcp_returns_64_when_loupe_dir_missing(tmp_path: Path, capsys):
    """Missing .loupe/ → 64 with a helpful 'loupe init' pointer."""
    code = mcp_command(tmp_path / "does-not-exist")
    assert code == 64
    err = capsys.readouterr().err
    assert "not found" in err.lower()


def test_mcp_keyboard_interrupt_returns_zero(tmp_path: Path, monkeypatch, capsys):
    """Ctrl-C from a TTY-attached MCP client is a clean shutdown -> 0."""
    loupe = tmp_path / ".loupe"
    loupe.mkdir()

    server = MagicMock()
    server.run.side_effect = KeyboardInterrupt
    monkeypatch.setattr(
        "loupe_cli.mcp_cmd.build_mcp_server",
        lambda loupe_dir, lenses, boundary: server,
    )
    monkeypatch.setattr("loupe_cli.mcp_cmd.discover_lenses", lambda: [])

    code = mcp_command(loupe)
    assert code == 0
    err = capsys.readouterr().err
    assert "clean shutdown" in err.lower()


def test_mcp_unexpected_exception_returns_one(tmp_path: Path, monkeypatch, capsys):
    """A non-KeyboardInterrupt error from server.run() surfaces and exits 1."""
    loupe = tmp_path / ".loupe"
    loupe.mkdir()

    server = MagicMock()
    server.run.side_effect = RuntimeError("transport pipe broke")
    monkeypatch.setattr(
        "loupe_cli.mcp_cmd.build_mcp_server",
        lambda loupe_dir, lenses, boundary: server,
    )
    monkeypatch.setattr("loupe_cli.mcp_cmd.discover_lenses", lambda: [])

    code = mcp_command(loupe)
    assert code == 1
    err = capsys.readouterr().err
    assert "transport pipe broke" in err
    assert "loupe mcp:" in err


def test_mcp_invalid_config_falls_back_to_readonly(tmp_path: Path, monkeypatch, capsys):
    """A malformed config.yaml warns and disables the boundary, NOT crashes."""
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    # schema_version: 1 missing required fields → ValidationError on load.
    (loupe / "config.yaml").write_text("schema_version: 'not-an-int'\n")

    captured: dict[str, object] = {}

    def _fake_build(loupe_dir, lenses, boundary):  # noqa: ANN001
        captured["boundary"] = boundary
        s = MagicMock()
        s.run.return_value = None
        return s

    monkeypatch.setattr("loupe_cli.mcp_cmd.build_mcp_server", _fake_build)
    monkeypatch.setattr("loupe_cli.mcp_cmd.discover_lenses", lambda: [])

    code = mcp_command(loupe)
    assert code == 0
    assert captured["boundary"] is None
    err = capsys.readouterr().err
    assert "could not load" in err.lower()


def test_mcp_does_not_swallow_programming_bugs(tmp_path: Path, monkeypatch):
    """An unrelated bug raised by load_config (NOT Validation/OS) must propagate."""
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    (loupe / "config.yaml").write_text("ignored: true\n")

    def _bug(_path):
        raise AttributeError("simulated programming bug deep in config")

    monkeypatch.setattr("loupe_cli.mcp_cmd.load_config", _bug)
    monkeypatch.setattr("loupe_cli.mcp_cmd.discover_lenses", lambda: [])

    with pytest.raises(AttributeError, match="simulated programming bug"):
        mcp_command(loupe)


def test_mcp_stdio_default_unaffected(tmp_path: Path, monkeypatch):
    """Calling with no transport-related kwargs at all must behave byte-identical
    to the pre-SSE contract — same build_mcp_server call shape, same server.run()."""
    loupe = tmp_path / ".loupe"
    loupe.mkdir()

    captured: dict[str, object] = {}

    def _fake_build(loupe_dir, lenses, boundary):  # noqa: ANN001
        captured["build_kwargs_only"] = True
        s = MagicMock()
        s.run.return_value = None
        return s

    monkeypatch.setattr("loupe_cli.mcp_cmd.build_mcp_server", _fake_build)
    monkeypatch.setattr("loupe_cli.mcp_cmd.discover_lenses", lambda: [])

    code = mcp_command(loupe)
    assert code == 0
    assert captured["build_kwargs_only"] is True


def test_mcp_sse_without_token_fails_fast(tmp_path: Path, monkeypatch, capsys):
    """--transport sse with no token anywhere -> 64, and build_mcp_server is
    never called (proves the check happens before any server construction)."""
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    monkeypatch.delenv("LOUPE_MCP_TOKEN", raising=False)

    build_called = MagicMock()
    monkeypatch.setattr("loupe_cli.mcp_cmd.build_mcp_server", build_called)
    monkeypatch.setattr("loupe_cli.mcp_cmd.discover_lenses", lambda: [])

    code = mcp_command(loupe, transport="sse")
    assert code == 64
    build_called.assert_not_called()
    err = capsys.readouterr().err
    assert "token" in err.lower()


def test_mcp_sse_token_from_env_var(tmp_path: Path, monkeypatch):
    """No --token flag, LOUPE_MCP_TOKEN set -> the env var is the accepted token."""
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    monkeypatch.setenv("LOUPE_MCP_TOKEN", "env-token")

    captured: dict[str, object] = {}

    def _fake_build(loupe_dir, *, lenses, boundary, token_verifier, auth_settings):  # noqa: ANN001
        captured["verifier"] = token_verifier
        s = MagicMock()
        s.run.return_value = None
        return s

    monkeypatch.setattr("loupe_cli.mcp_cmd.build_mcp_server", _fake_build)
    monkeypatch.setattr("loupe_cli.mcp_cmd.discover_lenses", lambda: [])

    code = mcp_command(loupe, transport="sse")
    assert code == 0
    verifier = captured["verifier"]
    assert hasattr(verifier, "_token")
    assert verifier._token == "env-token"  # noqa: SLF001


def test_mcp_token_flag_overrides_env(tmp_path: Path, monkeypatch):
    """Both --token and LOUPE_MCP_TOKEN set -> the flag wins."""
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    monkeypatch.setenv("LOUPE_MCP_TOKEN", "env-token")

    captured: dict[str, object] = {}

    def _fake_build(loupe_dir, *, lenses, boundary, token_verifier, auth_settings):  # noqa: ANN001
        captured["verifier"] = token_verifier
        s = MagicMock()
        s.run.return_value = None
        return s

    monkeypatch.setattr("loupe_cli.mcp_cmd.build_mcp_server", _fake_build)
    monkeypatch.setattr("loupe_cli.mcp_cmd.discover_lenses", lambda: [])

    code = mcp_command(loupe, transport="sse", token="flag-token")
    assert code == 0
    verifier = captured["verifier"]
    assert verifier._token == "flag-token"  # noqa: SLF001


def test_mcp_invalid_transport_value(tmp_path: Path, monkeypatch, capsys):
    """An unrecognized --transport value -> 64, before touching loupe_dir at all."""
    build_called = MagicMock()
    monkeypatch.setattr("loupe_cli.mcp_cmd.build_mcp_server", build_called)

    code = mcp_command(tmp_path / "does-not-exist", transport="carrier-pigeon")
    assert code == 64
    build_called.assert_not_called()
    err = capsys.readouterr().err
    assert "--transport" in err
