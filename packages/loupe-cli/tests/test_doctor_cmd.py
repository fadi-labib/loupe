"""Tests for `loupe doctor` — preflight diagnostics.

The doctor command is the new operator entry point for "is my Loupe
install ready to run". We pin the contract for each check:
- absence of .loupe/ → exit 64
- missing API key for `models.default` → exit 64
- missing capability binary → exit 64
- everything green → exit 0

Warnings (unknown provider, no capabilities configured) DO NOT change
the exit code — they're advisory.
"""

from __future__ import annotations

from pathlib import Path

from loupe_cli.__main__ import app
from typer.testing import CliRunner

from .conftest import minimal_config_yaml

runner = CliRunner()


def _make_loupe_dir(tmp_path: Path, *, context_filled: bool = True) -> Path:
    """Build a minimal .loupe/ that doctor can parse.

    `context_filled=True` swaps the scaffold TODO markers for real
    text so the context.md check passes by default; individual tests
    can build a different shape inline.
    """
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    (loupe / "config.yaml").write_text(minimal_config_yaml())
    if context_filled:
        (loupe / "context.md").write_text(
            "# Product Context\n\n## Product description\nA test product.\n"
        )
    return loupe


def test_doctor_fails_when_loupe_dir_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 64, result.stdout
    assert "loupe init" in result.stdout


def test_doctor_fails_when_api_key_missing(tmp_path, monkeypatch):
    """Default config has `models.default: anthropic:claude-opus-4-7` →
    requires ANTHROPIC_API_KEY. Doctor must fail when it's absent."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _make_loupe_dir(tmp_path)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 64, result.stdout
    assert "ANTHROPIC_API_KEY" in result.stdout
    assert "[✗]" in result.stdout


def test_doctor_passes_with_api_key_and_filled_context(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-123")
    _make_loupe_dir(tmp_path)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.stdout
    assert "[✓]" in result.stdout


def test_doctor_fails_when_context_md_has_many_todos(tmp_path, monkeypatch):
    """An unedited scaffold has ~6 TODO: markers — doctor must flag that
    state so users know to fill in context.md before paying for an
    LLM call that grounds on hallucinated product context."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-123")
    loupe = _make_loupe_dir(tmp_path, context_filled=False)
    # Write a scaffold-shape context.md with several TODOs.
    (loupe / "context.md").write_text(
        "## Product description\nTODO: describe\n\n"
        "## Critical assets\nTODO: list\n\n"
        "## Users\nTODO: list\n\n"
        "## Deployment\nTODO: describe\n"
    )
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 64, result.stdout
    assert "context.md" in result.stdout
    assert "TODO" in result.stdout


def test_doctor_warns_for_unknown_provider_without_failing(tmp_path, monkeypatch):
    """An unrecognized provider (one the env-var table doesn't know about)
    must produce a `[?]` warning row but NOT change the exit code."""
    monkeypatch.chdir(tmp_path)
    loupe = _make_loupe_dir(tmp_path)
    # Override the default model with an unrecognized provider.
    loupe_cfg = (
        "schema_version: 1\n"
        "models:\n  default: futurelab:experimental-v0\n"
        "limits:\n"
        "  per_run_max_usd: 1.0\n"
        "  per_run_max_tokens_in: 100000\n"
        "  per_run_max_steps: 5\n"
        "agent_writable_paths: [.loupe/threats.yaml]\n"
        "lenses:\n  threatlens:\n    enabled: true\n    minimum_relevance: 0.3\n"
    )
    (loupe / "config.yaml").write_text(loupe_cfg)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.stdout
    assert "[?]" in result.stdout
    assert "unknown provider" in result.stdout


def test_doctor_passes_for_ollama_without_key(tmp_path, monkeypatch):
    """Ollama runs locally and needs no API key. Doctor must recognise
    this so a local-only install doesn't trip on a missing env var."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    loupe = _make_loupe_dir(tmp_path)
    loupe_cfg = (
        "schema_version: 1\n"
        "models:\n  default: ollama:llama-3.3-70b\n"
        "limits:\n"
        "  per_run_max_usd: 1.0\n"
        "  per_run_max_tokens_in: 100000\n"
        "  per_run_max_steps: 5\n"
        "agent_writable_paths: [.loupe/threats.yaml]\n"
        "lenses:\n  threatlens:\n    enabled: true\n    minimum_relevance: 0.3\n"
    )
    (loupe / "config.yaml").write_text(loupe_cfg)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.stdout
    assert "local provider" in result.stdout


def test_doctor_fails_when_capability_binary_missing(tmp_path, monkeypatch):
    """If config.yaml wires a backend whose CLI binary isn't on PATH,
    doctor must catch it before `loupe ci` does — the whole point of
    a preflight check."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-123")
    # shutil.which returns None for everything to simulate empty PATH.
    monkeypatch.setattr("loupe_cli.doctor_cmd.shutil.which", lambda _: None)
    loupe = _make_loupe_dir(tmp_path)
    loupe_cfg = (
        "schema_version: 1\n"
        "models:\n  default: anthropic:claude-opus-4-7\n"
        "limits:\n"
        "  per_run_max_usd: 1.0\n"
        "  per_run_max_tokens_in: 100000\n"
        "  per_run_max_steps: 5\n"
        "agent_writable_paths: [.loupe/threats.yaml]\n"
        "lenses:\n  threatlens:\n    enabled: true\n    minimum_relevance: 0.3\n"
        "capabilities:\n  sbom:\n    mode: single\n    backends: [syft]\n"
    )
    (loupe / "config.yaml").write_text(loupe_cfg)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 64, result.stdout
    assert "syft" in result.stdout
    assert "not on PATH" in result.stdout
