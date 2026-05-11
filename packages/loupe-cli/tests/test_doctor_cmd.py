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

import pytest
from loupe_cli.__main__ import app
from typer.testing import CliRunner

from .conftest import minimal_config_yaml

runner = CliRunner()


# Wire two stub capabilities by default so the post-D-23 required-caps
# check passes. Tests that explicitly want to exercise the "unwired" path
# build their own config inline.
_WIRED_CAPS_BLOCK = (
    "capabilities:\n"
    "  sbom:\n    mode: single\n    backends: [syft]\n"
    "  cve:\n    mode: single\n    backends: [grype]\n"
)


@pytest.fixture(autouse=True)
def stub_which(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend every backend binary is on PATH so the happy-path doctor
    tests don't fail on a missing /usr/local/bin/syft. Tests that want
    to exercise the binary-missing path explicitly override `shutil.which`
    inside the test body; per-test monkeypatch precedence wins."""
    monkeypatch.setattr(
        "loupe_cli.doctor_cmd.shutil.which",
        lambda name: f"/usr/local/bin/{name}",
    )


def _make_loupe_dir(tmp_path: Path, *, context_filled: bool = True, wire_caps: bool = True) -> Path:
    """Build a minimal .loupe/ that doctor can parse.

    `context_filled=True` swaps the scaffold TODO markers for real
    text so the context.md check passes by default; individual tests
    can build a different shape inline.

    `wire_caps=True` appends a `capabilities:` block wiring sbom (syft)
    and cve (grype) so the post-D-23 required-caps check passes. Tests
    that need to exercise the unwired path set this to False.
    """
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    cfg = minimal_config_yaml()
    if wire_caps:
        cfg += _WIRED_CAPS_BLOCK
    (loupe / "config.yaml").write_text(cfg)
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
        + _WIRED_CAPS_BLOCK
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
        + _WIRED_CAPS_BLOCK
    )
    (loupe / "config.yaml").write_text(loupe_cfg)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.stdout
    assert "local provider" in result.stdout


def test_doctor_fails_when_required_capability_unwired(tmp_path, monkeypatch):
    """D-23 / A.10: ThreatLens declares requires_capabilities=[sbom, cve].
    Doctor must escalate the previous `[?] no capabilities wired` warn to
    `[✗]` when any enabled lens has unwired required capabilities — same
    contract `loupe ci` enforces at exit 64 time, surfaced one step earlier
    so the operator hits the wall in doctor instead of mid-run."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-123")
    _make_loupe_dir(tmp_path, wire_caps=False)  # the case we want to flag
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 64, result.stdout
    # Failure row names the lens and at least one of the missing capabilities
    assert "[✗]" in result.stdout
    assert "threatlens" in result.stdout.lower()
    assert "sbom" in result.stdout.lower() or "cve" in result.stdout.lower()


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


# ---------------------------------------------------------------------------
# F-06: doctor reports the full picture rather than aborting on first failure
# ---------------------------------------------------------------------------


def test_doctor_missing_loupe_dir_still_runs_dependent_checks_as_skipped(tmp_path, monkeypatch):
    """Pre-F-06, a missing .loupe/ short-circuited the run and the operator
    never learned whether their API key was set or whether caps were wired.
    Post-F-06, dependent checks render as [-] skipped and execution continues.
    Exit code is still 64 because .loupe/ missing is a fail."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-123")
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 64, result.stdout
    # The .loupe missing row is the failure, but every other check renders too.
    assert "[✗] .loupe/ directory" in result.stdout
    assert "[-] config.yaml parse" in result.stdout
    assert "[-] context.md" in result.stdout
    # Check 4 (provider env var) DOESN'T depend on .loupe/ — it runs
    # against the scaffold-default model id and the env var is set, so it passes.
    assert "[✓] provider key (anthropic)" in result.stdout
    # Caps check skipped without a parsed config.
    assert "[-] required capabilities" in result.stdout


def test_doctor_summary_line_includes_skip_count(tmp_path, monkeypatch):
    """The trailing summary line `N ok · N warn · N skip · N fail` lets
    a CI integration grep for the verdict at a glance."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-123")
    result = runner.invoke(app, ["doctor"])
    assert " skip · " in result.stdout
    # Three skips on the missing-loupe path: config.yaml, context.md, caps.
    assert "3 skip" in result.stdout


def test_doctor_fails_when_git_missing(tmp_path, monkeypatch):
    """git is required for `loupe chat`; doctor must surface a missing git as a fail."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-123")
    _make_loupe_dir(tmp_path)

    def fake_which(binary: str) -> str | None:
        if binary == "git":
            return None
        return f"/usr/local/bin/{binary}"

    monkeypatch.setattr("loupe_cli.doctor_cmd.shutil.which", fake_which)
    result = runner.invoke(app, ["doctor"])
    assert "git" in result.stdout.lower()
    assert "[✗]" in result.stdout
    assert result.exit_code == 64
