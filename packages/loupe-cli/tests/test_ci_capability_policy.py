"""D-23 / A.3: CLI integration of the required-vs-preferred capability policy.

These tests exercise `loupe ci`'s response to bootstrap outcomes:
- required-miss → exit 64 (`EX_USAGE`), no dispatch
- preferred-miss → exit 0, lens runs degraded, run record carries
  `capability_degraded` entries

The bootstrap layer itself is tested in test_bootstrap.py; here we
verify the CLI plumbs the right exception into the right exit code
and the returned degradations into the right ctx slot.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from loupe_cli.__main__ import app
from loupe_core.artifacts.run_record import load_run_records
from loupe_core.capabilities.bootstrap import bootstrap_capabilities
from loupe_core.capabilities.degradation import CapabilityDegradation
from typer.testing import CliRunner

from .conftest import minimal_config_yaml

runner = CliRunner()
FIXTURES = Path(__file__).parent.parent.parent / "loupe-core" / "tests" / "artifacts" / "fixtures"


@pytest.fixture(autouse=True)
def real_bootstrap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Opt out of the conftest stub for this test module — we want to
    see the real bootstrap behaviour at the CLI boundary."""
    for target in (
        "loupe_cli.ci_cmd.bootstrap_capabilities",
        "loupe_cli.scan_cmd.bootstrap_capabilities",
    ):
        monkeypatch.setattr(target, bootstrap_capabilities)


def _init_project(tmp_path: Path) -> Path:
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    shutil.copy(FIXTURES / "valid_context.md", loupe / "context.md")
    (loupe / "config.yaml").write_text(minimal_config_yaml())
    (loupe / "runs").mkdir()
    return loupe


# ---------------------------------------------------------------------------
# Required-miss → exit 64
# ---------------------------------------------------------------------------


def test_ci_required_miss_exits_64(tmp_path, monkeypatch):
    """ThreatLens declares requires=['sbom','cve']. With no `capabilities:`
    block in config, bootstrap raises RequiredCapabilityUnavailable and
    the CLI translates it to exit 64. The lens never runs."""
    monkeypatch.chdir(tmp_path)
    _init_project(tmp_path)

    code_diff = "diff --git a/src/api.py b/src/api.py\n@@ -0,0 +1,3 @@\n+def x():\n+    return 1\n"
    result = runner.invoke(
        app,
        ["ci", "--diff", code_diff, "--base-sha", "a", "--head-sha", "b"],
    )
    assert result.exit_code == 64, result.stdout
    # Friendly error names the lens and the capability.
    combined = (result.stdout or "") + (result.stderr or "")
    assert "threatlens" in combined.lower()
    assert "sbom" in combined.lower() or "cve" in combined.lower()


def test_scan_required_miss_exits_64(tmp_path, monkeypatch):
    """Same policy applies to `loupe scan` — required-miss is a config
    error regardless of which CLI invoked the lens."""
    monkeypatch.chdir(tmp_path)
    _init_project(tmp_path)

    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 64, result.stdout
    combined = (result.stdout or "") + (result.stderr or "")
    assert "threatlens" in combined.lower()


# ---------------------------------------------------------------------------
# Preferred-miss → exit 0 + run record carries degradation
# ---------------------------------------------------------------------------


def test_ci_preferred_miss_writes_capability_degraded_to_run_record(tmp_path, monkeypatch):
    """When the bootstrap layer returns a non-empty degradation list,
    the CLI stores it on ctx and the run-record writer persists it. The
    run still exits 0 (preferred-miss is soft) and auditors can see the
    degradation entry by reading the run record."""
    monkeypatch.chdir(tmp_path)
    loupe = _init_project(tmp_path)

    # Stub bootstrap to return a fake degradation as if a preferred
    # capability was missing. The CLI's job is to plumb this through,
    # not produce it.
    async def fake_bootstrap(**kwargs):
        return [
            CapabilityDegradation(
                lens_name="threatlens",
                capability="secret_detect",
                kind="unconfigured",
                detail="No backends configured for secret_detect.",
            )
        ]

    for target in (
        "loupe_cli.ci_cmd.bootstrap_capabilities",
        "loupe_cli.scan_cmd.bootstrap_capabilities",
    ):
        monkeypatch.setattr(target, fake_bootstrap)

    code_diff = "diff --git a/src/api.py b/src/api.py\n@@ -0,0 +1,3 @@\n+def x():\n+    return 1\n"
    result = runner.invoke(
        app,
        ["ci", "--diff", code_diff, "--base-sha", "a", "--head-sha", "b"],
    )
    assert result.exit_code == 0, result.stdout

    record = load_run_records(loupe / "runs")[0]
    assert len(record.capability_degraded) == 1
    entry = record.capability_degraded[0]
    assert entry.lens_name == "threatlens"
    assert entry.capability == "secret_detect"
    assert entry.kind == "unconfigured"


def test_scan_preferred_miss_writes_capability_degraded_to_run_record(tmp_path, monkeypatch):
    """Same plumbing for `loupe scan`. Stubbed bootstrap returns a
    degradation list; the run record persists it; scan exits 0."""
    monkeypatch.chdir(tmp_path)
    loupe = _init_project(tmp_path)

    async def fake_bootstrap(**kwargs):
        return [
            CapabilityDegradation(
                lens_name="threatlens",
                capability="static_analysis",
                kind="unconfigured",
                detail="No backends configured for static_analysis.",
            )
        ]

    for target in (
        "loupe_cli.ci_cmd.bootstrap_capabilities",
        "loupe_cli.scan_cmd.bootstrap_capabilities",
    ):
        monkeypatch.setattr(target, fake_bootstrap)

    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0, result.stdout

    record = load_run_records(loupe / "runs")[0]
    assert len(record.capability_degraded) == 1
    assert record.capability_degraded[0].capability == "static_analysis"
