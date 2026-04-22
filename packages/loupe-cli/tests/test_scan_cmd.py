"""Tests for `loupe scan` — D-15 full-repo / scoped scan mode."""

import shutil
from pathlib import Path

from loupe_cli.__main__ import app
from loupe_core.artifacts.run_record import load_run_records
from typer.testing import CliRunner

from .conftest import minimal_config_yaml

runner = CliRunner()
FIXTURES = Path(__file__).parent.parent.parent / "loupe-core" / "tests" / "artifacts" / "fixtures"


def _init_project(tmp_path: Path) -> Path:
    """A .loupe/ with threatlens at a high relevance threshold so diff mode
    would normally filter it out — proving that scan mode bypasses the filter."""
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    shutil.copy(FIXTURES / "valid_context.md", loupe / "context.md")
    # Impossible-for-diff-mode threshold — only scan mode can include this lens.
    (loupe / "config.yaml").write_text(minimal_config_yaml(threatlens_min_relevance=0.99))
    (loupe / "runs").mkdir()
    return loupe


def test_scan_runs_lens_despite_high_relevance_threshold(tmp_path, monkeypatch):
    """In scan mode, threatlens runs even though its real diff-mode relevance
    would be far below the configured 0.99 threshold."""
    monkeypatch.chdir(tmp_path)
    loupe = _init_project(tmp_path)

    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0, result.stdout

    runs = load_run_records(loupe / "runs")
    assert len(runs) == 1
    assert "threatlens" in runs[0].lenses_run


def test_scan_records_scope_full_in_run_record(tmp_path, monkeypatch):
    """The run record (or its trigger field) should reflect that this was a scan, not a diff."""
    monkeypatch.chdir(tmp_path)
    loupe = _init_project(tmp_path)

    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0

    runs = load_run_records(loupe / "runs")
    # The trigger string carries the mode signal in the record
    assert "scan" in runs[0].trigger.lower()


def test_scan_scoped_with_paths(tmp_path, monkeypatch):
    """`loupe scan --paths src/payments/` runs in scoped mode (D-15)."""
    monkeypatch.chdir(tmp_path)
    loupe = _init_project(tmp_path)

    result = runner.invoke(
        app,
        ["scan", "--paths", "src/payments/", "--paths", "src/api/"],
    )
    assert result.exit_code == 0, result.stdout

    runs = load_run_records(loupe / "runs")
    assert len(runs) == 1
    assert "threatlens" in runs[0].lenses_run


def test_scan_fails_when_loupe_dir_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan"])
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "loupe init" in combined.lower() or ".loupe" in combined


def test_scan_bootstraps_capabilities_before_dispatch(tmp_path, monkeypatch):
    """`loupe scan` must call bootstrap_capabilities() so lenses have their
    declared SBOM/CVE/etc inputs available. ci_cmd does this; scan_cmd
    historically skipped it, so ThreatLens (requires sbom+cve) ran with
    empty capability slots on every full-repo scan.
    """
    monkeypatch.chdir(tmp_path)
    _init_project(tmp_path)

    calls: list[dict] = []

    async def _spy(**kwargs):
        # Capture the kwargs so we can assert ctx/lenses/config were threaded.
        calls.append(kwargs)

    monkeypatch.setattr("loupe_cli.scan_cmd.bootstrap_capabilities", _spy)

    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0, result.stdout
    assert len(calls) == 1, "bootstrap_capabilities was not called by loupe scan"
    # Sanity: scan threaded the planned lenses through so the bootstrap
    # only runs caps for what will actually execute.
    assert "lenses" in calls[0]
    assert any(
        getattr(lens.capabilities, "name", None) == "threatlens"
        for lens in calls[0]["lenses"]
    )
