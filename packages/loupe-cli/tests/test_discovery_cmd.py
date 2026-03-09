"""Tests for `loupe lens list` and `loupe cap list` discovery commands.

These verify that the CLI surface enumerates whatever's registered via
the `loupe.lenses` and `loupe.capabilities` entry-point groups. Since the
workspace ships ThreatLens, Syft, and Grype in editable mode during dev
sync, the commands have real data to print and we can assert on it.
"""
from loupe_cli.__main__ import app
from typer.testing import CliRunner

runner = CliRunner()


def test_lens_list_prints_threatlens():
    result = runner.invoke(app, ["lens", "list"])
    assert result.exit_code == 0, result.stdout
    # ThreatLens ships in the workspace; should appear in the output.
    assert "threatlens" in result.stdout.lower()
    # Header columns
    assert "NAME" in result.stdout
    assert "DOMAIN" in result.stdout


def test_lens_list_includes_requires_capabilities():
    """ThreatLens declares requires_capabilities=['sbom', 'cve']."""
    result = runner.invoke(app, ["lens", "list"])
    assert result.exit_code == 0
    assert "sbom" in result.stdout
    assert "cve" in result.stdout


def test_cap_list_prints_sbom_and_cve_categories():
    result = runner.invoke(app, ["cap", "list"])
    assert result.exit_code == 0, result.stdout
    # Bundled defaults: syft for sbom, grype for cve.
    assert "sbom" in result.stdout
    assert "cve" in result.stdout
    assert "syft" in result.stdout
    assert "grype" in result.stdout


def test_cap_list_shows_dotted_path():
    """Operators need to see WHERE each backend lives so they can debug."""
    result = runner.invoke(app, ["cap", "list"])
    assert result.exit_code == 0
    # Bundled backends live under loupe_core.capabilities.backends.*
    assert "loupe_core.capabilities.backends" in result.stdout


def test_lens_list_help_does_not_crash():
    """`loupe lens` (no subcommand) should print help, not error."""
    result = runner.invoke(app, ["lens"])
    # Typer returns 2 when a sub-app is invoked without a verb. Should not crash.
    assert "list" in result.stdout.lower() or "list" in (result.stderr or "").lower()


def test_cap_list_help_does_not_crash():
    result = runner.invoke(app, ["cap"])
    assert "list" in result.stdout.lower() or "list" in (result.stderr or "").lower()
