import json
from unittest.mock import patch

from loupe_core.sbom import diff_sboms, generate_sbom

SAMPLE_BEFORE = {"components": [
    {"name": "requests", "version": "2.30.0", "type": "library"},
    {"name": "django", "version": "5.0.0", "type": "library"},
]}
SAMPLE_AFTER = {"components": [
    {"name": "requests", "version": "2.31.0", "type": "library"},
    {"name": "django", "version": "5.0.0", "type": "library"},
    {"name": "stripe", "version": "9.5.0", "type": "library"},
]}


def test_generate_sbom_invokes_syft(tmp_path):
    with patch("loupe_core.sbom._run_syft") as mock_syft:
        mock_syft.return_value = json.dumps(SAMPLE_BEFORE)
        out = generate_sbom(repo_path=tmp_path, output_path=tmp_path / "sbom.cdx.json")
    assert mock_syft.called
    assert (tmp_path / "sbom.cdx.json").exists()


def test_diff_sboms_detects_changes():
    delta = diff_sboms(before=SAMPLE_BEFORE, after=SAMPLE_AFTER)
    assert "stripe" in delta.added_packages
    assert ("requests", "2.30.0", "2.31.0") in delta.upgraded_packages
    assert delta.removed_packages == []
