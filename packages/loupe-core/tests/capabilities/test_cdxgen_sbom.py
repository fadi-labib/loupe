"""Tests for the cdxgen SBOM backend."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from loupe_core.capabilities.backends.cdxgen_sbom import (
    CdxgenSbomBackend,
    _parse_cyclonedx,
)
from loupe_core.capabilities.errors import BackendError


def _cdx(components: list[dict]) -> str:
    return json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": components,
    })


def _component(
    *,
    name: str = "requests",
    version: str = "2.31.0",
    purl: str | None = "pkg:pypi/requests@2.31.0",
    licenses: list[dict] | None = None,
) -> dict:
    c: dict = {"name": name, "version": version}
    if purl:
        c["purl"] = purl
    if licenses is not None:
        c["licenses"] = licenses
    return c


# ---------------------------------------------------------------------------
# _parse_cyclonedx
# ---------------------------------------------------------------------------


def test_parse_empty_returns_empty():
    assert _parse_cyclonedx("") == []
    assert _parse_cyclonedx("   ") == []


def test_parse_no_components_returns_empty():
    assert _parse_cyclonedx(_cdx([])) == []


def test_parse_basic_components():
    document = _cdx([
        _component(name="requests", version="2.31.0"),
        _component(name="fastapi", version="0.104.0",
                   purl="pkg:pypi/fastapi@0.104.0"),
    ])
    components = _parse_cyclonedx(document)
    assert len(components) == 2
    assert {c.name for c in components} == {"requests", "fastapi"}
    assert components[0].purl == "pkg:pypi/requests@2.31.0"


def test_parse_extracts_licenses():
    document = _cdx([
        _component(
            licenses=[
                {"license": {"id": "Apache-2.0"}},
                {"license": {"id": "MIT"}},
            ],
        ),
    ])
    components = _parse_cyclonedx(document)
    assert components[0].licenses == ["Apache-2.0", "MIT"]


def test_parse_handles_missing_optional_fields():
    """A component without purl / licenses should still parse — defaults apply."""
    document = _cdx([{"name": "minimal", "version": "1.0"}])
    components = _parse_cyclonedx(document)
    assert len(components) == 1
    assert components[0].purl is None
    assert components[0].licenses == []


def test_parse_malformed_json_raises():
    with pytest.raises(BackendError) as exc_info:
        _parse_cyclonedx("not JSON at all")
    assert "cdxgen" in str(exc_info.value)


# ---------------------------------------------------------------------------
# CdxgenSbomBackend.run — mocked subprocess + tempfile
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_backend_returns_typed_result(tmp_path):
    sbom_payload = _cdx([_component(name="ramda", version="0.29.1")])

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = ""

    def _fake_run(cmd, **_kwargs):
        # cdxgen writes the SBOM to the path given via `-o <path>`. Find
        # the path in the cmd and write our canned payload there.
        for i, arg in enumerate(cmd):
            if arg == "-o" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text(sbom_payload)
                break
        return mock_proc

    with (
        patch("shutil.which", return_value="/usr/bin/cdxgen"),
        patch("subprocess.run", side_effect=_fake_run),
    ):
        result = await CdxgenSbomBackend().run(tmp_path)

    assert result.backend_name == "cdxgen"
    assert result.sbom_format == "cyclonedx-json"
    assert len(result.components) == 1
    assert result.components[0].name == "ramda"
    # raw_document is preserved for downstream consumers (e.g., osv-scanner).
    assert "ramda" in result.raw_document


@pytest.mark.asyncio
async def test_backend_raises_when_binary_missing(tmp_path):
    with patch("shutil.which", return_value=None):
        with pytest.raises(BackendError) as exc_info:
            await CdxgenSbomBackend().run(tmp_path)
    msg = str(exc_info.value)
    assert "cdxgen" in msg
    # The error message should guide the operator toward installation.
    assert "npm install" in msg or "Docker" in msg


@pytest.mark.asyncio
async def test_backend_raises_on_subprocess_failure(tmp_path):
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = ""
    mock_proc.stderr = "cdxgen: error: invalid project type"

    with (
        patch("shutil.which", return_value="/usr/bin/cdxgen"),
        patch("subprocess.run", return_value=mock_proc),
    ):
        with pytest.raises(BackendError) as exc_info:
            await CdxgenSbomBackend().run(tmp_path)
    assert "invalid project type" in str(exc_info.value)


def test_backend_registered_under_sbom_capability():
    assert CdxgenSbomBackend.name == "sbom"
    assert CdxgenSbomBackend.backend_name == "cdxgen"
