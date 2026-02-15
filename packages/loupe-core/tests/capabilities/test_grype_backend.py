from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from loupe_core.capabilities.backends.grype_cve import GrypeCveBackend
from loupe_core.capabilities.errors import BackendError
from loupe_core.capabilities.protocols import CveCapability, SbomResult


def _grype_json(matches: list[dict]) -> str:
    return json.dumps({"matches": matches})


def _match(cve: str, name: str, version: str, severity: str = "High") -> dict:
    return {
        "vulnerability": {
            "id": cve,
            "severity": severity,
            "description": f"{cve} description",
            "dataSource": f"https://nvd.nist.gov/vuln/detail/{cve}",
        },
        "artifact": {"name": name, "version": version},
    }


def test_grype_backend_implements_cve_capability_protocol():
    backend = GrypeCveBackend()
    assert isinstance(backend, CveCapability)
    assert backend.name == "cve"


@pytest.mark.asyncio
async def test_grype_parses_matches_into_typed_findings():
    raw = _grype_json(
        [
            _match("CVE-2024-12345", "requests", "2.31.0", "High"),
            _match("CVE-2024-99999", "urllib3", "2.0.7", "Medium"),
        ]
    )
    completed = MagicMock(returncode=0, stdout=raw, stderr="")
    with (
        patch(
            "loupe_core.capabilities.backends.grype_cve.shutil.which",
            return_value="/usr/bin/grype",
        ),
        patch(
            "loupe_core.capabilities.backends.grype_cve.subprocess.run",
            return_value=completed,
        ),
    ):
        result = await GrypeCveBackend().run(SbomResult(raw_document="{}"))
    assert len(result.findings) == 2
    assert result.findings[0].cve_id == "CVE-2024-12345"
    assert result.findings[0].severity == "high"  # severity normalised to lower-case
    assert result.findings[1].severity == "medium"


@pytest.mark.asyncio
async def test_grype_passes_sbom_via_stdin():
    raw = _grype_json([])
    completed = MagicMock(returncode=0, stdout=raw, stderr="")
    with (
        patch(
            "loupe_core.capabilities.backends.grype_cve.shutil.which",
            return_value="/usr/bin/grype",
        ),
        patch(
            "loupe_core.capabilities.backends.grype_cve.subprocess.run",
            return_value=completed,
        ) as run_mock,
    ):
        await GrypeCveBackend().run(SbomResult(raw_document='{"bomFormat":"CycloneDX"}'))
    call = run_mock.call_args
    # The SBOM JSON gets fed to grype via stdin to avoid temp-file plumbing.
    assert call.kwargs.get("input") == '{"bomFormat":"CycloneDX"}'


@pytest.mark.asyncio
async def test_grype_raises_when_binary_missing():
    with patch(
        "loupe_core.capabilities.backends.grype_cve.shutil.which",
        return_value=None,
    ):
        with pytest.raises(BackendError, match="grype"):
            await GrypeCveBackend().run(SbomResult(raw_document="{}"))


@pytest.mark.asyncio
async def test_grype_raises_when_subprocess_fails():
    failed = MagicMock(returncode=2, stdout="", stderr="database not found")
    with (
        patch(
            "loupe_core.capabilities.backends.grype_cve.shutil.which",
            return_value="/usr/bin/grype",
        ),
        patch(
            "loupe_core.capabilities.backends.grype_cve.subprocess.run",
            return_value=failed,
        ),
    ):
        with pytest.raises(BackendError, match="database not found"):
            await GrypeCveBackend().run(SbomResult(raw_document="{}"))
