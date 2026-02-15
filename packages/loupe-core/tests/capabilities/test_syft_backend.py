from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from loupe_core.capabilities.backends.syft_sbom import SyftSbomBackend
from loupe_core.capabilities.errors import BackendError
from loupe_core.capabilities.protocols import SbomCapability


def _cyclonedx_json(components: list[dict[str, str]]) -> str:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": components,
        }
    )


def test_syft_backend_implements_sbom_capability_protocol():
    backend = SyftSbomBackend()
    # The runtime-checkable Protocol is the contract used by the registry
    # before invoking any backend.
    assert isinstance(backend, SbomCapability)
    assert backend.name == "sbom"


@pytest.mark.asyncio
async def test_syft_backend_parses_cyclonedx_components():
    raw = _cyclonedx_json(
        [
            {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
            {"name": "urllib3", "version": "2.0.7", "purl": "pkg:pypi/urllib3@2.0.7"},
        ]
    )
    completed = MagicMock(returncode=0, stdout=raw, stderr="")
    with (
        patch(
            "loupe_core.capabilities.backends.syft_sbom.shutil.which",
            return_value="/usr/bin/syft",
        ),
        patch(
            "loupe_core.capabilities.backends.syft_sbom.subprocess.run",
            return_value=completed,
        ),
    ):
        result = await SyftSbomBackend().run(Path("/repo"))
    assert {c.name for c in result.components} == {"requests", "urllib3"}
    assert result.sbom_format == "cyclonedx-json"
    assert result.backend_name == "syft"


@pytest.mark.asyncio
async def test_syft_backend_raises_backend_error_when_binary_missing():
    with patch(
        "loupe_core.capabilities.backends.syft_sbom.shutil.which",
        return_value=None,
    ):
        with pytest.raises(BackendError, match="syft"):
            await SyftSbomBackend().run(Path("/repo"))


@pytest.mark.asyncio
async def test_syft_backend_raises_when_subprocess_fails():
    failed = MagicMock(returncode=2, stdout="", stderr="permission denied")
    with (
        patch(
            "loupe_core.capabilities.backends.syft_sbom.shutil.which",
            return_value="/usr/bin/syft",
        ),
        patch(
            "loupe_core.capabilities.backends.syft_sbom.subprocess.run",
            return_value=failed,
        ),
    ):
        with pytest.raises(BackendError, match="permission denied"):
            await SyftSbomBackend().run(Path("/repo"))
