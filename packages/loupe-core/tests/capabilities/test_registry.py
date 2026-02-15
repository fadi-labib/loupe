from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from loupe_core.capabilities.errors import (
    CapabilityNotFoundError,
    NoBackendsConfiguredError,
)
from loupe_core.capabilities.protocols import SbomResult
from loupe_core.capabilities.registry import CapabilityRegistry


class FakeSyft:
    name = "sbom"
    backend_name = "syft"

    async def run(self, repo_path: Path) -> SbomResult:
        return SbomResult(backend_name="syft")


class FakeTrivy:
    name = "sbom"
    backend_name = "trivy"

    async def run(self, repo_path: Path) -> SbomResult:
        return SbomResult(backend_name="trivy")


class FakeGrype:
    name = "cve"
    backend_name = "grype"

    async def run(self, sbom):  # signature differs by capability
        from loupe_core.capabilities.protocols import CveResult

        return CveResult(backend_name="grype")


def _entry_points_fake(group: str):
    ep_syft = MagicMock()
    ep_syft.name = "syft"
    ep_syft.load.return_value = FakeSyft
    ep_trivy = MagicMock()
    ep_trivy.name = "trivy"
    ep_trivy.load.return_value = FakeTrivy
    ep_grype = MagicMock()
    ep_grype.name = "grype"
    ep_grype.load.return_value = FakeGrype
    return [ep_syft, ep_trivy, ep_grype]


def _make_registry() -> CapabilityRegistry:
    with patch("loupe_core.capabilities.registry._entry_points", _entry_points_fake):
        return CapabilityRegistry.discover()


def test_discovers_backends_via_entry_points():
    reg = _make_registry()
    assert reg.list_backends("sbom") == ["syft", "trivy"]
    assert reg.list_backends("cve") == ["grype"]


def test_resolve_returns_backends_in_configured_order():
    reg = _make_registry()
    backends = reg.resolve(capability="sbom", backend_names=["trivy", "syft"])
    assert [b.backend_name for b in backends] == ["trivy", "syft"]


def test_resolve_raises_when_capability_unknown():
    reg = _make_registry()
    with pytest.raises(CapabilityNotFoundError):
        reg.resolve(capability="quantum_oracles", backend_names=["x"])


def test_resolve_raises_when_no_backends_configured():
    reg = _make_registry()
    with pytest.raises(NoBackendsConfiguredError):
        reg.resolve(capability="sbom", backend_names=[])


def test_resolve_raises_when_named_backend_not_registered():
    reg = _make_registry()
    with pytest.raises(CapabilityNotFoundError) as exc:
        reg.resolve(capability="sbom", backend_names=["snyk"])
    assert "snyk" in str(exc.value)


def test_list_backends_returns_empty_for_unknown_capability():
    reg = _make_registry()
    assert reg.list_backends("not_a_real_capability") == []
