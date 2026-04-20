"""§5 — bootstrap integration tests.

The bootstrap pass computes the union of `requires_capabilities` across
selected lenses, resolves each via the registry, runs each with its
configured composition mode, and populates the typed RunContext slots.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from loupe_core.capabilities.bootstrap import bootstrap_capabilities
from loupe_core.capabilities.errors import NoBackendsConfiguredError
from loupe_core.capabilities.protocols import (
    CveFinding,
    CveResult,
    SbomComponent,
    SbomResult,
)
from loupe_core.capabilities.registry import CapabilityRegistry
from loupe_core.config import CapabilityActivation, LoupeConfig
from loupe_core.lens_api import LensCapabilities
from loupe_core.run_context import RunContext


class FakeSbomBackend:
    name = "sbom"
    backend_name = "fake-syft"

    async def run(self, repo_path: Path) -> SbomResult:
        return SbomResult(
            components=[SbomComponent(name="pkg", version="1.0")],
            backend_name=self.backend_name,
        )


class FakeCveBackend:
    name = "cve"
    backend_name = "fake-grype"

    async def run(self, sbom: SbomResult) -> CveResult:
        # Exercises the SBOM→CVE pipeline ordering: this backend's input is
        # the previously-populated SbomResult on ctx.sbom.
        assert len(sbom.components) == 1
        return CveResult(
            findings=[
                CveFinding(
                    cve_id="CVE-2024-1",
                    component_name=sbom.components[0].name,
                    component_version=sbom.components[0].version,
                    severity="high",
                    summary="x",
                )
            ],
            backend_name=self.backend_name,
        )


def _empty_ctx() -> RunContext:
    return RunContext(
        run_id="r1",
        mode="ci",
        started_at=datetime.now(UTC),
        user_intent="",
        diff=None,
        sbom_delta=None,
        project=None,
        knowledge=None,
    )


def _registry_with_fakes() -> CapabilityRegistry:
    return CapabilityRegistry(
        {"sbom": {"fake-syft": FakeSbomBackend}, "cve": {"fake-grype": FakeCveBackend}}
    )


class _Lens:
    def __init__(self, name: str, requires: list[str]) -> None:
        self.capabilities = LensCapabilities(name=name, domain="t", requires_capabilities=requires)


@pytest.mark.asyncio
async def test_bootstrap_populates_sbom_when_lens_requires_it():
    ctx = _empty_ctx()
    config = LoupeConfig(
        capabilities={"sbom": CapabilityActivation(mode="single", backends=["fake-syft"])}
    )
    lenses = [_Lens("threatlens", requires=["sbom"])]
    await bootstrap_capabilities(
        ctx=ctx,
        lenses=lenses,
        config=config,
        registry=_registry_with_fakes(),
        repo_path=Path("/repo"),
    )
    assert ctx.sbom is not None
    assert ctx.sbom.backend_name == "fake-syft"


@pytest.mark.asyncio
async def test_bootstrap_runs_sbom_before_cve_so_pipeline_works():
    ctx = _empty_ctx()
    config = LoupeConfig(
        capabilities={
            "sbom": CapabilityActivation(mode="single", backends=["fake-syft"]),
            "cve": CapabilityActivation(mode="single", backends=["fake-grype"]),
        }
    )
    lenses = [_Lens("threatlens", requires=["cve"])]  # only cve; sbom pulled implicitly
    await bootstrap_capabilities(
        ctx=ctx,
        lenses=lenses,
        config=config,
        registry=_registry_with_fakes(),
        repo_path=Path("/repo"),
    )
    assert ctx.sbom is not None
    assert ctx.cve_findings is not None
    assert ctx.cve_findings.findings[0].cve_id == "CVE-2024-1"


@pytest.mark.asyncio
async def test_bootstrap_unions_required_capabilities_across_lenses():
    # Two lenses, each needs sbom — capability runs once, both observe it.
    ctx = _empty_ctx()
    config = LoupeConfig(
        capabilities={"sbom": CapabilityActivation(mode="single", backends=["fake-syft"])}
    )
    lenses = [
        _Lens("threatlens", requires=["sbom"]),
        _Lens("autocyber", requires=["sbom"]),
    ]
    with patch.object(FakeSbomBackend, "run", wraps=FakeSbomBackend().run) as run_spy:
        await bootstrap_capabilities(
            ctx=ctx,
            lenses=lenses,
            config=config,
            registry=_registry_with_fakes(),
            repo_path=Path("/repo"),
        )
    assert run_spy.call_count == 1
    assert ctx.sbom is not None


@pytest.mark.asyncio
async def test_bootstrap_skips_capabilities_no_lens_needs():
    ctx = _empty_ctx()
    # Operator configured cve but no lens requires it: registry never invoked.
    config = LoupeConfig(
        capabilities={
            "sbom": CapabilityActivation(mode="single", backends=["fake-syft"]),
            "cve": CapabilityActivation(mode="single", backends=["fake-grype"]),
        }
    )
    lenses = [_Lens("threatlens", requires=["sbom"])]
    await bootstrap_capabilities(
        ctx=ctx,
        lenses=lenses,
        config=config,
        registry=_registry_with_fakes(),
        repo_path=Path("/repo"),
    )
    assert ctx.sbom is not None
    assert ctx.cve_findings is None  # never ran


@pytest.mark.asyncio
async def test_bootstrap_raises_when_capability_missing_from_config():
    ctx = _empty_ctx()
    config = LoupeConfig(capabilities={})  # operator forgot to declare sbom
    lenses = [_Lens("threatlens", requires=["sbom"])]
    with pytest.raises(NoBackendsConfiguredError):
        await bootstrap_capabilities(
            ctx=ctx,
            lenses=lenses,
            config=config,
            registry=_registry_with_fakes(),
            repo_path=Path("/repo"),
        )


@pytest.mark.asyncio
async def test_bootstrap_is_noop_when_no_lens_declares_requirements():
    ctx = _empty_ctx()
    config = LoupeConfig()
    lenses = [_Lens("docs_lens", requires=[])]
    await bootstrap_capabilities(
        ctx=ctx,
        lenses=lenses,
        config=config,
        registry=_registry_with_fakes(),
        repo_path=Path("/repo"),
    )
    assert ctx.sbom is None
    assert ctx.cve_findings is None
