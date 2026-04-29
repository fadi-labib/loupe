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
from loupe_core.capabilities.degradation import CapabilityDegradation
from loupe_core.capabilities.errors import (
    NoBackendsConfiguredError,
    RequiredCapabilityUnavailable,
)
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
    def __init__(
        self,
        name: str,
        requires: list[str] | None = None,
        prefers: list[str] | None = None,
    ) -> None:
        self.capabilities = LensCapabilities(
            name=name,
            domain="t",
            requires_capabilities=requires or [],
            prefers_capabilities=prefers or [],
        )


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
async def test_bootstrap_required_missing_config_raises_required_capability_unavailable():
    """D-23: a required-but-unwired capability raises the typed
    RequiredCapabilityUnavailable exception carrying the lens name and
    the underlying NoBackendsConfiguredError as its cause. The CLI
    translates this to exit 64; older callers can still catch via the
    CapabilityError base class for back-compat."""
    ctx = _empty_ctx()
    config = LoupeConfig(capabilities={})  # operator forgot to declare sbom
    lenses = [_Lens("threatlens", requires=["sbom"])]
    with pytest.raises(RequiredCapabilityUnavailable) as exc_info:
        await bootstrap_capabilities(
            ctx=ctx,
            lenses=lenses,
            config=config,
            registry=_registry_with_fakes(),
            repo_path=Path("/repo"),
        )
    assert exc_info.value.lens_name == "threatlens"
    assert exc_info.value.capability == "sbom"
    assert isinstance(exc_info.value.cause, NoBackendsConfiguredError)


@pytest.mark.asyncio
async def test_bootstrap_preferred_missing_config_returns_degradation():
    """D-23: a preferred-but-unwired capability returns a
    CapabilityDegradation entry; the lens runs with the slot at None."""
    ctx = _empty_ctx()
    config = LoupeConfig(capabilities={})  # operator forgot to declare sbom
    lenses = [_Lens("future_lens", prefers=["sbom"])]
    degradations = await bootstrap_capabilities(
        ctx=ctx,
        lenses=lenses,
        config=config,
        registry=_registry_with_fakes(),
        repo_path=Path("/repo"),
    )
    assert ctx.sbom is None  # slot stays unpopulated, lens reads None
    assert len(degradations) == 1
    entry = degradations[0]
    assert isinstance(entry, CapabilityDegradation)
    assert entry.lens_name == "future_lens"
    assert entry.capability == "sbom"
    assert entry.kind == "unconfigured"
    assert "sbom" in entry.detail


@pytest.mark.asyncio
async def test_bootstrap_returns_empty_list_when_all_capabilities_succeed():
    """The happy path returns an empty degradation list — every required
    AND preferred capability bootstrapped successfully. Lets callers
    use truthiness to decide whether to surface anything."""
    ctx = _empty_ctx()
    config = LoupeConfig(
        capabilities={"sbom": CapabilityActivation(mode="single", backends=["fake-syft"])}
    )
    lenses = [_Lens("threatlens", requires=["sbom"])]
    degradations = await bootstrap_capabilities(
        ctx=ctx,
        lenses=lenses,
        config=config,
        registry=_registry_with_fakes(),
        repo_path=Path("/repo"),
    )
    assert degradations == []
    assert ctx.sbom is not None


@pytest.mark.asyncio
async def test_bootstrap_required_wins_when_two_lenses_declare_same_capability():
    """If one lens requires sbom and another prefers sbom, sbom is
    treated as required (strict policy wins). Missing config raises
    rather than returning a degradation."""
    ctx = _empty_ctx()
    config = LoupeConfig(capabilities={})
    lenses = [
        _Lens("strict_lens", requires=["sbom"]),
        _Lens("loose_lens", prefers=["sbom"]),
    ]
    with pytest.raises(RequiredCapabilityUnavailable) as exc_info:
        await bootstrap_capabilities(
            ctx=ctx,
            lenses=lenses,
            config=config,
            registry=_registry_with_fakes(),
            repo_path=Path("/repo"),
        )
    # The exception is reported under the strict lens's name — that's
    # the one whose contract is violated.
    assert exc_info.value.lens_name == "strict_lens"


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
