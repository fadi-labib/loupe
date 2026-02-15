"""D-18 §5 — capability bootstrap pass.

Sits between the coordinator's plan-building and the dispatcher's
per-lens execution: computes the union of `requires_capabilities`
across selected lenses, resolves each via the registry, runs each
backend with its configured composition mode, and populates the
typed RunContext slots.

The hard-coded sbom-before-cve ordering reflects the only real
inter-capability dependency today (CVE backends consume the SBOM
output via pipeline). When a third dependency-bearing capability
arrives, replace the explicit ordering with a small topological
sort over a per-capability `depends_on` declaration.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from loupe_core.capabilities.composition import CompositionMode, compose_run
from loupe_core.capabilities.protocols import (
    CveResult,
    SbomResult,
    SecretDetectionResult,
    StaticAnalysisResult,
)
from loupe_core.capabilities.registry import CapabilityRegistry
from loupe_core.config import CapabilityActivation, LoupeConfig
from loupe_core.run_context import RunContext

# Order in which capabilities must run if multiple are required. Capabilities
# later in the list may consume the typed result of earlier ones (e.g.,
# CVE pipelines feed on SbomResult). Capabilities not in this list run
# in arbitrary (declaration) order.
_CAPABILITY_ORDER: list[str] = ["sbom", "cve", "secret_detect", "static_analysis"]

# Implicit dependencies: requesting the key implicitly requests the values.
# Lets a lens declare `requires_capabilities=["cve"]` and get an SBOM
# bootstrapped for free, since every CVE backend in practice needs one.
_IMPLICIT_DEPS: dict[str, list[str]] = {"cve": ["sbom"]}


class _LensLike(Protocol):
    capabilities: Any


async def bootstrap_capabilities(
    *,
    ctx: RunContext,
    lenses: list[_LensLike],
    config: LoupeConfig,
    registry: CapabilityRegistry,
    repo_path: Path,
) -> None:
    required = _collect_required(lenses)
    ordered = _order_capabilities(required)

    for capability in ordered:
        activation = config.capabilities.get(capability)
        if activation is None:
            # No operator configuration for a capability a lens needs.
            # NoBackendsConfiguredError carries the specific name so the
            # user can fix config.yaml without grepping.
            from loupe_core.capabilities.errors import NoBackendsConfiguredError

            raise NoBackendsConfiguredError(capability=capability)
        result = await _run_one(
            capability=capability,
            activation=activation,
            registry=registry,
            ctx=ctx,
            repo_path=repo_path,
        )
        _store_on_context(ctx, capability, result)


def _collect_required(lenses: list[_LensLike]) -> set[str]:
    required: set[str] = set()
    for lens in lenses:
        required.update(lens.capabilities.requires_capabilities)
    # Pull in implicit dependencies (e.g., cve → sbom)
    for cap in list(required):
        required.update(_IMPLICIT_DEPS.get(cap, []))
    return required


def _order_capabilities(required: set[str]) -> list[str]:
    ordered = [c for c in _CAPABILITY_ORDER if c in required]
    # Append any custom capability not in the canonical order
    ordered.extend(sorted(required - set(_CAPABILITY_ORDER)))
    return ordered


_RESULT_TYPES: dict[str, type] = {
    "sbom": SbomResult,
    "cve": CveResult,
    "secret_detect": SecretDetectionResult,
    "static_analysis": StaticAnalysisResult,
}


async def _run_one(
    *,
    capability: str,
    activation: CapabilityActivation,
    registry: CapabilityRegistry,
    ctx: RunContext,
    repo_path: Path,
) -> Any:
    backends = registry.resolve(capability=capability, backend_names=activation.backends)
    args = _args_for(capability, ctx=ctx, repo_path=repo_path)
    result_type = _RESULT_TYPES.get(capability)
    if result_type is None:
        # Unknown capability — invoke the first backend without composition
        # so the run still completes; the lens reading the result must know
        # its own typed shape.
        return await backends[0].run(*args)
    return await compose_run(
        mode=CompositionMode(activation.mode),
        backends=backends,
        result_type=result_type,
        args=args,
        consensus_threshold=activation.consensus_threshold,
    )


def _args_for(capability: str, *, ctx: RunContext, repo_path: Path) -> tuple[Any, ...]:
    # CVE backends consume the previously-populated SbomResult.
    if capability == "cve":
        if ctx.sbom is None:
            raise RuntimeError(
                "cve capability invoked before sbom — _CAPABILITY_ORDER is wrong"
            )
        return (ctx.sbom,)
    return (repo_path,)


def _store_on_context(ctx: RunContext, capability: str, result: Any) -> None:
    setattr(ctx, _SLOT_NAMES[capability], result)


_SLOT_NAMES: dict[str, str] = {
    "sbom": "sbom",
    "cve": "cve_findings",
    "secret_detect": "secrets",
    "static_analysis": "static_findings",
}
