"""D-18 §5 — capability bootstrap pass.

Sits between the coordinator's plan-building and the dispatcher's
per-lens execution: computes the union of `requires_capabilities`
across selected lenses, resolves each via the registry, runs each
backend with its configured composition mode, and populates the
typed RunContext slots.

Inter-capability dependencies are encoded once in `_CAPABILITY_GRAPH`;
the run order is derived from a topological sort over that dict, and
the implicit-deps expansion (`requires_capabilities=["cve"]` ⇒ also
runs sbom) reads from the same source.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from loupe_core.capabilities.composition import CompositionMode, compose_run
from loupe_core.capabilities.errors import NoBackendsConfiguredError
from loupe_core.capabilities.protocols import (
    CveResult,
    SbomResult,
    SecretDetectionResult,
    StaticAnalysisResult,
)
from loupe_core.capabilities.registry import CapabilityRegistry
from loupe_core.config import CapabilityActivation, LoupeConfig
from loupe_core.run_context import RunContext

# Single source of truth for the capability dependency graph.
# Each key is a capability; the value lists capabilities that MUST run before
# it (typically because the dependent consumes the dependency's typed result).
# Adding a third dep-bearing capability is a one-line edit here — both the
# implicit-deps expansion and the run-order topo sort derive from this dict.
_CAPABILITY_GRAPH: dict[str, list[str]] = {
    "sbom": [],
    "cve": ["sbom"],  # cve backends consume the SbomResult via pipeline
    "secret_detect": [],
    "static_analysis": [],
}


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
    # Pull in implicit dependencies transitively (e.g., cve → sbom). Iterate
    # to a fixed point so future multi-hop chains (a → b → c) resolve cleanly.
    pending = set(required)
    while pending:
        cap = pending.pop()
        for dep in _CAPABILITY_GRAPH.get(cap, []):
            if dep not in required:
                required.add(dep)
                pending.add(dep)
    return required


def _order_capabilities(required: set[str]) -> list[str]:
    """Topologically sort `required` so dependencies precede dependents.

    Capabilities not declared in `_CAPABILITY_GRAPH` are treated as having no
    deps and are appended in lexicographic order for determinism.
    """
    ordered: list[str] = []
    visited: set[str] = set()
    temp: set[str] = set()

    def visit(node: str) -> None:
        if node in visited:
            return
        if node in temp:
            raise RuntimeError(
                f"capability dependency cycle detected involving {node!r}"
            )
        temp.add(node)
        for dep in _CAPABILITY_GRAPH.get(node, []):
            if dep in required:
                visit(dep)
        temp.remove(node)
        visited.add(node)
        ordered.append(node)

    # Visit in a deterministic order: known graph nodes first (declaration order),
    # then any unknown capabilities (sorted) so two runs with the same input
    # produce the same plan.
    for node in _CAPABILITY_GRAPH:
        if node in required:
            visit(node)
    for node in sorted(required - set(_CAPABILITY_GRAPH)):
        visit(node)
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
    backends = registry.resolve(
        capability=capability,
        backend_names=activation.backends,
        options=activation.options,
    )
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
                "cve capability invoked before sbom — _CAPABILITY_GRAPH is wrong"
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
