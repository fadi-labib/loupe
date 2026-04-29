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
from loupe_core.capabilities.degradation import CapabilityDegradation, DegradationKind
from loupe_core.capabilities.errors import (
    CapabilityError,
    CapabilityNotFoundError,
    EntryPointMalformedError,
    NoBackendsConfiguredError,
    RequiredCapabilityUnavailable,
)
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
) -> list[CapabilityDegradation]:
    """Resolve every capability the planned lenses declared, populate the
    typed slots on `ctx`, and return any soft-failure degradations.

    Policy (D-23):
    - `requires_capabilities` on any lens makes the capability required.
      Missing config or backend errors raise `RequiredCapabilityUnavailable`
      with the violating lens and underlying cause attached.
    - `prefers_capabilities` on a lens (with no lens requiring the same
      capability) makes it preferred. Missing config or backend errors are
      recorded as `CapabilityDegradation` entries; the slot stays `None`
      and the lens runs.
    - Required wins on disagreement: if two lenses declare the same
      capability, one as required and one as preferred, the capability is
      treated as required.
    - Implicit dependencies (e.g. cve → sbom) inherit the policy of the
      capability that pulled them in.

    Returns: list of degradations for run-record persistence (A.5). The
    list is empty on the happy path so callers can use truthiness.
    """
    required_by, preferred_by = _collect_capability_demands(lenses)
    ordered = _order_capabilities(set(required_by) | set(preferred_by))

    degradations: list[CapabilityDegradation] = []
    for capability in ordered:
        is_required = capability in required_by
        owning_lens = (
            required_by.get(capability, [None])[0]
            if is_required
            else preferred_by.get(capability, [None])[0]
        ) or "unknown"

        activation = config.capabilities.get(capability)
        if activation is None:
            cause = NoBackendsConfiguredError(capability=capability)
            if is_required:
                raise RequiredCapabilityUnavailable(
                    lens_name=owning_lens, capability=capability, cause=cause
                )
            degradations.append(
                CapabilityDegradation(
                    lens_name=owning_lens,
                    capability=capability,
                    kind="unconfigured",
                    detail=str(cause),
                )
            )
            continue

        try:
            result = await _run_one(
                capability=capability,
                activation=activation,
                registry=registry,
                ctx=ctx,
                repo_path=repo_path,
            )
        except CapabilityError as exc:
            if is_required:
                raise RequiredCapabilityUnavailable(
                    lens_name=owning_lens, capability=capability, cause=exc
                ) from exc
            degradations.append(
                CapabilityDegradation(
                    lens_name=owning_lens,
                    capability=capability,
                    kind=_kind_for(exc),
                    detail=str(exc),
                )
            )
            continue
        _store_on_context(ctx, capability, result)

    return degradations


def _collect_capability_demands(
    lenses: list[_LensLike],
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Split capability demands into required vs preferred maps.

    Required wins: if a capability appears in `requires_capabilities` on
    any lens, it's tracked as required (and absent from the preferred
    map) even if other lenses listed it as preferred. Implicit dependencies
    (from `_CAPABILITY_GRAPH`) inherit the strictest policy of the
    capabilities that pulled them in.
    """
    required_by: dict[str, list[str]] = {}
    preferred_by: dict[str, list[str]] = {}
    for lens in lenses:
        lens_name = lens.capabilities.name
        for cap in lens.capabilities.requires_capabilities:
            required_by.setdefault(cap, []).append(lens_name)
        for cap in lens.capabilities.prefers_capabilities:
            preferred_by.setdefault(cap, []).append(lens_name)

    # Required wins over preferred on overlap.
    for cap in list(preferred_by):
        if cap in required_by:
            del preferred_by[cap]

    # Expand implicit dependencies. Required deps stay required; preferred
    # deps stay preferred unless already promoted by another lens.
    _expand_transitively(required_by, promote_to_required=True, preferred_by=preferred_by)
    _expand_transitively(preferred_by, promote_to_required=False, preferred_by=None)

    return required_by, preferred_by


def _expand_transitively(
    targets: dict[str, list[str]],
    *,
    promote_to_required: bool,
    preferred_by: dict[str, list[str]] | None,
) -> None:
    """Walk `_CAPABILITY_GRAPH` and add transitive dependencies into `targets`.

    When promote_to_required=True and a transitive dep currently lives in
    `preferred_by`, it gets removed from there and added to `targets`
    (the required map). This enforces "required wins" across the implicit
    edge.
    """
    pending = set(targets)
    while pending:
        cap = pending.pop()
        for dep in _CAPABILITY_GRAPH.get(cap, []):
            if dep in targets:
                continue
            owner = targets[cap][0] if targets[cap] else "unknown"
            targets.setdefault(dep, []).append(owner)
            if promote_to_required and preferred_by is not None and dep in preferred_by:
                del preferred_by[dep]
            pending.add(dep)


def _kind_for(exc: CapabilityError) -> DegradationKind:
    if isinstance(exc, NoBackendsConfiguredError):
        return "unconfigured"
    if isinstance(exc, CapabilityNotFoundError):
        return "not_found"
    if isinstance(exc, EntryPointMalformedError):
        return "entry_point_malformed"
    # BackendError or any other CapabilityError subtype — runtime failure.
    return "backend_error"


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
            raise RuntimeError(f"capability dependency cycle detected involving {node!r}")
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
            raise RuntimeError("cve capability invoked before sbom — _CAPABILITY_GRAPH is wrong")
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
