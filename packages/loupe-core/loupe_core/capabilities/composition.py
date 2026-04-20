from __future__ import annotations

from collections import Counter
from enum import StrEnum
from typing import Any

from pydantic import BaseModel


class CompositionMode(StrEnum):
    SINGLE = "single"
    FALLBACK = "fallback"
    UNION = "union"
    CONSENSUS = "consensus"
    PIPELINE = "pipeline"


async def compose_run[R: BaseModel](
    *,
    mode: CompositionMode,
    backends: list[Any],
    result_type: type[R],
    args: tuple[Any, ...] = (),
    consensus_threshold: int | None = None,
) -> R:
    """Invoke ``backends`` under the requested composition mode.

    The five modes implement the cross-tool patterns from D-18:

    - ``single`` — run the first backend; ignore the rest.
    - ``fallback`` — try each in order; first success wins.
    - ``union`` — run all, merge findings (dedup on ``(file, line, rule_id)``
      / ``(cve_id, component_name)`` heuristics that work for the existing
      result types).
    - ``consensus`` — run all, keep only findings ≥``consensus_threshold``
      backends emitted independently.
    - ``pipeline`` — backend ``N`` consumes the output of backend ``N-1``
      (e.g., SBOM → CVE).
    """
    if mode is CompositionMode.SINGLE:
        single: R = await backends[0].run(*args)
        return single

    if mode is CompositionMode.FALLBACK:
        last_exc: Exception | None = None
        for backend in backends:
            try:
                fallback: R = await backend.run(*args)
                return fallback
            except Exception as exc:  # noqa: BLE001 - we re-raise the last one below
                last_exc = exc
        if last_exc is None:
            raise RuntimeError(
                "fallback composition reached the post-loop branch with no captured exception "
                "(should be impossible if backends list is non-empty)"
            )
        raise last_exc

    if mode is CompositionMode.UNION:
        results: list[R] = [await b.run(*args) for b in backends]
        return _merge_union(results, result_type)

    if mode is CompositionMode.CONSENSUS:
        if consensus_threshold is None:
            raise ValueError("consensus_threshold is required for CompositionMode.CONSENSUS")
        results = [await b.run(*args) for b in backends]
        return _merge_consensus(results, result_type, threshold=consensus_threshold)

    if mode is CompositionMode.PIPELINE:
        value: Any = args[0] if args else None
        for backend in backends:
            value = await backend.run(value)
        return value  # type: ignore[no-any-return]

    raise AssertionError(f"unreachable: {mode!r}")  # pragma: no cover


def _finding_key(finding: BaseModel) -> tuple[Any, ...]:
    """Identity for dedup/consensus. Tuned to existing result-finding shapes."""
    data = finding.model_dump()
    if "cve_id" in data:
        return (data["cve_id"], data.get("component_name"), data.get("component_version"))
    return (data.get("file"), data.get("line"), data.get("rule_id"))


def _merge_union[R: BaseModel](results: list[R], result_type: type[R]) -> R:
    findings = _collect_findings(results)
    seen: dict[tuple[Any, ...], BaseModel] = {}
    for f in findings:
        seen.setdefault(_finding_key(f), f)
    return _build_result(result_type, list(seen.values()), backend_name="union")


def _merge_consensus[R: BaseModel](results: list[R], result_type: type[R], *, threshold: int) -> R:
    counts: Counter[tuple[Any, ...]] = Counter()
    representatives: dict[tuple[Any, ...], BaseModel] = {}
    for r in results:
        per_backend: set[tuple[Any, ...]] = set()
        for f in getattr(r, "findings", []):
            key = _finding_key(f)
            if key not in per_backend:
                per_backend.add(key)
                counts[key] += 1
                representatives.setdefault(key, f)
    kept = [representatives[k] for k, c in counts.items() if c >= threshold]
    return _build_result(result_type, kept, backend_name=f"consensus>={threshold}")


def _collect_findings[R: BaseModel](results: list[R]) -> list[BaseModel]:
    out: list[BaseModel] = []
    for r in results:
        out.extend(getattr(r, "findings", []))
    return out


def _build_result[R: BaseModel](
    result_type: type[R], findings: list[Any], *, backend_name: str
) -> R:
    return result_type(findings=findings, backend_name=backend_name)
