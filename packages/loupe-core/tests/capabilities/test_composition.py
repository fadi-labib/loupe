from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from loupe_core.capabilities.composition import (
    CompositionMode,
    compose_run,
)
from loupe_core.capabilities.protocols import (
    SecretDetectionResult,
    SecretFinding,
)


class _DummyBackend:
    """Configurable async backend used to verify composition modes."""

    def __init__(self, name: str, findings: list[SecretFinding], *, raises: bool = False) -> None:
        self.backend_name = name
        self._findings = findings
        self._raises = raises
        self.invocation_count = 0

    async def run(self, *args: Any, **kwargs: Any) -> SecretDetectionResult:
        self.invocation_count += 1
        if self._raises:
            raise RuntimeError(f"{self.backend_name} died")
        return SecretDetectionResult(findings=list(self._findings), backend_name=self.backend_name)


def _f(path: str, rule: str = "k") -> SecretFinding:
    return SecretFinding(file=path, line=1, rule_id=rule, redacted_match="x", severity="high")


@pytest.mark.asyncio
async def test_single_mode_invokes_first_backend_only():
    a = _DummyBackend("a", [_f("1.py")])
    b = _DummyBackend("b", [_f("2.py")])
    result = await compose_run(
        mode=CompositionMode.SINGLE,
        backends=[a, b],
        result_type=SecretDetectionResult,
        args=(Path("/repo"),),
    )
    assert a.invocation_count == 1
    assert b.invocation_count == 0
    assert [f.file for f in result.findings] == ["1.py"]


@pytest.mark.asyncio
async def test_fallback_mode_tries_next_on_failure():
    failing = _DummyBackend("a", [], raises=True)
    working = _DummyBackend("b", [_f("2.py")])
    result = await compose_run(
        mode=CompositionMode.FALLBACK,
        backends=[failing, working],
        result_type=SecretDetectionResult,
        args=(Path("/repo"),),
    )
    assert failing.invocation_count == 1
    assert working.invocation_count == 1
    assert result.backend_name == "b"


@pytest.mark.asyncio
async def test_fallback_mode_raises_when_all_fail():
    a = _DummyBackend("a", [], raises=True)
    b = _DummyBackend("b", [], raises=True)
    with pytest.raises(RuntimeError):
        await compose_run(
            mode=CompositionMode.FALLBACK,
            backends=[a, b],
            result_type=SecretDetectionResult,
            args=(Path("/repo"),),
        )


@pytest.mark.asyncio
async def test_union_mode_merges_findings_dedup_by_identity():
    a = _DummyBackend("a", [_f("shared.py"), _f("a_only.py")])
    b = _DummyBackend("b", [_f("shared.py"), _f("b_only.py")])
    result = await compose_run(
        mode=CompositionMode.UNION,
        backends=[a, b],
        result_type=SecretDetectionResult,
        args=(Path("/repo"),),
    )
    files = sorted(f.file for f in result.findings)
    # shared.py appears once (deduped on (file, line, rule_id)); a_only + b_only present
    assert files == ["a_only.py", "b_only.py", "shared.py"]


@pytest.mark.asyncio
async def test_consensus_mode_keeps_findings_meeting_threshold():
    a = _DummyBackend("a", [_f("agreed.py"), _f("a_only.py")])
    b = _DummyBackend("b", [_f("agreed.py"), _f("b_only.py")])
    c = _DummyBackend("c", [_f("agreed.py")])
    result = await compose_run(
        mode=CompositionMode.CONSENSUS,
        backends=[a, b, c],
        result_type=SecretDetectionResult,
        args=(Path("/repo"),),
        consensus_threshold=2,
    )
    assert [f.file for f in result.findings] == ["agreed.py"]


@pytest.mark.asyncio
async def test_consensus_requires_threshold_parameter():
    a = _DummyBackend("a", [_f("x.py")])
    with pytest.raises(ValueError, match="consensus_threshold"):
        await compose_run(
            mode=CompositionMode.CONSENSUS,
            backends=[a],
            result_type=SecretDetectionResult,
            args=(Path("/repo"),),
        )


@pytest.mark.asyncio
async def test_pipeline_mode_feeds_output_to_next_backend():
    # Pipeline semantics: backend N receives the *result* of backend N-1.
    # We use SbomResult → CveResult to exercise the cross-type pipeline path.
    from loupe_core.capabilities.protocols import CveFinding, CveResult, SbomResult

    class _Sbom:
        backend_name = "sbom-stage"

        async def run(self, repo: Path) -> SbomResult:
            return SbomResult(backend_name="sbom-stage", raw_document="{}")

    class _Cve:
        backend_name = "cve-stage"

        async def run(self, sbom: SbomResult) -> CveResult:
            assert sbom.backend_name == "sbom-stage"
            return CveResult(
                backend_name="cve-stage",
                findings=[
                    CveFinding(
                        cve_id="CVE-1",
                        component_name="x",
                        component_version="1",
                        severity="high",
                        summary="y",
                    )
                ],
            )

    result = await compose_run(
        mode=CompositionMode.PIPELINE,
        backends=[_Sbom(), _Cve()],
        result_type=CveResult,
        args=(Path("/repo"),),
    )
    assert result.backend_name == "cve-stage"
    assert result.findings[0].cve_id == "CVE-1"
