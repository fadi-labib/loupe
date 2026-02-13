from __future__ import annotations

from collections import defaultdict
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from loupe_core.capabilities.protocols.sbom import SbomResult

Severity = Literal["critical", "high", "medium", "low", "informational"]


class CveFinding(BaseModel):
    cve_id: str
    component_name: str
    component_version: str
    severity: Severity
    summary: str
    source_url: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    fixed_version: str | None = None


class CveResult(BaseModel):
    findings: list[CveFinding] = Field(default_factory=list)
    backend_name: str = ""

    def by_severity(self) -> dict[Severity, list[CveFinding]]:
        out: dict[Severity, list[CveFinding]] = defaultdict(list)
        for f in self.findings:
            out[f.severity].append(f)
        return dict(out)


@runtime_checkable
class CveCapability(Protocol):
    """Tool category: CVE / vulnerability matching against an SBOM."""

    name: str

    async def run(self, sbom: SbomResult) -> CveResult: ...
