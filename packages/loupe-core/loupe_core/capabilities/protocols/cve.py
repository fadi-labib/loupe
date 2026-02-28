from __future__ import annotations

from collections import defaultdict
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from loupe_core.capabilities.protocols.sbom import SbomResult

Severity = Literal["critical", "high", "medium", "low", "informational"]


class CveFinding(BaseModel):
    """A single CVE matched against a component in the SBOM."""

    cve_id: str = Field(description="CVE identifier such as `CVE-2024-12345`.")
    component_name: str = Field(description="SBOM component the CVE applies to.")
    component_version: str = Field(description="Component version when matched.")
    severity: Severity = Field(description="Severity normalised to five levels.")
    summary: str = Field(description="One-line description from the source feed.")
    source_url: str | None = Field(default=None, description="Authoritative URL for the CVE.")
    cvss_score: float | None = Field(
        default=None, ge=0.0, le=10.0, description="CVSS base score 0.0-10.0."
    )
    fixed_version: str | None = Field(default=None, description="Upstream-fixed version.")


class CveResult(BaseModel):
    """Typed return of a CVE-capability invocation."""

    findings: list[CveFinding] = Field(default_factory=list, description="All matched CVEs.")
    backend_name: str = Field(default="", description="Backend that produced the result.")

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
