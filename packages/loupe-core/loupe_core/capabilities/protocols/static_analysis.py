from __future__ import annotations

from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "informational"]


class StaticFinding(BaseModel):
    """One SAST-rule violation."""

    rule_id: str = Field(description="Rule identifier from the analyser.")
    file: str = Field(description="Repo-relative path of the violation.")
    line: int | None = Field(
        default=None,
        ge=1,
        description="1-based line number; None for whole-file or unknown.",
    )
    severity: Severity = Field(description="Severity assigned by the rule.")
    message: str = Field(description="One-line description from the analyser.")


class StaticAnalysisResult(BaseModel):
    """Typed return of a static-analysis-capability invocation."""

    findings: list[StaticFinding] = Field(default_factory=list, description="All findings.")
    backend_name: str = Field(default="", description="Backend that produced the result.")


@runtime_checkable
class StaticAnalysisCapability(Protocol):
    """Tool category: static analysis / SAST."""

    name: str

    async def run(self, repo_path: Path) -> StaticAnalysisResult: ...
