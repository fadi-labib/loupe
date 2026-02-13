from __future__ import annotations

from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "informational"]


class StaticFinding(BaseModel):
    rule_id: str
    file: str
    line: int = Field(ge=0)
    severity: Severity
    message: str


class StaticAnalysisResult(BaseModel):
    findings: list[StaticFinding] = Field(default_factory=list)
    backend_name: str = ""


@runtime_checkable
class StaticAnalysisCapability(Protocol):
    """Tool category: static analysis / SAST."""

    name: str

    async def run(self, repo_path: Path) -> StaticAnalysisResult: ...
