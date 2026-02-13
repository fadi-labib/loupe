from __future__ import annotations

from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "informational"]


class SecretFinding(BaseModel):
    file: str
    line: int = Field(ge=0)
    rule_id: str
    redacted_match: str
    severity: Severity = "high"


class SecretDetectionResult(BaseModel):
    findings: list[SecretFinding] = Field(default_factory=list)
    backend_name: str = ""


@runtime_checkable
class SecretDetectionCapability(Protocol):
    """Tool category: scanning the working tree for leaked credentials."""

    name: str

    async def run(self, repo_path: Path) -> SecretDetectionResult: ...
