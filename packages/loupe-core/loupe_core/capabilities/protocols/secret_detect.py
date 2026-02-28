from __future__ import annotations

from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "informational"]


class SecretFinding(BaseModel):
    """One leaked-credential candidate."""

    file: str = Field(description="Repo-relative path containing the match.")
    line: int = Field(ge=0, description="1-based line number; 0 for whole-file matches.")
    rule_id: str = Field(description="Backend-specific identifier (e.g., `aws-access-key-id`).")
    redacted_match: str = Field(description="The matched secret, scrubbed for safe display.")
    severity: Severity = Field(default="high", description="Severity; defaults to high.")


class SecretDetectionResult(BaseModel):
    """Typed return of a secret-detection-capability invocation."""

    findings: list[SecretFinding] = Field(default_factory=list, description="All detected secrets.")
    backend_name: str = Field(default="", description="Backend that produced the result.")


@runtime_checkable
class SecretDetectionCapability(Protocol):
    """Tool category: scanning the working tree for leaked credentials."""

    name: str

    async def run(self, repo_path: Path) -> SecretDetectionResult: ...
