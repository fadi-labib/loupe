from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints
from ruamel.yaml import YAML

from loupe_core.artifacts.types import Severity, StrideCategory, ThreatStatus

ThreatId = Annotated[str, StringConstraints(pattern=r"^T-\d{3,}$")]
ElementId = Annotated[str, StringConstraints(pattern=r"^E-\d{3,}$")]

_yaml = YAML()
_yaml.default_flow_style = False
_yaml.indent(mapping=2, sequence=4, offset=2)


class Threat(BaseModel):
    """One STRIDE-category threat, written into `.loupe/threats.yaml`.

    Threats start as `proposed` (agent-written) and humans transition them through
    `accepted` / `mitigated` / `accepted_risk` / `rejected`. Every threat references
    a system element and carries a stable ID for cross-reference and audit.
    """

    id: ThreatId = Field(description="Stable ID, format `T-NNN`.")
    element_id: ElementId = Field(description="System component this applies to (`E-NNN`).")
    stride_category: StrideCategory = Field(description="Single-letter STRIDE category.")
    title: str = Field(min_length=1, max_length=200, description="Short label for summaries.")
    description: str = Field(min_length=1, description="Full prose description.")
    severity: Severity = Field(description="Severity rating; feeds CI gating.")
    status: ThreatStatus = Field(description="Lifecycle state; humans transition past `proposed`.")
    mitigation_ids: list[str] = Field(
        default_factory=list, description="Mitigation IDs that address this threat."
    )
    cwe_refs: list[str] = Field(
        default_factory=list, description="CWE identifiers, e.g., `CWE-79`."
    )
    attack_pattern_refs: list[str] = Field(
        default_factory=list, description="CAPEC or similar refs."
    )
    introduced_in_pr: str | None = Field(
        default=None, description="PR number that introduced this."
    )
    last_reviewed: date = Field(description="When a human last reviewed.")
    review_due: date | None = Field(default=None, description="Next-review schedule.")
    rationale: str = Field(description="Why this threat exists; how it was identified.")
    proposed_by: str = Field(description="Agent identity or human name.")


class ThreatsFile(BaseModel):
    """Root of `.loupe/threats.yaml`."""

    schema_version: int = Field(default=1, description="Bumped on breaking schema change.")
    threats: list[Threat] = Field(default_factory=list, description="All threats for the project.")

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.model_dump(mode="json")
        with path.open("w") as f:
            _yaml.dump(data, f)

    @classmethod
    def load(cls, path: Path) -> ThreatsFile:
        with path.open("r") as f:
            data = _yaml.load(f) or {}
        return cls.model_validate(data)
