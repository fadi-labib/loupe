from __future__ import annotations
from datetime import date
from pathlib import Path
from typing import Annotated
from pydantic import BaseModel, Field, StringConstraints
from ruamel.yaml import YAML
from loupe_core.artifacts.types import Severity, ThreatStatus, StrideCategory

ThreatId = Annotated[str, StringConstraints(pattern=r"^T-\d{3,}$")]
ElementId = Annotated[str, StringConstraints(pattern=r"^E-\d{3,}$")]

_yaml = YAML()
_yaml.default_flow_style = False
_yaml.indent(mapping=2, sequence=4, offset=2)


class Threat(BaseModel):
    id: ThreatId
    element_id: ElementId
    stride_category: StrideCategory
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1)
    severity: Severity
    status: ThreatStatus
    mitigation_ids: list[str] = Field(default_factory=list)
    cwe_refs: list[str] = Field(default_factory=list)
    attack_pattern_refs: list[str] = Field(default_factory=list)
    introduced_in_pr: str | None = None
    last_reviewed: date
    review_due: date | None = None
    rationale: str
    proposed_by: str


class ThreatsFile(BaseModel):
    schema_version: int = 1
    threats: list[Threat] = Field(default_factory=list)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.model_dump(mode="json")
        with path.open("w") as f:
            _yaml.dump(data, f)

    @classmethod
    def load(cls, path: Path) -> "ThreatsFile":
        with path.open("r") as f:
            data = _yaml.load(f) or {}
        return cls.model_validate(data)
