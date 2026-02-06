from __future__ import annotations
from datetime import date
from pathlib import Path
from typing import Annotated, Literal
from pydantic import BaseModel, Field, StringConstraints
from ruamel.yaml import YAML
from loupe_core.artifacts.types import MitigationStatus

MitigationId = Annotated[str, StringConstraints(pattern=r"^M-\d{3,}$")]

_yaml = YAML()
_yaml.default_flow_style = False
_yaml.indent(mapping=2, sequence=4, offset=2)


class Evidence(BaseModel):
    kind: Literal["code", "doc", "test", "config", "external"]
    location: str = Field(min_length=1)
    note: str | None = None


class Mitigation(BaseModel):
    id: MitigationId
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1)
    threats_addressed: list[str] = Field(default_factory=list)
    status: MitigationStatus
    evidence: list[Evidence] = Field(default_factory=list)
    verified_by: str | None = None
    last_verified: date | None = None


class MitigationsFile(BaseModel):
    schema_version: int = 1
    mitigations: list[Mitigation] = Field(default_factory=list)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w") as f:
            _yaml.dump(self.model_dump(mode="json"), f)

    @classmethod
    def load(cls, path: Path) -> "MitigationsFile":
        with path.open("r") as f:
            return cls.model_validate(_yaml.load(f) or {})
