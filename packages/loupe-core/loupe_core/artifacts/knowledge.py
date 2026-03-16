from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints
from ruamel.yaml import YAML

from loupe_core.artifacts._io import atomic_write_yaml

AssetId = Annotated[str, StringConstraints(pattern=r"^A-\d{3,}$")]
ElementId = Annotated[str, StringConstraints(pattern=r"^E-\d{3,}$")]
DecisionId = Annotated[str, StringConstraints(pattern=r"^D-\d{4}-\d{2}-\d{2}-[a-z0-9-]+$")]
FactId = Annotated[str, StringConstraints(pattern=r"^F-\d{3,}$")]

_yaml = YAML()
_yaml.default_flow_style = False
_yaml.indent(mapping=2, sequence=4, offset=2)


class Asset(BaseModel):
    id: AssetId
    name: str
    description: str
    criticality: Literal["low", "medium", "high", "critical"]
    facts_supporting: list[str] = Field(default_factory=list)
    first_identified: date
    confirmed_by_human: bool = False


class Element(BaseModel):
    id: ElementId
    name: str
    type: Literal["trust_boundary", "process", "data_store", "external_entity", "data_flow"]
    interfaces: list[str] = Field(default_factory=list)


class Decision(BaseModel):
    id: DecisionId
    type: Literal["risk_acceptance", "design_choice", "deferral"]
    rationale_file: str
    authored_by: Literal["human"]


class CrossReference(BaseModel):
    asset: str
    threat_ids: list[str] = Field(default_factory=list)
    hazard_ids: list[str] = Field(default_factory=list)
    privacy_concerns: list[str] = Field(default_factory=list)


class KnowledgeGraph(BaseModel):
    schema_version: int = 1
    last_updated: datetime
    assets: list[Asset] = Field(default_factory=list)
    elements: list[Element] = Field(default_factory=list)
    decisions: list[Decision] = Field(default_factory=list)
    cross_references: list[CrossReference] = Field(default_factory=list)

    def save(self, path: Path) -> None:
        atomic_write_yaml(path, self.model_dump(mode="json"), yaml=_yaml)

    @classmethod
    def load(cls, path: Path) -> KnowledgeGraph:
        with path.open("r") as f:
            return cls.model_validate(_yaml.load(f) or {})

    @classmethod
    def load_or_empty(cls, path: Path) -> KnowledgeGraph:
        if not path.exists():
            return cls(last_updated=datetime.now(UTC))
        return cls.load(path)
