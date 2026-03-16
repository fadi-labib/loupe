from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field
from ruamel.yaml import YAML

from loupe_core.artifacts._io import atomic_write_yaml
from loupe_core.artifacts.types import MitigationId, MitigationStatus, ThreatId

_yaml = YAML()
_yaml.default_flow_style = False
_yaml.indent(mapping=2, sequence=4, offset=2)


class Evidence(BaseModel):
    """Pointer into the codebase / docs / external system that backs a mitigation."""

    kind: Literal["code", "doc", "test", "config", "external"] = Field(
        description="Where this evidence lives."
    )
    location: str = Field(min_length=1, description="Path, URL, or other reference.")
    note: str | None = Field(default=None, description="Optional annotation.")


class Mitigation(BaseModel):
    """One mitigation, written into `.loupe/mitigations.yaml`.

    A mitigation addresses one or more threats. It carries a lifecycle state
    (proposed to verified to retired) and Evidence pointers that say where the
    mitigation is realised. Reverse relation: `Threat.mitigation_ids`.
    """

    id: MitigationId = Field(description="Stable ID, format `M-NNN`.")
    title: str = Field(min_length=1, max_length=200, description="Short label.")
    description: str = Field(min_length=1, description="What this mitigation does.")
    threats_addressed: list[ThreatId] = Field(
        default_factory=list, description="Threat IDs this addresses (validated as `T-NNN`)."
    )
    status: MitigationStatus = Field(description="Lifecycle state.")
    evidence: list[Evidence] = Field(
        default_factory=list, description="Where this mitigation is realised."
    )
    verified_by: str | None = Field(default=None, description="Whoever verified the mitigation.")
    last_verified: date | None = Field(default=None, description="When verification happened.")


class MitigationsFile(BaseModel):
    """Root of `.loupe/mitigations.yaml`."""

    schema_version: int = Field(default=1, description="Bumped on breaking schema change.")
    mitigations: list[Mitigation] = Field(
        default_factory=list, description="All mitigations for the project."
    )

    def save(self, path: Path) -> None:
        atomic_write_yaml(path, self.model_dump(mode="json"), yaml=_yaml)

    @classmethod
    def load(cls, path: Path) -> MitigationsFile:
        with path.open("r") as f:
            return cls.model_validate(_yaml.load(f) or {})
