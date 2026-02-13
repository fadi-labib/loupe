from __future__ import annotations

from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field


class SbomComponent(BaseModel):
    name: str
    version: str
    purl: str | None = None
    licenses: list[str] = Field(default_factory=list)


class SbomResult(BaseModel):
    components: list[SbomComponent] = Field(default_factory=list)
    sbom_format: Literal["cyclonedx-json", "spdx-json"] = "cyclonedx-json"
    raw_document: str = ""
    backend_name: str = ""


@runtime_checkable
class SbomCapability(Protocol):
    """Tool category: software bill of materials generation."""

    name: str

    async def run(self, repo_path: Path) -> SbomResult: ...
