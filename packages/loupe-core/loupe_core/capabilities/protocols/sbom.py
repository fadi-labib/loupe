from __future__ import annotations

from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field


class SbomComponent(BaseModel):
    """One package entry in an SBOM."""

    name: str = Field(description="Package name.")
    version: str = Field(description="Package version.")
    purl: str | None = Field(default=None, description="Package URL per the purl-spec.")
    licenses: list[str] = Field(default_factory=list, description="SPDX license identifiers.")


class SbomResult(BaseModel):
    """Typed return of an SBOM-capability invocation."""

    components: list[SbomComponent] = Field(
        default_factory=list, description="Parsed component entries."
    )
    sbom_format: Literal["cyclonedx-json", "spdx-json"] = Field(
        default="cyclonedx-json", description="Standard the raw document follows."
    )
    raw_document: str = Field(default="", description="Complete SBOM text from the backend.")
    backend_name: str = Field(default="", description="Backend that produced the result.")


@runtime_checkable
class SbomCapability(Protocol):
    """Tool category: software bill of materials generation."""

    name: str

    async def run(self, repo_path: Path) -> SbomResult: ...
