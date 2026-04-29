from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from loupe_core.run_context import RelevanceScore, RunContext


class LensCapabilities(BaseModel):
    name: str
    domain: str
    handles_intent_keywords: list[str] = Field(default_factory=list)
    artifact_paths: list[str] = Field(default_factory=list)
    requires_lenses: list[str] = Field(default_factory=list)
    # D-18: capability categories this lens needs (e.g., ["sbom", "cve"]).
    # The coordinator resolves the union across selected lenses and the
    # capability registry runs each backend once, populating typed fields
    # on RunContext that every lens then reads.
    #
    # D-23: split into required vs. preferred. A required-but-unavailable
    # capability raises RequiredCapabilityUnavailable at bootstrap time
    # and the CLI exits 64 (EX_USAGE). A preferred-but-unavailable
    # capability lets the lens run with the slot set to None; the run
    # record carries a structured capability_degraded entry so the
    # degradation is auditor-visible without breaking the run.
    requires_capabilities: list[str] = Field(default_factory=list)
    prefers_capabilities: list[str] = Field(default_factory=list)


class McpTool(BaseModel):
    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    handler_path: str  # dotted python path to callable


class McpWorkflow(BaseModel):
    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    handler_path: str


@runtime_checkable
class Lens(Protocol):
    capabilities: LensCapabilities

    def build_agent(self, deps_type: type) -> Any: ...
    def mcp_tools(self) -> list[McpTool]: ...
    def mcp_workflows(self) -> list[McpWorkflow]: ...
    def is_relevant(self, run_ctx: RunContext) -> RelevanceScore: ...
    async def run(
        self,
        ctx: RunContext,
        plan_entry: Any,
        boundary: Any,
        loupe_dir: Any,
    ) -> None: ...
