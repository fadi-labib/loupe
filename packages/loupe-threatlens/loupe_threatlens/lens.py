"""ThreatLens — Loupe's v1 lens for STRIDE-based threat modelling.

Wires the PydanticAI agent (defined in agent.py) into the Lens protocol.
The lens is responsible for: declaring static capabilities, computing
relevance from the diff (pure Python, no LLM), and orchestrating one
agent invocation when run.

Per D-16, the system prompt at prompts/system.md is informed by
StrideGPT's prompt structure (MIT-licensed prior art).
"""
from __future__ import annotations

import os
from pathlib import Path

from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.lens_api import LensCapabilities, McpTool, McpWorkflow
from loupe_core.pricing import estimate_cost_usd
from loupe_core.run_context import LensRunPlan, LensUsage, RelevanceScore, RunContext

from loupe_threatlens.agent import DEFAULT_MODEL, AgentDeps, build_agent
from loupe_threatlens.mcp_tools import register_threatlens_mcp_tools
from loupe_threatlens.user_prompt import build_user_prompt

_CODE_EXTS = (
    ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs",
    ".java", ".kt", ".swift", ".c", ".cpp", ".cs", ".rb",
)
_DEP_FILES = {
    "requirements.txt", "Pipfile", "package.json", "pnpm-lock.yaml",
    "Cargo.toml", "go.mod", "pom.xml", "Gemfile",
}


class ThreatLens:
    """STRIDE threat-modelling lens. v1 ships with a stub run() — Phase 6 wires the agent."""

    capabilities = LensCapabilities(
        name="threatlens",
        domain="security",
        handles_intent_keywords=[
            "threat", "STRIDE", "TARA", "CRA", "asset", "attack", "vex", "cve", "sbom",
        ],
        artifact_paths=[
            ".loupe/threats.yaml",
            ".loupe/mitigations.yaml",
            ".loupe/threat-model.md",
            ".loupe/vex.json",
            ".loupe/sbom.cdx.json",
        ],
        # D-18: SBOM + CVE come from the capability layer. ThreatLens reads
        # the typed results off ctx.sbom / ctx.cve_findings; no subprocess
        # calls inside the lens, and any other lens needing the same data
        # observes it on the shared blackboard (VALUES §4).
        requires_capabilities=["sbom", "cve"],
    )

    def build_agent(self, deps_type: type) -> None:
        # The PydanticAI agent is built lazily inside `run()` so we don't
        # construct a model client when only `is_relevant()` is needed.
        return None

    def mcp_tools(self) -> list[McpTool]:
        # The declarative McpTool list is intentionally empty at v1.
        # ThreatLens contributes tools via `register_to_mcp` below — see
        # the docstring on `register_to_mcp` and on
        # `loupe_core.mcp_server.build_mcp_server` for why we bypass the
        # mcp_tools dance for now.
        return []

    def mcp_workflows(self) -> list[McpWorkflow]:
        return []

    def register_to_mcp(self, server: object, loupe_dir: Path) -> None:
        """Add ThreatLens-specific tools to a FastMCP server instance.

        Called by `loupe_core.mcp_server.build_mcp_server` when the
        operator launches `loupe mcp`. The `server` argument is a
        `mcp.server.fastmcp.FastMCP` instance; we use `object` in the
        type hint here so this module doesn't take a hard import on
        `mcp` (lens packages shouldn't dictate the platform's choice
        of MCP framework — they share the choice that loupe-core makes
        per D-21).
        """
        register_threatlens_mcp_tools(server, loupe_dir)

    def is_relevant(self, ctx: RunContext) -> RelevanceScore:
        """Pure-Python relevance heuristic. No LLM call.

        Higher score → coordinator includes the lens in the run plan.
        See [`DESIGN-DECISIONS.md` D-11] for the contract.
        """
        paths = ctx.diff.changed_paths if ctx.diff else []
        if any(p.endswith(_CODE_EXTS) for p in paths):
            return RelevanceScore(score=0.95, reason="code changes likely affect threat surface")
        if any(Path(p).name in _DEP_FILES for p in paths):
            return RelevanceScore(score=0.80, reason="dependency changes affect SBOM/CVE")
        if any(p.startswith(".github/workflows/") for p in paths):
            return RelevanceScore(score=0.60, reason="CI/CD changes may affect trust boundaries")
        return RelevanceScore(score=0.10, reason="no security-relevant files touched")

    async def run(
        self,
        ctx: RunContext,
        plan_entry: LensRunPlan,
        boundary: PathBoundary,
        loupe_dir: Path,
    ) -> None:
        """Invoke the PydanticAI agent for one threat-modelling pass.

        Assembles a structured user prompt from `RunContext` — diff,
        project context, SBOM components, CVE findings, known
        architectural elements — and runs the agent against it. The
        agent emits threats via `propose_threat` tool calls; the free-text
        return value is discarded. Structured artefacts written through
        the Layer-1-enforced tool surface are the only product.
        """
        model_id = os.environ.get("THREATLENS_MODEL", DEFAULT_MODEL)
        agent = build_agent(model_id)
        deps = AgentDeps(
            ctx=ctx,
            boundary=boundary,
            loupe_dir=loupe_dir,
            model_id=model_id,
        )
        prompt = build_user_prompt(ctx, plan_entry)
        result = await agent.run(prompt, deps=deps)

        # Capture token usage so the run record can carry real numbers
        # rather than the placeholder zeros [principle §8 — cost discipline].
        # PydanticAI exposes usage as a method on AgentRunResult (older
        # versions used a property); handle both by calling when callable.
        # Inner attributes are guarded with getattr so providers that emit
        # fewer fields don't raise.
        usage_attr = getattr(result, "usage", None)
        usage = usage_attr() if callable(usage_attr) else usage_attr
        if usage is not None:
            entry = LensUsage(
                model_id=model_id,
                input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
                output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
                cache_read_tokens=int(getattr(usage, "cache_read_tokens", 0) or 0),
                cache_write_tokens=int(getattr(usage, "cache_write_tokens", 0) or 0),
            )
            entry.cost_usd_estimate = estimate_cost_usd(entry)
            ctx.lens_usage[self.capabilities.name] = entry
