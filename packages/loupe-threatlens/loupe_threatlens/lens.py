"""ThreatLens — Loupe's v1 lens for STRIDE-based threat modelling.

Phase 6 of the implementation plan fleshes out the real PydanticAI agent
and the tool surface. This module provides the minimum required by the
Lens protocol so that the entry point loads cleanly and the platform's
end-to-end plumbing can be exercised without an LLM call.

The `is_relevant()` heuristic is already implemented (Task 6.1) because
it's pure Python and no LLM. The `run()` method is a no-op until Task 6.3
wires in the PydanticAI agent; calling `run()` on this stub will produce
no artefacts but will not error.
"""
from __future__ import annotations
from pathlib import Path
from loupe_core.lens_api import LensCapabilities
from loupe_core.run_context import RunContext, RelevanceScore


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
    )

    def build_agent(self, deps_type: type) -> None:
        # Phase 6 (Task 6.3) returns a configured PydanticAI Agent.
        return None

    def mcp_tools(self) -> list:
        # Phase 9 (Task 9.3) returns the granular MCP tool list.
        return []

    def mcp_workflows(self) -> list:
        # Phase 9 returns workflow definitions.
        return []

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
        plan_entry,
        boundary,
        loupe_dir,
    ) -> None:
        """Stub. Phase 6 (Task 6.3) wires in the PydanticAI agent + tool calls."""
        return None
