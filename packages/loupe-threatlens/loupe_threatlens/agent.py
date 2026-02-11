"""PydanticAI agent for ThreatLens.

Builds a configured `Agent` instance that:
- Uses the model named in `THREATLENS_MODEL` env (default: anthropic:claude-opus-4-7)
- Loads its system prompt from prompts/system.md
- Exposes propose_threat as a tool that the model can call
- Receives an `AgentDeps` carrying the shared RunContext, the Layer-1 boundary,
  the loupe directory, and the model identifier (for proposed_by attribution)

The agent itself is built lazily by `build_agent()` so the module imports
without needing any provider SDK installed — the actual Anthropic / OpenAI /
etc. client is only instantiated when `agent.run(...)` is called.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.run_context import RunContext as LoupeRunContext
from pydantic_ai import Agent
from pydantic_ai import RunContext as AgentRunCtx

from loupe_threatlens.tools import (
    ProposeThreatInput,
    ProposeThreatResult,
    propose_threat_impl,
)

DEFAULT_MODEL = "anthropic:claude-opus-4-7"


@dataclass
class AgentDeps:
    """Dependency object passed via PydanticAI's `deps` mechanism.

    Each tool registered on the agent receives an `AgentRunCtx[AgentDeps]`
    and can reach into `ctx.deps` to get the shared run context, the path
    boundary for Layer-1-enforced writes, the loupe directory, and the
    model identifier for attribution.
    """
    ctx: LoupeRunContext
    boundary: PathBoundary
    loupe_dir: Path
    model_id: str


_SYSTEM_PROMPT_PATH = Path(__file__).parent / "prompts" / "system.md"


def _load_system_prompt() -> str:
    return _SYSTEM_PROMPT_PATH.read_text()


def build_agent(model_id: str | None = None) -> Agent[AgentDeps, str]:
    """Construct the ThreatLens PydanticAI agent.

    The actual provider SDK call only happens when `agent.run(...)` is invoked;
    this function is safe to call without any API key set.
    """
    effective_model = model_id or os.environ.get("THREATLENS_MODEL", DEFAULT_MODEL)
    # `defer_model_check=True` postpones provider API-key validation until
    # the first `agent.run()` call. This lets tests and dry-runs construct
    # an agent without keys set, while still failing loudly at invocation.
    agent: Agent[AgentDeps, str] = Agent(
        model=effective_model,
        deps_type=AgentDeps,
        system_prompt=_load_system_prompt(),
        model_settings={"temperature": 0.0},
        defer_model_check=True,
    )

    @agent.tool
    async def propose_threat(
        rc: AgentRunCtx[AgentDeps],
        input: ProposeThreatInput,
    ) -> ProposeThreatResult:
        """Propose a new threat for the project. One call per threat."""
        return propose_threat_impl(
            rc.deps.ctx,
            rc.deps.boundary,
            rc.deps.loupe_dir,
            input,
            model_id=rc.deps.model_id,
        )

    return agent
