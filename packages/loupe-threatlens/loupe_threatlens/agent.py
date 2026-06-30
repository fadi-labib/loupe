"""PydanticAI agent for ThreatLens.

Builds a configured `Agent` instance that:
- Uses the model identifier resolved by the caller (typically `lens.run`,
  which reads `THREATLENS_MODEL` once and passes the result here)
- Loads its system prompt from prompts/system.md
- Exposes propose_threat as a tool that the model can call
- Receives an `AgentDeps` carrying the shared RunContext, the Layer-1 boundary,
  the loupe directory, and the model identifier (for proposed_by attribution)

Per principle §3 (multi-LLM by default), this module does NOT hardcode a
default provider/model. Env-var resolution lives in exactly one place —
`lens.run` — and the resolved id is passed into `build_agent` explicitly.

The agent itself is built lazily by `build_agent()` so the module imports
without needing any provider SDK installed — the actual Anthropic / OpenAI /
etc. client is only instantiated when `agent.run(...)` is called.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.run_context import RunContext as LoupeRunContext
from pydantic_ai import Agent, AgentRetries
from pydantic_ai import RunContext as AgentRunCtx
from pydantic_ai.settings import ModelSettings

from loupe_threatlens.tools import (
    ProposeThreatInput,
    ProposeThreatResult,
    propose_threat_impl,
)


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


# F-08: Anthropic thinking-class models reject sampling parameters
# (PydanticAI emits a UserWarning + ignores the setting). Match against
# the provider:model id prefixes here; new thinking-class models can
# be added without touching build_agent. Non-Anthropic providers and
# Anthropic non-thinking models (claude-haiku-4-5, claude-sonnet-3-5
# etc.) accept temperature normally.
_REJECTS_TEMPERATURE_PREFIXES: tuple[str, ...] = (
    "anthropic:claude-opus-4",
    "anthropic:claude-sonnet-4",  # thinking-mode sonnet variants
)


def _model_rejects_temperature(model_id: str) -> bool:
    return model_id.startswith(_REJECTS_TEMPERATURE_PREFIXES)


def build_agent(model_id: str) -> Agent[AgentDeps, str]:
    """Construct the ThreatLens PydanticAI agent for the given model id.

    `model_id` is REQUIRED — env-var resolution is the caller's job (see
    `lens.run`). This keeps env reads to a single site and prevents drift
    when env mutates between resolution and agent construction.

    The actual provider SDK call only happens when `agent.run(...)` is invoked;
    this function is safe to call without any API key set.
    """
    if not model_id:
        raise ValueError("build_agent requires a non-empty model_id")
    # `defer_model_check=True` postpones provider API-key validation until
    # the first `agent.run()` call. This lets tests and dry-runs construct
    # an agent without keys set, while still failing loudly at invocation.
    # `retries={'tools': 3}` allows the model up to three chances to correct
    # a malformed `propose_threat` argument list before the agent aborts.
    # PydanticAI's default of 1 is too brittle for `loupe scan` workloads
    # over large source trees: one mis-shaped tool call out of many
    # crashes the entire lens (observed: a `propose_threat` call missing
    # required fields when scanning Mongoose's MQTT/HTTP/TLS sources at
    # once). Three attempts costs at most a few extra request round-trips
    # but lets the model self-correct from validation feedback instead of
    # losing every successfully-proposed threat in the same run.
    #
    # F-08: only set `temperature` when the model is known to accept it.
    # Anthropic's thinking-class models (Opus 4.x, Sonnet 4.x thinking
    # variants) reject sampling parameters; setting temperature there
    # produces a UserWarning per agent.run() call (twice per run with
    # three tool retries, four times with retries observed). Empty
    # model_settings keeps the model on its provider-default temperature
    # which is already low for Anthropic's reasoning models.
    model_settings: ModelSettings = {}
    if not _model_rejects_temperature(model_id):
        model_settings["temperature"] = 0.0

    agent: Agent[AgentDeps, str] = Agent(
        model=model_id,
        deps_type=AgentDeps,
        system_prompt=_load_system_prompt(),
        model_settings=model_settings,
        defer_model_check=True,
        retries=AgentRetries(tools=3),
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
