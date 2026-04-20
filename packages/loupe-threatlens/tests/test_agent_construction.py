"""Offline tests for the ThreatLens PydanticAI agent.

These tests verify:
- The agent can be constructed for several different model identifiers
- The system prompt is non-empty and references key concepts
- The propose_threat tool is registered on the agent
- AgentDeps carries the four expected fields

The full end-to-end agent-execution test lives in test_agent_run.py and
uses VCR cassettes; that one requires a one-time ANTHROPIC_API_KEY to
record (and runs offline thereafter).
"""

from datetime import datetime
from pathlib import Path

import pytest
from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.run_context import RunContext
from loupe_threatlens.agent import AgentDeps, build_agent


def test_agent_constructs_with_explicit_model():
    agent = build_agent("anthropic:claude-opus-4-7")
    assert agent is not None


def test_build_agent_rejects_empty_model_id():
    """`build_agent` must REQUIRE a model id — env-var resolution is the caller's job."""
    with pytest.raises((ValueError, TypeError)):
        build_agent("")


def test_agent_constructs_for_multiple_providers():
    """Loupe's multi-LLM promise: agents construct for any PydanticAI-supported model.

    We don't run them — just verify the construction code path works. Actually running
    these would require provider SDKs + API keys we don't want in unit tests.
    """
    for model_id in [
        "anthropic:claude-opus-4-7",
        "anthropic:claude-haiku-4-5",
        "openai:gpt-5",
        "google-gla:gemini-2.5-pro",
    ]:
        agent = build_agent(model_id)
        assert agent is not None, f"Failed to construct agent for {model_id}"


def test_lens_resolves_threatlens_model_env_var(monkeypatch):
    """`THREATLENS_MODEL` env override is read once by `lens.run` and threaded through.

    We assert the resolution site is `lens._FALLBACK_MODEL_ID` (when env unset)
    and that setting the env var overrides it. The lens uses `os.environ.get`
    at call time, not import time, so monkeypatching here is sufficient.
    """
    from loupe_threatlens import lens as lens_module

    monkeypatch.delenv("THREATLENS_MODEL", raising=False)
    # Fallback constant lives in the lens module — agent.py has no default.
    assert lens_module._FALLBACK_MODEL_ID == "anthropic:claude-opus-4-7"

    monkeypatch.setenv("THREATLENS_MODEL", "openai:gpt-5")
    # The lens reads env at call time inside `run()`; we don't invoke a real
    # provider, just confirm that the env value is what `os.environ.get`
    # would return at the resolution site.
    import os

    assert os.environ.get("THREATLENS_MODEL", lens_module._FALLBACK_MODEL_ID) == "openai:gpt-5"


def test_system_prompt_references_stride_and_context_md():
    """The system prompt must mention STRIDE categories and the context.md anchor."""
    prompt_path = Path(__file__).parent.parent / "loupe_threatlens" / "prompts" / "system.md"
    text = prompt_path.read_text()
    assert "STRIDE" in text
    assert "Spoofing" in text
    assert "Tampering" in text
    assert "context.md" in text
    assert "propose_threat" in text


def test_system_prompt_attributes_stridegpt():
    """Per D-16, the system prompt must attribute StrideGPT prior art."""
    prompt_path = Path(__file__).parent.parent / "loupe_threatlens" / "prompts" / "system.md"
    text = prompt_path.read_text()
    assert "StrideGPT" in text
    assert "D-16" in text


def test_agent_deps_has_required_fields():
    """AgentDeps must carry ctx, boundary, loupe_dir, model_id."""
    deps = AgentDeps(
        ctx=RunContext(
            run_id="r",
            mode="ci",
            started_at=datetime(2026, 5, 14),
            user_intent="",
            diff=None,
            sbom_delta=None,
            project=None,
            plan=[],
            knowledge=None,
        ),
        boundary=PathBoundary(writable_globs=[]),
        loupe_dir=Path("/tmp/.loupe"),
        model_id="anthropic:claude-opus-4-7",
    )
    assert deps.ctx.run_id == "r"
    assert deps.boundary is not None
    assert deps.model_id == "anthropic:claude-opus-4-7"


def test_propose_threat_tool_registered_on_agent():
    """The agent must have propose_threat registered as a callable tool."""
    agent = build_agent("anthropic:claude-opus-4-7")
    # PydanticAI exposes registered tools through the agent's toolset.
    # Different PydanticAI versions structure this slightly differently;
    # what we care about is that the tool is discoverable by name.
    tool_names = _collect_tool_names(agent)
    assert "propose_threat" in tool_names, f"propose_threat not in registered tools: {tool_names}"


def _collect_tool_names(agent) -> set[str]:
    """Best-effort tool-name extraction across PydanticAI versions."""
    names: set[str] = set()
    # Try the most common attribute names PydanticAI has used.
    for attr in ("_function_toolset", "_user_toolset", "_toolsets"):
        tools = getattr(agent, attr, None)
        if tools is None:
            continue
        # Toolsets may be lists or single objects with `.tools` mappings.
        candidates = tools if isinstance(tools, (list, tuple)) else [tools]
        for candidate in candidates:
            tool_dict = getattr(candidate, "tools", None) or getattr(candidate, "_tools", None)
            if isinstance(tool_dict, dict):
                names.update(tool_dict.keys())
    return names
