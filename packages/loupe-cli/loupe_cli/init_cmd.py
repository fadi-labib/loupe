"""`loupe init` — scaffold .loupe/ in the current working directory.

Creates a minimal layout that:
- Parses cleanly via ProjectContext.from_markdown (all required sections present)
- Round-trips through LoupeConfig validation
- Round-trips through KnowledgeGraph.load (so the very first lens run can read it)
- Has agent_writable_paths set to the v1 default set
- Includes runs/ and decisions/ subdirectories so the very first run doesn't
  have to mkdir them on the fly

Templates carry "TODO" markers in places the human is expected to fill in.
The agent never auto-fills these — they're human-owned by Layer 1 design.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import typer
from loupe_core.artifacts.knowledge import KnowledgeGraph

# BSD sysexits.h EX_USAGE — operator-config / usage errors.
USAGE_ERROR = 64

_DEFAULT_CONTEXT = """\
---
schema_version: 1
last_human_edit: 2026-05-14
maintained_by: your-team@example.com
---

# Product Context

## Product description
TODO: Describe your product in 2-3 sentences. What does it do? Who is it for?
This is the anti-hallucination anchor for every agent run -- keep it accurate.

## Critical assets
- TODO: list each critical asset on its own bullet (e.g., "card numbers", "API keys")

## Users and roles
- TODO: list each user type and what they can do
- example-role: short description of permissions

## Deployment
TODO: Where does this run? Container on AWS? Self-hosted? Edge?
What's the trust boundary topology?

## Threat actors of concern
- TODO: who do you worry about? Compromised internal services? Insiders?
- Supply-chain compromise via PyPI/npm?

## Out of scope
- TODO: list things you explicitly do NOT worry about (e.g., physical attacks,
- denial-of-service from upstream CDN)
"""

_DEFAULT_CONFIG = """\
schema_version: 1

models:
  # PydanticAI native `provider:model` form. Loupe is multi-LLM by design
  # (principle §3) — pick whichever provider matches your team's setup.
  default: anthropic:claude-opus-4-7
  # default: openai:gpt-5
  # default: google-gla:gemini-2.5-pro
  # default: ollama:llama-3.3-70b  # local, no API key

limits:
  per_run_max_usd: 2.50
  per_run_max_tokens_in: 500000
  per_run_max_steps: 30

ci:
  # Severities that fail the build (exit code 1). Bare severity strings
  # match the Action's gate today: 'critical', 'high', 'medium', 'low'.
  # Richer semantic tokens (e.g., 'new_critical_threat_unmitigated') are
  # planned but not yet consumed by the gate logic.
  fail_on:
    - critical
    - high
  warn_on:
    - medium
  ignore_paths:
    - "docs/**"

agent_writable_paths:
  - .loupe/threats.yaml
  - .loupe/mitigations.yaml
  - .loupe/threat-model.md
  - .loupe/vex.json
  - .loupe/sbom.cdx.json
  - .loupe/knowledge.yaml
  - .loupe/runs/**

lenses:
  threatlens:
    enabled: true
    minimum_relevance: 0.3
"""


_KNOWLEDGE_HEADER = (
    "# .loupe/knowledge.yaml\n"
    "# Persistent knowledge graph populated across runs.\n"
    "# Lenses promote high-confidence Facts here; humans curate the rest.\n"
    "# Safe to delete to reset; the next run rebuilds an empty graph.\n"
)


def init_command() -> None:
    """Initialise .loupe/ in the current directory."""
    cwd = Path.cwd()
    loupe = cwd / ".loupe"
    if loupe.exists():
        typer.echo(f"Error: {loupe} already exists. Aborting.", err=True)
        raise typer.Exit(code=USAGE_ERROR)
    loupe.mkdir()
    (loupe / "context.md").write_text(_DEFAULT_CONTEXT)
    (loupe / "config.yaml").write_text(_DEFAULT_CONFIG)
    _write_empty_knowledge(loupe / "knowledge.yaml")
    (loupe / "runs").mkdir()
    (loupe / "decisions").mkdir()
    typer.echo(f"Initialised {loupe}.")
    typer.echo(
        "Edit .loupe/context.md to describe your product, then run "
        "`loupe ci` or `loupe chat`."
    )


def _write_empty_knowledge(path: Path) -> None:
    """Write a header-commented empty knowledge graph.

    The resulting file round-trips through `KnowledgeGraph.load`.
    """
    kg = KnowledgeGraph(last_updated=datetime.now(UTC).replace(tzinfo=None))
    kg.save(path)
    body = path.read_text()
    path.write_text(_KNOWLEDGE_HEADER + body)
