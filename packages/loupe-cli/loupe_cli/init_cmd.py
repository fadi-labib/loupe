"""`loupe init` — scaffold .loupe/ in the current working directory.

Creates a minimal layout that:
- Parses cleanly via ProjectContext.from_markdown (all required sections present)
- Round-trips through LoupeConfig validation
- Has agent_writable_paths set to the v1 default set
- Includes runs/ and decisions/ subdirectories so the very first run doesn't
  have to mkdir them on the fly

Templates carry "TODO" markers in places the human is expected to fill in.
The agent never auto-fills these — they're human-owned by Layer 1 design.
"""
from __future__ import annotations

from pathlib import Path

import typer

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
  default: anthropic/claude-opus-4-7

limits:
  per_run_max_usd: 2.50
  per_run_max_tokens_in: 500000
  per_run_max_steps: 30

ci:
  fail_on:
    - new_critical_threat_unmitigated
  warn_on:
    - new_high_threat_unmitigated
  ignore_paths:
    - "docs/**"

agent_writable_paths:
  - .loupe/threats.yaml
  - .loupe/mitigations.yaml
  - .loupe/threat-model.md
  - .loupe/vex.json
  - .loupe/sbom.cdx.json
  - .loupe/runs/**

lenses:
  threatlens:
    enabled: true
    minimum_relevance: 0.3
"""


def init_command() -> None:
    """Initialise .loupe/ in the current directory."""
    cwd = Path.cwd()
    loupe = cwd / ".loupe"
    if loupe.exists():
        typer.echo(f"Error: {loupe} already exists. Aborting.", err=True)
        raise typer.Exit(code=1)
    loupe.mkdir()
    (loupe / "context.md").write_text(_DEFAULT_CONTEXT)
    (loupe / "config.yaml").write_text(_DEFAULT_CONFIG)
    (loupe / "runs").mkdir()
    (loupe / "decisions").mkdir()
    typer.echo(f"Initialised {loupe}.")
    typer.echo(
        "Edit .loupe/context.md to describe your product, then run "
        "`loupe ci` or `loupe chat`."
    )
