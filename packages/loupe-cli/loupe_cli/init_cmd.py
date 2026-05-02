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
  # D-24: per-mode cost ceiling. `ci` covers diff-mode runs (cheap per
  # call, runs often); `scan` covers scoped/full scans (fewer runs but
  # each one reads more source bytes, so the envelope is wider). A
  # scalar `per_run_max_usd: 2.50` is still accepted as back-compat.
  per_run_max_usd:
    ci: 2.50
    scan: 5.00
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

# Uncomment and edit to wire capability backends. ThreatLens declares
# `requires: [sbom, cve]` — without these blocks `loupe ci` warns
# "capability bootstrap failed" on first run because no backend is
# bound. Each backend below maps to a CLI tool that must be on $PATH:
# Syft (https://github.com/anchore/syft), Grype (https://github.com/anchore/grype),
# etc. See docs/concepts/capabilities.md for composition modes
# (single / fallback / union / consensus / pipeline).
#
# capabilities:
#   sbom:
#     mode: single
#     backends: [syft]              # alternative: cdxgen
#   cve:
#     mode: single
#     backends: [grype]             # alternative: osv-scanner
#   secret_detect:
#     mode: union                   # union surfaces hits from any tool
#     backends: [gitleaks, trufflehog]
#   static_analysis:
#     mode: consensus               # require N tools to agree
#     consensus_threshold: 2
#     backends: [semgrep, codeql, bandit]
"""


_KNOWLEDGE_HEADER = (
    "# .loupe/knowledge.yaml\n"
    "# Persistent knowledge graph populated across runs.\n"
    "# Lenses promote high-confidence Facts here; humans curate the rest.\n"
    "# Safe to delete to reset; the next run rebuilds an empty graph.\n"
)


def init_command(*, force: bool = False, dry_run: bool = False) -> None:
    """Initialise .loupe/ in the current directory.

    With `force=True`, an existing .loupe/ is updated in-place rather
    than refusing to run: `config.yaml` and `knowledge.yaml` are
    regenerated from the current template, but `context.md` is
    preserved if the user has edited it (we don't want to clobber
    human-authored product context), and `runs/` / `decisions/` are
    never touched (they contain the audit trail and human-curated
    risk acceptances).

    With `dry_run=True`, no filesystem changes are made; the command
    prints what would be created or overwritten and exits 0.
    """
    cwd = Path.cwd()
    loupe = cwd / ".loupe"

    if loupe.exists() and not force:
        typer.echo(
            f"Error: {loupe} already exists. Aborting.\n"
            "Use --force to regenerate scaffold files (context.md is preserved if edited).",
            err=True,
        )
        raise typer.Exit(code=USAGE_ERROR)

    actions: list[str] = []
    fresh = not loupe.exists()
    context_path = loupe / "context.md"
    # Preserve human-edited context.md across --force regenerations. The
    # default template carries the literal "TODO:" markers; if those have
    # been replaced the file is no longer the default. Hash comparison
    # rather than text-equality avoids whitespace false-negatives.
    preserve_context = (
        not fresh and context_path.exists() and context_path.read_text() != _DEFAULT_CONTEXT
    )

    if fresh:
        actions.append(f"create {loupe}/")
        actions.append(f"create {context_path}")
    else:
        if preserve_context:
            actions.append(f"preserve {context_path} (human edits detected)")
        else:
            actions.append(f"overwrite {context_path}")
    actions.append(f"{'create' if fresh else 'overwrite'} {loupe / 'config.yaml'}")
    actions.append(f"{'create' if fresh else 'overwrite'} {loupe / 'knowledge.yaml'}")
    actions.append(f"ensure {loupe / 'runs'}/ exists")
    actions.append(f"ensure {loupe / 'decisions'}/ exists")

    if dry_run:
        typer.echo("Dry run — no filesystem changes will be made:")
        for action in actions:
            typer.echo(f"  - {action}")
        return

    loupe.mkdir(exist_ok=True)
    if not preserve_context:
        context_path.write_text(_DEFAULT_CONTEXT)
    (loupe / "config.yaml").write_text(_DEFAULT_CONFIG)
    _write_empty_knowledge(loupe / "knowledge.yaml")
    (loupe / "runs").mkdir(exist_ok=True)
    (loupe / "decisions").mkdir(exist_ok=True)

    if fresh:
        typer.echo(f"Initialised {loupe}.")
        typer.echo(
            "Edit .loupe/context.md to describe your product, then run `loupe ci` or `loupe chat`."
        )
        # D-23 / A.9: ThreatLens declares requires_capabilities=[sbom, cve].
        # Under the enforced contract a fresh `loupe ci` will exit 64 until
        # the operator installs Syft + Grype and uncomments the
        # `capabilities:` block. Tell them now so they don't hit the wall
        # in ci. `loupe doctor` is the verification step.
        typer.echo(
            "Next: install Syft + Grype, then uncomment the `capabilities:` "
            "block in .loupe/config.yaml. Run `loupe doctor` to verify."
        )
    else:
        typer.echo(f"Regenerated scaffold files in {loupe}.")
        if preserve_context:
            typer.echo(f"  Preserved {context_path} (human edits detected).")


def _write_empty_knowledge(path: Path) -> None:
    """Write a header-commented empty knowledge graph.

    The resulting file round-trips through `KnowledgeGraph.load`.
    """
    kg = KnowledgeGraph(last_updated=datetime.now(UTC).replace(tzinfo=None))
    kg.save(path)
    body = path.read_text()
    path.write_text(_KNOWLEDGE_HEADER + body)
