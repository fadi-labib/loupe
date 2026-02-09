# Loupe

A platform of analysis **lenses** for software-engineering risk activities. v1 ships **ThreatLens** — diff-aware STRIDE threat modeling whose outputs double as EU Cyber Resilience Act (CRA) Annex I evidence.

> A *loupe* is the small precision lens jewellers and watchmakers use to inspect detail others miss. Loupe brings the same idea to code: each lens looks at a codebase through one specialised perspective. ThreatLens looks for security threats. SafetyLens (future) will look for functional-safety hazards. PrivacyLens (future) will look for data-protection concerns. Same instrument, different lenses.

**Status:** pre-alpha, under active development. Foundation built; first real LLM agent coming in Phase 6.

---

## What Loupe is — and isn't

**Loupe is** a Python platform that runs domain-specialised AI agents (called *lenses*) against your code changes and produces auditor-credible evidence as in-repo artifacts. It runs in CI, runs interactively from your terminal, and exposes its capabilities to other AI clients (Claude Code, Cursor, ChatGPT) over the Model Context Protocol (MCP). All three surfaces share one core, one enforcement model, and one artifact set.

**Loupe is not** a chatbot, a generic AI assistant, or a "compliance scanner." Specifically:

- It does not run unattended writes to your repo. Every change passes through one of four enforcement layers, and protected files (`context.md`, `decisions/*`, `config.yaml`) cannot be modified by the agent — only proposed for human review.
- It does not lock you into a single LLM provider. Lenses run on Claude, OpenAI, Google, or any provider PydanticAI supports — switched via environment variable.
- It does not produce one-shot reports. It maintains a living set of versioned artifacts that grow with your codebase and form continuous CRA evidence rather than point-in-time snapshots.
- It is not a compliance product. It's an *evidence-generation* product. The distinction matters: a compliance product tells you you're fine; an evidence-generation product produces artifacts an external auditor could verify themselves.

---

## Who Loupe is for

- **Security engineers** who want threat modelling that responds to actual code changes rather than living in stale Confluence pages.
- **Software teams subject to the EU CRA** (digital-element manufacturers, fully applicable December 2027) who need an auditable trail of risk assessment, secure-by-design rationale, SBOMs, and VEX statements.
- **Functional-safety, privacy, and AI-risk teams** (eventually, when SafetyLens, PrivacyLens, AIRiskLens land) who would benefit from sharing infrastructure with the security team rather than running parallel tooling.
- **Platform engineers** who want a single AI-driven workflow that any team can plug new domain lenses into, instead of N point-tools per regulation.

---

## Quick start (once Phase 7 lands; currently aspirational)

```bash
# install
pip install loupe-cli loupe-threatlens

# initialise in your repo
loupe init
$EDITOR .loupe/context.md   # describe your product, assets, threat actors

# run on a diff (locally) — incremental mode, used in CI
git diff main... > diff.patch
loupe ci --diff-file diff.patch --base-sha $(git rev-parse main) --head-sha HEAD

# or run a full-repo scan — for first-time onboarding, periodic re-baseline, audit prep
loupe scan
loupe scan --paths src/payments/         # scope to specific paths

# or run interactively (handles both kinds of question)
loupe chat

# or expose Loupe to Claude Code / Cursor / your editor over MCP
loupe mcp
```

In CI, a tiny composite GitHub Action wraps the CLI:

```yaml
- uses: loupe-action@v1
  with:
    pr: ${{ github.event.pull_request.number }}
```

---

## How to read the rest of this repo

| You want to | Read this |
|---|---|
| Understand what Loupe is and why it exists | [`docs/ABOUT.md`](docs/ABOUT.md) |
| Know the values and design principles that guided every decision | [`docs/VALUES.md`](docs/VALUES.md) |
| See the actual decisions made (and the alternatives rejected) | [`docs/DESIGN-DECISIONS.md`](docs/DESIGN-DECISIONS.md) |
| Look up a term used elsewhere in the docs | [`docs/GLOSSARY.md`](docs/GLOSSARY.md) |
| Understand what data Loupe sends to LLMs (and what it doesn't) | [`docs/DATA-HANDLING.md`](docs/DATA-HANDLING.md) |
| Compare Loupe with Snyk / Wiz / Trivy / OWASP Threat Dragon / etc. | [`docs/COMPARISON.md`](docs/COMPARISON.md) |
| Develop on Loupe or write a new lens | [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) |
| Read the full technical design spec | [``]() |
| See the phased implementation plan | [``]() |

---

## Current build state

Phases 0–3 of the implementation plan are complete. The codebase has:

- A uv-managed Python 3.13 workspace with four packages (`loupe-core`, `loupe-cli`, `loupe-threatlens`, `loupe-action`)
- All nine artifact schemas (Pydantic models with YAML/JSON round-trip): `Threat`, `Mitigation`, `KnowledgeGraph`, `ProjectContext`, `LoupeConfig`, `RunRecord` (with hash chain), and supporting types
- Layer 1 enforcement: `PathBoundary` + `write_agent_artifact` + `propose_patch` + `BoundaryViolation`
- The within-run shared blackboard (`RunContext`) with namespaced findings + facts, plus `RunContext.bootstrap()` that loads context + knowledge graph + parses the diff
- A diff parser and SBOM/Grype subprocess wrappers
- 40 unit tests, all passing

What's not yet wired up: the Lens API (Phase 4), the coordinator + prompt builder (Phase 5), the ThreatLens PydanticAI agent (Phase 6), the CLI commands (Phase 7), the GitHub Action entrypoint (Phase 8), the MCP server (Phase 9), and the polish work (Phase 10).

---

## Licence

Not yet decided. Currently treat this as "all rights reserved" while we settle on a licence.
