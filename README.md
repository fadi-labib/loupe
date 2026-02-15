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

## Why Loupe — the value proposition

### What you get

| Value | What it means in practice |
|---|---|
| **Open source, Apache 2.0 licence** | Read every line, fork it, integrate it, ship it as-is in a commercial product. No license fear, no GPL viral concerns. See [`LICENSE`](LICENSE). |
| **Free** | No per-seat fees, no usage limits, no SaaS subscription, no "contact sales" tier. You pay only for whatever LLM provider you choose to route to. |
| **No vendor lock-in (multi-LLM)** | Anthropic, OpenAI, Google, Mistral, Groq, Cohere, Ollama, local LLMs, Bedrock — switch with one env var (`THREATLENS_MODEL=…`). Your security-team's "approved LLM list" doesn't block adoption. |
| **No vendor lock-in (multi-tool, pluggable capabilities)** | Every non-LLM tool category (SBOM gen, CVE scan, secret detect, static analysis, license scan, vuln-DB lookup) is a typed Protocol with registerable backends. Run Syft *or* Trivy *or* both-merged. Run TruffleHog *and* gitleaks for belt-and-braces secret detection. Composition modes (single/fallback/union/consensus/pipeline) make audit posture configurable. See [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md). |
| **No vendor lock-in (no SaaS)** | Local-first. All artefacts live in your repo as plain files. No Loupe-hosted backend, no telemetry, no cloud database. Migrate away (or never use) by copying the `.loupe/` directory. |
| **Multi-flow: one core, three frontends** | `loupe ci` runs on every PR. `loupe chat` runs interactively in the terminal. `loupe mcp` exposes the same capabilities to Claude Code, Cursor, ChatGPT desktop, or any MCP-aware client. Same artefacts, same enforcement, in all three. |
| **Plugin-extensible (multiple domains)** | v1 ships **ThreatLens** (security). The platform supports `SafetyLens` (ISO 26262 / HARA), `PrivacyLens` (GDPR / LINDDUN), `AIRiskLens` (NIST AI RMF) as separate pip-installable lenses on the same core. One workflow, many domains. |
| **Auditor-credible by design** | Four-layer write-boundary enforcement, hash-chained run records, standards-conformant artefacts (CycloneDX SBOMs, OpenVEX statements, STRIDE threats with stable IDs). Git history is the audit substrate. |
| **CI-friendly and cost-disciplined** | Three cost-saving levers built in: stable-prefix prompt caching, shared blackboard (no recompute across lenses), coordinated dispatch (skip irrelevant lenses for trivial PRs). Illustrative per-PR cost: ~$0.001 for docs-only PRs, ~$0.11 for a meaningful code change. |
| **AI-assistant native** | The MCP server lets Claude Code or Cursor ask "what threats does this PR introduce?" without re-explaining your codebase. The same enforcement applies whether you drive Loupe yourself or your AI assistant does. |
| **CRA-Annex-I shaped** | Outputs (threat model, mitigations, SBOM, VEX, decision log) match Annex I conformity evidence directly. Not a regulatory afterthought; designed against the requirements from D-01. |

### How this compares with alternatives

| If you also looked at … | What Loupe offers beyond it |
|---|---|
| [**StrideGPT**](https://github.com/mrwadams/stride-gpt) (OSS, one-shot STRIDE) | Continuous (every PR) + persistent (in-repo) + multi-domain + CRA-shaped + enforcement layers + MCP exposure |
| **IriusRisk** (commercial, ~42% market share) | Local-first (vs SaaS), multi-LLM (vs single-vendor), OSS (vs commercial), pluggable (vs single-domain), free (vs licence fee) |
| **OWASP Threat Dragon** (OSS, manual) | AI-drafted (vs manual diagrams), diff-aware (vs one-shot), CRA-shaped (vs no regulatory framing), CI-native (vs desktop tool) |
| **Concordance** (commercial, CRA evidence) | Goes deep on threat-modelling specifically; complementary not competitive |
| **Snyk / Trivy / Wiz** (vuln scanners) | Different category — they find vulns, Loupe builds threat models around them. Run both. |
| **Claude Code / Cursor** (AI coding assistants) | Different purpose — they write code, Loupe reasons about risk. Compose via MCP. |

See [`docs/COMPARISON.md`](docs/COMPARISON.md) for the deeper analysis.

### Why we built it instead of using one of the above

Honest answer: **the platform shape is the point**, not the threat-modelling technique. Six of the seven Loupe-specific values above are about *being a platform* (plugin architecture, in-repo artefacts, enforcement, MCP, structured outputs, multi-frontend). Only one is about *doing STRIDE threat modelling*. Existing tools each cover one or two pieces; none combine them. If your future plans include multiple regulated domains, continuous operation, and auditor-credible artefacts, no single existing tool fits.

If your plans are smaller — one team, one domain, occasional threat modelling — use [StrideGPT](https://github.com/mrwadams/stride-gpt) and skip the platform. We say so up front because that's honest engineering, not marketing.

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

In CI, the composite GitHub Action wraps the CLI, fetches the PR diff,
posts a sticky comment, and surfaces machine-readable outputs:

```yaml
- uses: loupe-action@v1
  with:
    pr: ${{ github.event.pull_request.number }}
    # comment_mode: sticky    # sticky (default) / new / none
    # config: .loupe/config.yaml
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The Action emits the following outputs for downstream steps:

| Output | Type | Description |
|---|---|---|
| `findings_count` | int | Total threats reported by this run |
| `findings_critical` / `findings_high` / `findings_medium` / `findings_low` | int | Per-severity counts |
| `run_id` | string | Matches `.loupe/runs/<id>.json` |
| `run_hash` | string | Self-hash of the run record — your audit chain anchor |
| `exit_code` | int | `0` clean, `1` gate failed, `64` usage/config error |

Exit codes are driven by the `ci.fail_on` list in `config.yaml`. Adding
`fail_on: [critical, high]` makes the step fail (exit 1) the moment a
critical or high threat is reported. Set `fail_on: []` to report-only.

---

## How to read the rest of this repo

| You want to | Read this |
|---|---|
| Understand what Loupe is and why it exists | [`docs/ABOUT.md`](docs/ABOUT.md) |
| See the architecture visually (C4 diagrams + sequence flows, GitHub-rendered) | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| Know the values and design principles that guided every decision | [`docs/VALUES.md`](docs/VALUES.md) |
| See the actual decisions made (and the alternatives rejected) | [`docs/DESIGN-DECISIONS.md`](docs/DESIGN-DECISIONS.md) |
| Look up a term used elsewhere in the docs | [`docs/GLOSSARY.md`](docs/GLOSSARY.md) |
| Understand what data Loupe sends to LLMs (and what it doesn't) | [`docs/DATA-HANDLING.md`](docs/DATA-HANDLING.md) |
| Understand the capability / tool-agnostic plugin model | [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md) |
| See the two-tier evaluation benchmark methodology (Mongoose + Mosquitto + StrideGPT comparison) | [`docs/EVALUATION.md`](docs/EVALUATION.md) |
| Compare Loupe with Snyk / Wiz / Trivy / OWASP Threat Dragon / etc. | [`docs/COMPARISON.md`](docs/COMPARISON.md) |
| Develop on Loupe or write a new lens | [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) |

---

## Current build state

Phases 0–3 of the implementation plan are complete. The codebase has:

- A uv-managed Python 3.13 workspace with four packages (`loupe-core`, `loupe-cli`, `loupe-threatlens`, `loupe-action`)
- All nine artifact schemas (Pydantic models with YAML/JSON round-trip): `Threat`, `Mitigation`, `KnowledgeGraph`, `ProjectContext`, `LoupeConfig`, `RunRecord` (with hash chain), and supporting types
- Layer 1 enforcement: `PathBoundary` + `write_agent_artifact` + `propose_patch` + `BoundaryViolation`
- The within-run shared blackboard (`RunContext`) with namespaced findings + facts, plus `RunContext.bootstrap()` that loads context + knowledge graph + parses the diff
- A diff parser and SBOM/Grype subprocess wrappers
- 40 unit tests, all passing

What's not yet wired up: the MCP server (Phase 9), benchmark fixtures + cost
regression test (Phase 10).

---

## Licence

**Apache 2.0.** See [`LICENSE`](LICENSE). Patent grant included; trademark not granted. Use it, fork it, integrate it, ship it. Attribution appreciated but not required.
