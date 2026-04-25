<div align="center">

<img src="docs/assets/logo.svg" alt="Loupe" width="96" height="96" />

# Loupe

**Auditor-credible AI lenses for code review.**

*A precision instrument for software-engineering risk: threat models, hazard analyses, privacy reviews — same platform, different lens.*

[![License](https://img.shields.io/badge/license-Apache_2.0-2E7DAF.svg?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.13+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange.svg?style=flat-square)](#status)
[![Tests](https://github.com/fadi-labib/loupe/actions/workflows/tests.yml/badge.svg)](https://github.com/fadi-labib/loupe/actions/workflows/tests.yml)
[![Docs](https://github.com/fadi-labib/loupe/actions/workflows/docs.yml/badge.svg)](https://github.com/fadi-labib/loupe/actions/workflows/docs.yml)
[![Vale](https://github.com/fadi-labib/loupe/actions/workflows/prose-check.yml/badge.svg)](https://github.com/fadi-labib/loupe/actions/workflows/prose-check.yml)
[![Links](https://github.com/fadi-labib/loupe/actions/workflows/link-check.yml/badge.svg)](https://github.com/fadi-labib/loupe/actions/workflows/link-check.yml)

[Docs](https://fadi-labib.github.io/loupe/) · [Quickstart](docs/quickstart.md) · [Architecture](docs/concepts/architecture.md) · [Verification](docs/reference/verification.md) · [Decisions](docs/reference/decisions.md) · [Changelog](CHANGELOG.md)

</div>

---

<details>
<summary><b>📑 Table of contents</b></summary>

- [The problem](#-the-problem)
- [The bet](#-the-bet)
- [The mental model](#-the-mental-model)
- [Architecture at a glance](#️-architecture-at-a-glance)
- [Quickstart](#-quickstart) · [GitHub Action](#github-action)
- [What lives in `.loupe/`](#-what-lives-in-loupe)
- [Sample output](#-sample-output)
- [You pick the LLM. You pick the tools.](#-you-pick-the-llm-you-pick-the-tools)
- [Defence in depth (four layers)](#️-defence-in-depth-four-layers)
- [Status](#-status)
- [Why now: the CRA timeline](#️-why-now-the-cra-timeline)
- [Where to find things](#-where-to-find-things)
- [Built on](#-built-on)
- [Contributing](#-contributing) · [Security](#-security) · [Licence](#-licence)

</details>

## 🔍 The problem

Software-engineering risk activities — threat modelling, hazard analysis, privacy review — share a structural failure mode: **artefacts drift out of sync with the code they describe**, and the work needed to keep them current is the slow, careful, evidence-shaped work most engineers will not do without external pressure.

Two failure modes show up everywhere. **Stale documents**: a wiki page from 2023 still claims the service uses session cookies, two years after the OAuth migration. An auditor reads it. The auditor is satisfied. The document is wrong. **Compliance theatre**: a scanner emits a 200-page PDF on every commit. Nobody reads it. The process runs. No actual analysis happens.

The EU Cyber Resilience Act (fully applicable December 2027) makes both worse: manufacturers must maintain a *current* risk assessment, a *current* secure-by-design rationale, a *current* SBOM, and *current* per-vulnerability impact statements — as living documents, not point-in-time PDFs filed after release.

## 💡 The bet

| Claim | Shape |
|---|---|
| **AI agents can do the slow, careful, evidence-shaped work** | … provided their outputs are structured, auditable, and human-reviewed at the boundaries that matter |
| **A plugin platform with separate domain lenses is the right shape** | Threat modelling, safety analysis, privacy review have different methods but share infrastructure (diff parsing, SBOM generation, artefact storage, enforcement, MCP exposure) |
| **The platform must be auditor-credible from day one or it loses to the spreadsheet** | Standards-conformant outputs (CycloneDX, OpenVEX, STRIDE), Git-versioned artefacts, hash-chained run records, write-boundary enforcement in code (not policy) |

## 🩺 The mental model

The shortest correct answer to *"what is Loupe?"* is a medical-clinic metaphor that holds all the way down.

> A pull request rolls in (the **patient**). The **clinic** decides which **specialists** should see this patient. The specialists order the **diagnostic tests** they need. The clinic writes up a **chart** an external auditor can read.

| Role | What it is | What it does | In Loupe |
|---|---|---|---|
| 🏥 The clinic | The platform | Orchestrates, files paperwork, enforces boundaries | `loupe-core` |
| 👩‍⚕️ The specialist | A lens | Brings domain expertise, decides what to look for | `ThreatLens` (security), `SafetyLens` *(future)*, `PrivacyLens` *(future)* |
| 🔬 The diagnostic test | A capability | A tool category specialists can order | `sbom`, `cve`, `secret_detect`, `static_analysis` |
| ⚙️ The test machine | A backend | The specific tool that performs the test | `syft`, `cdxgen`, `grype`, `trufflehog`, `semgrep`, … |
| 📋 The chart | An artefact | The patient's medical record | Files in `.loupe/` |

## 🏗️ Architecture at a glance

```mermaid
flowchart TB
    PR["📬 Pull request"]
    Action["⚡ loupe-action<br/>(GitHub Action wrapper)"]
    Core["🏥 loupe-core<br/>(coordinator · enforcement · run records)"]

    subgraph lenses["👩‍⚕️ Lenses (domain plugins)"]
        ThreatLens["🛡️ ThreatLens<br/>(v1, shipped)"]
        Future["💤 SafetyLens · PrivacyLens · AIRiskLens<br/>(planned)"]
    end

    subgraph caps["🔬 Capabilities"]
        SBOM["sbom"]
        CVE["cve"]
        Secret["secret_detect"]
        SAST["static_analysis"]
    end

    Backends["⚙️ 10 bundled backends<br/>syft · cdxgen · grype · osv-scanner ·<br/>gitleaks · trufflehog · detect-secrets ·<br/>semgrep · codeql · bandit"]

    LLM["🤖 LLM (you pick)<br/>Anthropic · OpenAI · Google · Mistral ·<br/>Groq · Ollama · Bedrock · …"]

    Artefacts[("📁 .loupe/<br/>threats · mitigations ·<br/>SBOM · VEX · run records ·<br/>decisions · knowledge graph")]

    PR --> Action --> Core
    Core --> lenses
    Core --> caps
    caps --> Backends
    ThreatLens -.-> LLM
    Core --> Artefacts

    classDef shipped fill:#d4edda,stroke:#155724,stroke-width:2px
    classDef planned fill:#fff3cd,stroke:#856404,stroke-width:1px,stroke-dasharray:5 5
    class ThreatLens,Action,Core,Backends shipped
    class Future planned
```

Each layer is replaceable without disturbing the others. Swap `syft` for `trivy` and lenses don't notice. Add `AutoCyberLens` for TARA and the platform doesn't change. Change the GitHub Action wrapper for a GitLab one and the core stays the same.

## ⚡ Quickstart

> [!WARNING]
> **Pre-alpha · pre-PyPI.** Loupe is wired end-to-end but the API will move before v0.1 tags. Install from source for now; treat the artefact schemas as the stable surface.

```bash
git clone https://github.com/fadi-labib/loupe.git
cd loupe
uv sync --all-packages
```

Then in your project:

```bash
cd your-repo
uv run loupe init                    # scaffold .loupe/
$EDITOR .loupe/context.md            # describe your product (anti-hallucination anchor)
export ANTHROPIC_API_KEY="sk-ant-…"  # or OPENAI_API_KEY / GOOGLE_API_KEY / etc.
uv run loupe ci --diff-file <(git diff main...)
```

A full walk-through with screenshots is in the **[Quickstart](docs/quickstart.md)**.

### GitHub Action

```yaml
# .github/workflows/loupe.yml
on:
  pull_request:

jobs:
  loupe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fadi-labib/loupe@main          # post-v0.1: fadi-labib/loupe-action@v0.1
        with:
          pr: ${{ github.event.pull_request.number }}
          comment_mode: sticky                # or 'new' or 'none'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

| Exit code | Meaning |
|:-:|---|
| `0` | Clean run; no severity in `ci.fail_on` triggered |
| `1` | Gate failure: a threat at a `ci.fail_on` severity was reported |
| `64` | Usage / configuration error (BSD `sysexits.h` `EX_USAGE`) |

The Action publishes eight outputs (`findings_count`, severity-specific counts, `run_id`, `run_hash`, `exit_code`) — see [`action.yml`](packages/loupe-action/action.yml) for the schema.

## 📂 What lives in `.loupe/`

> [!NOTE]
> The audit pack is **plain files**, Git-tracked, no SaaS, no hidden state, no telemetry. An auditor can replay every run from in-repo state alone; the `runs/*.json` hash chain detects history rewrites.

| File | Who writes it | What it is |
|---|---|---|
| `context.md` | Human | Product brief — the anti-hallucination anchor every lens reads |
| `threats.yaml` + `threat-model.md` | `ThreatLens` | STRIDE threats, machine-readable + narrative |
| `mitigations.yaml` | `ThreatLens` | Mitigations cross-referencing threats |
| `sbom.cdx.json` | Syft (or cdxgen, or your pick) | CycloneDX 1.6 SBOM |
| `vex.json` | `ThreatLens` + human approval | OpenVEX vulnerability statements |
| `runs/*.json` | `loupe-core` | Hash-chained audit trail of every invocation |
| `decisions/D-*.md` | Human | ADR-style risk acceptances |
| `knowledge.yaml` | `loupe-core` | Persistent cross-run knowledge graph |
| `config.yaml` | Human | Operator settings — which lenses, which backends, which gates |

Full schemas in [`docs/reference/schemas/`](docs/reference/schemas/index.md).

## 🧾 Sample output

<details>
<summary>What ThreatLens actually writes to <code>.loupe/threats.yaml</code></summary>

```yaml
schema_version: 1
threats:
  - id: T-001
    element_id: E-001
    stride_category: I            # Information disclosure
    title: API endpoint leaks user IDs in error messages
    description: |
      The /api/users endpoint returns stack traces in 500 responses,
      revealing internal user IDs and database schema names.
    severity: high
    status: proposed              # human moves it through accepted / mitigated / accepted_risk / rejected
    mitigation_ids: [M-005]
    cwe_refs: [CWE-209]
    attack_pattern_refs: []
    introduced_in_pr: "1234"
    last_reviewed: 2026-05-15
    review_due: 2026-08-15
    rationale: |
      Reviewing the diff for /api/users, I noticed the new exception
      handler raises Exception directly without sanitisation.
    proposed_by: threatlens
```

Every threat carries a stable `T-NNN` ID, an element it applies to (`E-NNN`), a STRIDE category (single letter), severity, lifecycle status, mitigation cross-references (`M-NNN`), CWE/CAPEC references, and a rationale the LLM is required to produce. The mitigations file (`mitigations.yaml`), VEX statements (`vex.json`), and run records (`runs/*.json`) share the same shape: Pydantic-validated, stable IDs, no prose-only fields.

See [`docs/reference/schemas/`](docs/reference/schemas/index.md) for every artefact's schema.

</details>

## 🔌 You pick the LLM. You pick the tools.

> [!TIP]
> **Multi-LLM by design.** PydanticAI ships Anthropic, OpenAI, Google, Mistral, Groq, Cohere, Ollama, Bedrock natively. Set `THREATLENS_MODEL=openai:gpt-5` and you're done — no code change.

**No tool lock-in.** Every non-LLM tool is a Capability Protocol. Five composition modes (`single`, `fallback`, `union`, `consensus`, `pipeline`) let you say *"run TruffleHog AND gitleaks and merge"* or *"require two of three SAST scanners to agree"* in `config.yaml`. That's the evidence.

<details>
<summary>What that looks like in <code>.loupe/config.yaml</code></summary>

```yaml
capabilities:
  sbom:
    mode: single                                       # any SBOM tool is fine
    backends: [syft, cdxgen]
  cve:
    mode: union                                        # different DBs catch different CVEs
    backends: [grype, osv-scanner]                     # merge results, dedupe by CVE ID
  secret_detect:
    mode: union                                        # belt and braces — false negatives are catastrophic
    backends: [trufflehog, gitleaks, detect-secrets]
  static_analysis:
    mode: consensus                                    # require two analysers to agree
    consensus_threshold: 2
    backends: [semgrep, codeql, bandit]
```

An auditor reads this and knows the team's posture without grepping any code. *The configuration is the evidence.*

</details>

## 🛡️ Defence in depth (four layers)

| Layer | Status | What it protects |
|:-:|:-:|---|
| **1** — Tool surface | ✅ Shipped | Agent has only `write_agent_artifact` (allow-list) + `propose_patch` (writes to `.proposed/`). `PathBoundary` enforced in Python, not in a prompt. Parent-symlink-safe via `dir_fd` + `O_NOFOLLOW`. |
| **2** — Branch namespace | 📐 Designed | Fine-grained GitHub PAT scoped to `loupe/proposal-*`; CODEOWNERS gates protected paths |
| **3** — `loupe verify` | ✅ Shipped | Four checks: hash chain · artefact schemas · cross-references · protected-path authorship (`--strict`) |
| **4** — Interactive UX gate | 📐 Designed | `loupe chat` `[y/N/edit/skip]` confirmation with no `--auto-confirm` |

See [`docs/reference/verification.md`](docs/reference/verification.md) for the **mechanical recipes** an auditor can run against each principle.

## 🚀 Status

### ✅ Shipped today

- **Platform**: `loupe-core` (coordinator, dispatcher, run context, prompt builder, MCP server, pricing, enforcement)
- **CLI**: `loupe init`, `loupe ci`, `loupe verify [--strict]`, `loupe scan`, `loupe mcp`, `loupe chat` (TTY guard only), `loupe lens list`, `loupe cap list`
- **GitHub Action**: PR fetch · `loupe ci` runner · sticky-comment poster (sticky / new / none modes) · retry + rate-limit handling
- **ThreatLens**: PydanticAI agent wired to a live LLM, exercised in CI through a VCR cassette · STRIDE threats · mitigations · cross-references
- **MCP server** (stdio): read tools (`list_threats`, `query_by_severity`, `latest_run`, `threat_model_summary`) + write tools (`propose_threat`, `propose_mitigation`, both Layer-1 gated)
- **10 bundled capability backends**: Syft + cdxgen (SBOM) · Grype + osv-scanner (CVE) · gitleaks + TruffleHog + detect-secrets (secret) · Semgrep + CodeQL + Bandit (SAST)
- **Composition modes**: `single`, `fallback`, `union`, `consensus`, `pipeline`
- **Audit trail**: hash-chained run records · `loupe verify` Layer 3 checks (chain, schema, cross-refs, authorship)
- **Cost discipline**: stable-prefix prompt caching, blackboard, dispatch skipping, RunRecord token/cost telemetry, [cost-regression test](packages/loupe-threatlens/tests/test_cost_regression.py)

### 🔄 In flight (before v0.1 tags)

- `loupe chat` conversational pipeline (TTY guard wired; `[y/N/edit/skip]` not)
- HTTP+SSE remote MCP transport (stdio works today)
- Layer 2 fine-grained-PAT branch namespace enforcement
- `--verbose`, `--budget-usd` flags
- Benchmarks against Cesanta Mongoose (Tier 1) and Eclipse Mosquitto (Tier 2) per [D-19](docs/reference/decisions.md#d-19)

### 💤 Anticipated

- **SafetyLens** — functional-safety hazard analysis (ISO 26262, IEC 61508, IEC 62304)
- **PrivacyLens** — data-protection review (GDPR DPIA, LINDDUN)
- **AIRiskLens** — AI/ML risk (NIST AI RMF, EU AI Act high-risk; possibly MAESTRO)

## 🗓️ Why now: the CRA timeline

```text
   2024              2026-09-11               2027-12-11
    │                     │                        │
    ●─────────────────────●────────────────────────●─────►
   CRA adopted    Reporting obligations    Full applicability
                  begin (ENISA SRP)        — every manufacturer
                                            of "products with
                                            digital elements"
```

The EU Cyber Resilience Act ([Regulation 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847)) becomes fully applicable on **11 December 2027**. From **11 September 2026**, manufacturers must report actively-exploited vulnerabilities and severe incidents via [ENISA's Single Reporting Platform](https://www.enisa.europa.eu/topics/cyber-resilience-act).

Both require *living* risk assessments, *living* SBOMs, *living* per-CVE impact statements. Loupe produces all three as in-repo artefacts, on every PR, with audit-grade provenance.

## 📚 Where to find things

The published docs site is at **[fadi-labib.github.io/loupe](https://fadi-labib.github.io/loupe/)** (search, navigation, social previews). The fallback for in-tree browsing:

| 🧭 | If you want to … | Read |
|:-:|---|---|
| 🚀 | get something running | [Quickstart](docs/quickstart.md) |
| 🧠 | understand the mental model | [Architecture](docs/concepts/architecture.md) · [Capabilities](docs/concepts/capabilities.md) |
| 📜 | know the principles Loupe won't compromise on | [Principles](docs/principles.md) |
| 🔍 | verify the principles mechanically | [Verification](docs/reference/verification.md) |
| ⚙️ | look up a CLI command or flag | [CLI reference](docs/reference/cli.md) |
| 🧩 | configure `.loupe/config.yaml` | [Config reference](docs/reference/config.md) |
| 📐 | see each artefact's schema | [Schemas](docs/reference/schemas/index.md) |
| 🛰️ | run the MCP server | [How-to: MCP server](docs/how-to/run-mcp-server.md) · [MCP tools reference](docs/reference/mcp-tools.md) |
| 💰 | understand cost estimation | [Pricing reference](docs/reference/pricing.md) |
| ⚖️ | know why a decision was made | [Decisions log](docs/reference/decisions.md) (D-01 → D-22) |
| 🆚 | compare against StrideGPT / IriusRisk / Snyk / etc. | [Comparison](docs/comparison.md) |
| 🔒 | check what data leaves your repo | [Data handling](docs/reference/data-handling.md) |
| 📖 | look up a term | [Glossary](docs/reference/glossary.md) |
| 🛠️ | contribute code or a lens | [Contributing](docs/contributing.md) |
| 📰 | see what changed | [CHANGELOG](CHANGELOG.md) |

## 🧱 Built on

Loupe stands on:

| Layer | Built with |
|---|---|
| LLM agent framework | [PydanticAI](https://ai.pydantic.dev/) (multi-provider, typed I/O) |
| Validation + serialisation | [Pydantic 2.x](https://docs.pydantic.dev/) |
| LLM tool protocol | [MCP](https://modelcontextprotocol.io/) (official Anthropic SDK, FastMCP API — [D-21](docs/reference/decisions.md#d-21)) |
| SBOM | [CycloneDX 1.6](https://cyclonedx.org/) via [Syft](https://github.com/anchore/syft) / [cdxgen](https://github.com/CycloneDX/cdxgen) |
| Vulnerability matching | [Grype](https://github.com/anchore/grype) · [osv-scanner](https://github.com/google/osv-scanner) |
| VEX | [OpenVEX 0.2](https://openvex.dev/) |
| Secret detection | [TruffleHog](https://github.com/trufflesecurity/trufflehog) · [gitleaks](https://github.com/gitleaks/gitleaks) · [detect-secrets](https://github.com/Yelp/detect-secrets) |
| Static analysis | [Semgrep](https://semgrep.dev/) · [CodeQL](https://codeql.github.com/) · [Bandit](https://github.com/PyCQA/bandit) |
| Threat-modelling method | [STRIDE](https://learn.microsoft.com/azure/security/develop/threat-modeling-tool-threats) (Microsoft) · methodology inspiration from [StrideGPT](https://github.com/mrwadams/stride-gpt) ([D-16](docs/reference/decisions.md#d-16)) |
| Docs site | [MkDocs Material](https://squidfunk.github.io/mkdocs-material/) · [mkdocstrings](https://mkdocstrings.github.io/) · [mike](https://github.com/jimporter/mike) versioning |
| Workspace / packaging | [uv](https://docs.astral.sh/uv/) · [hatchling](https://hatch.pypa.io/) |
| Prose linting | [Vale](https://vale.sh/) with a custom [`Loupe`](.vale/styles/Loupe/) style |

## 🤝 Contributing

Workspace layout, test discipline (hermetic, VCR-cassetted), commit conventions, and CI gates: **[`docs/contributing.md`](docs/contributing.md)**. Pre-alpha private; PR contributions welcomed once the repo opens.

## 🔐 Security

The threat model for Loupe itself is at **[`docs/reference/loupe-threat-model.md`](docs/reference/loupe-threat-model.md)** — dogfood, same STRIDE shape Loupe would emit for any other repo. Disclosure policy in **[`SECURITY.md`](SECURITY.md)**.

## 📄 Licence

Apache 2.0. See [`LICENSE`](LICENSE). Use it, fork it, ship it. Attribution appreciated, not required.

---

<div align="center">
<sub>Copyright © 2026 Fadi Labib · <a href="https://fadi-labib.github.io/loupe/">Docs</a> · <a href="LICENSE">Apache 2.0</a> · <a href="SECURITY.md">Security</a> · <a href="CHANGELOG.md">Changelog</a></sub>
</div>
