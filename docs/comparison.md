# Loupe vs adjacent tools

> **Last reviewed:** 2026-05-15. The AI-threat-modelling space moves fast; treat anything older than three months in this doc as stale and worth re-verifying.

Comparisons against tools in adjacent spaces. Some are competitors, most are complements. The goal is to help you decide what to use Loupe for and what to keep using your existing tools for.

## Loupe is not unprecedented

AI-driven threat modelling is a crowded space, not an empty one. Several open-source LLM-based threat-modelling tools already exist (StrideGPT, ThreatCompute, ASTRIDE, TITO, Arrows). The dominant commercial threat-modelling tool (IriusRisk, around 42% market share per PeerSpot, March 2026[^peerspot-iriusrisk]) has added AI features. Microsoft's Threat Modeling Tool v4.2 has added AI-assisted threat detection[^ms-tmt-v42]. A dedicated CRA-evidence product (Concordance) is on market, mapping engineering data to all 21 CRA Annex I requirements[^concordance]. New frameworks (MAESTRO[^maestro], STRIFE) are emerging specifically for AI/agentic systems.

Loupe's distinctive combination is plugin architecture (multiple domains via lenses and multiple tools via capabilities), in-repo local-first artefacts, four-layer write-boundary enforcement, multi-LLM provider-agnostic, and MCP server exposure. No single tool in the search results matched all five. Several match three or four. Loupe is a recombination of capabilities that exist elsewhere, with a coherent platform shape, not a category-creating product.

One consequence of the capability architecture (see [`concepts/capabilities.md`](concepts/capabilities.md)) is that tools listed below as "competitors" are often Loupe backends in disguise. Syft, Trivy, Grype, gitleaks, TruffleHog, Semgrep all become registerable backends behind their respective Capability Protocols. The comparison is therefore not "Loupe vs these" but "Loupe vs the typical assembly-by-hand of these."

---

## TL;DR

| Tool | Category | Relationship to Loupe |
|---|---|---|
| **StrideGPT** | Open-source LLM-based STRIDE generator | **Most directly comparable in spirit**; one-shot vs Loupe's continuous |
| **ThreatCompute** | Academic LLM agent for Kubernetes threat models, uses MCP | **Most architecturally similar**; Kubernetes-specific |
| **TITO** | Automated threat modelling tool (MAESTRO-based, CI/CD) | Direct competitor in agentic-AI threat modelling |
| **ASTRIDE / Arrows** | LLM + Vision-Language Models for architecture diagrams | Visual-first variants |
| **Concordance** | CRA Annex I evidence platform | **Most directly comparable on the CRA-evidence side** |
| **MAESTRO** (framework, not tool) | Agentic-AI threat modelling methodology (Cloud Security Alliance) | A method ThreatLens *or* a future Loupe lens could adopt |
| **IriusRisk** | Commercial threat-modelling platform (AI-augmented) | Largest market share commercial product |
| **Devici** | Visual + AI-augmented threat modelling (commercial SaaS) | Closest "post-Threat-Dragon AI era" commercial product |
| **OWASP Threat Dragon** | Manual threat-modelling (OSS) | Closest manual-tool predecessor |
| **Microsoft Threat Modeling Tool v4.2** | Manual + AI-assisted (Windows-only) | Same lineage |
| **Threagile / pytm** | Threat-modelling-as-code (OSS, not AI) | "As-code" predecessors; share DNA |
| **Snyk** | SCA + SAST (commercial) | Complementary vuln scanning, not threat modelling |
| **Trivy** | Vuln scanner (OSS) | Complementary; could substitute Loupe's Syft+Grype back-end |
| **cdxgen** | SBOM generator (OSS) | **Bundled** as a registered `sbom` backend complementary to syft |
| **osv-scanner** | CVE matcher against OSV.dev DB (OSS, Google) | **Bundled** as a registered `cve` backend complementary to grype |
| **gitleaks** | Secret scanner (OSS) | **Bundled** as a registered `secret_detect` backend |
| **TruffleHog** | High-entropy + verifier-based secret scanner (OSS) | **Bundled** as a registered `secret_detect` backend |
| **detect-secrets** | Pattern-based secret scanner (Yelp, OSS) | **Bundled** as a registered `secret_detect` backend |
| **Wiz** | Cloud security posture | Different layer entirely |
| **Semgrep** | Static analysis | **Bundled** as a registered `static_analysis` backend |
| **CodeQL** | Query-based static analysis (GitHub, OSS) | **Bundled** as a registered `static_analysis` backend |
| **Bandit** | Python-specific SAST (PyCQA, OSS) | **Bundled** as a registered `static_analysis` backend |
| **GHAS (CodeQL, Dependabot)** | Defect detection | Complementary |
| **Claude Code / Cursor / Aider** | Generic AI coding assistants | Complementary via MCP |
| **Renovate / Dependabot** | Dep update automation | Orthogonal |

---

## AI-driven threat-modelling tools (the most directly comparable cohort)

These are the tools that share Loupe's basic premise: use LLMs to do threat modelling. They differ in scope, deployment model, and depth.

### StrideGPT

**What it is:** Open-source LLM-based threat-modelling tool by Matthew Adams (mrwadams/stride-gpt). Streamlit web UI. User pastes an application description; LLM generates STRIDE threats and attack trees.

**LLM support:** OpenAI, Anthropic, Google AI, Mistral, Groq, plus local hosting via Ollama and LM Studio Server[^stridegpt]. (Note: my first draft incorrectly said "single-LLM (OpenAI)", but StrideGPT is in fact multi-LLM and has been for some time.)

**Where it overlaps with ThreatLens:** Same core method (STRIDE), same LLM-driven approach.

**Where they differ:**
- StrideGPT is **one-shot** paste a description, get a threat model. ThreatLens is **continuous** runs on diffs, maintains living artefacts.
- StrideGPT has no in-repo persistence; the threat model lives in the browser session unless you export it.
- StrideGPT has no write-boundary enforcement (it's not modifying your repo at all).
- No MCP exposure; no plugin architecture; no CRA-evidence framing.

**Honest read:** If your only need is "generate a STRIDE threat model from a description," StrideGPT is simpler, ships today, and is mature. Loupe's value over StrideGPT is the *platform shape* (continuous, multi-domain, CRA-shaped, enforcement, MCP) not the threat-modelling technique itself.

### ThreatCompute

**What it is:** Academic LLM agent for automated threat modelling of cloud-native (Kubernetes) applications. Published at the 2025 ACM Cloud Computing Security Workshop[^threatcompute]. Uses LLMs to dynamically direct reasoning over structured inputs. Designed for CI/CD integration via Kubernetes-native MCP servers.

**Architecturally, this is the closest published work to Loupe.** Same combination: LLM agent + structured inputs + MCP server + CI/CD-friendly.

**Where they differ:**
- ThreatCompute is Kubernetes-specific. Loupe is repo-agnostic (any language, any deployment target).
- ThreatCompute is a research project, not a productised platform yet (as of mid-2026).
- ThreatCompute has a single domain (Kubernetes infrastructure). Loupe's plugin architecture targets multiple domains.

**Honest read:** If you ship on Kubernetes and want a more specialised tool, watch ThreatCompute. If you want a multi-domain platform that's repo-shape-agnostic, Loupe.

### TITO (Threat In and Threat Out)

**What it is:** Automated threat modelling tool. Built on the MAESTRO classification framework (Cloud Security Alliance). Designed for continuous CI/CD-pipeline integration. Targets agentic-AI threat scenarios specifically.

**Where it overlaps with ThreatLens:** CI/CD integration, continuous (not one-shot), automated.

**Where they differ:**
- TITO is MAESTRO-based; ThreatLens is STRIDE-based. MAESTRO is specifically for agentic-AI systems, STRIDE is general.
- TITO appears to focus on classifying threats *of* AI systems; Loupe is threat-modelling-for-any-codebase using AI (the agent is the analyst, not the subject).

**Honest read:** If your *product* is an AI/agentic system, MAESTRO is the right method and TITO is purpose-built for it. ThreatLens currently doesn't use MAESTRO; this could be a future lens (e.g., `AIRiskLens` with MAESTRO methodology).

### ASTRIDE / Arrows

**ASTRIDE:** Uses Vision-Language Models to analyse architecture diagrams, then an LLM to write threat reports. "AI to protect AI."

**Arrows:** Uses specialised LLM analysers for each STRIDE category, produces interactive diagrams.

**Where they overlap with ThreatLens:** LLM-based STRIDE threat modelling.

**Where they differ:**
- Both are diagram-first; ThreatLens is code-first.
- Both produce reports; ThreatLens produces structured artefacts.
- I don't have detail on their deployment model, in-repo behaviour, or enforcement story; these may be research-style demos rather than productised platforms.

**Honest read:** Diagram-first is a legitimately different UX. If your team prefers visual threat modelling and you can describe your architecture as a diagram, these are worth investigating.

### MAESTRO (framework, not a tool)

**What it is:** Multi-Agent Environment, Security, Threat, Risk, & Outcome. A threat-modelling *framework* (not a tool) from the Cloud Security Alliance, specifically designed for agentic-AI systems. Addresses the "dynamic trust boundaries" problem that breaks classical STRIDE when applied to LLM-based systems.

**How it relates to Loupe:** ThreatLens could adopt MAESTRO as an additional categorisation alongside STRIDE for AI-system threats. Or, more likely, a future `AIRiskLens` would use MAESTRO as its methodology. Tools like TITO show the framework is implementable.

**Honest read:** MAESTRO is what STRIDE would become if reinvented for agentic AI. ThreatLens stays STRIDE-based because most code isn't agentic; AIRiskLens (if/when built) should probably use MAESTRO.

---

## CRA-specific evidence tooling

### Concordance

**What it is:** Commercial CRA-compliance platform. Continuous evidence mapping engineering data from your toolchain, structured against Annex I requirements. Observes 50 engineering protocols mapped to all 21 Annex I essential requirements.

**This is the most directly comparable tool on the CRA-evidence side.** Concordance focuses on the *evidence-from-toolchain* angle that Loupe's `runs/*.json` + artefact set is heading toward.

**Where they differ:**
- Concordance is multi-protocol: it ingests data from many engineering tools and maps them to CRA requirements. Loupe is single-domain: it produces threat-modelling evidence specifically.
- Concordance is SaaS; Loupe is local-first.
- Concordance covers all 21 Annex I requirements; Loupe primarily addresses risk-assessment (§1), secure-by-design (§§1b/1c), SBOM (§2), and vulnerability handling. Other Annex I requirements (technical documentation completeness, user information, declaration of conformity) are out of Loupe's scope.

**Honest read:** Concordance and Loupe are *complementary*, not substitutes. Concordance maps existing toolchain output to CRA; Loupe generates the threat-modelling portion of that toolchain output. A buyer of both would get: Loupe produces high-quality `threats.yaml` + `mitigations.yaml` + `vex.json`; Concordance ingests them and maps them into a CRA-conformity package.

### ENISA Single Reporting Platform (SRP) not a tool, a regulatory artefact

CRA reporting obligations begin **11 September 2026**[^cra-reporting] (4 months from when this doc was last updated). Manufacturers must report certain vulnerabilities and incidents via ENISA's SRP, coordinated through their Member State CSIRT. Loupe is not a reporting tool; Concordance and similar platforms presumably integrate with the SRP.

---

## Threat-modelling-as-code (pre-AI lineage)

### Threagile

**What it is:** Open-source. Threat modelling defined in YAML. Generates threat models from declarative input.

**Lineage shared with Loupe:** "Threat models as version-controlled artefacts" is a Threagile idea ThreatLens inherits. The difference: Threagile YAML is human-authored; Loupe artefacts are AI-drafted-human-approved.

### pytm (OWASP pytm)

**What it is:** Open-source. Python DSL for declaring threat models programmatically. Outputs diagrams + reports.

**Lineage shared with Loupe:** Same as Threagile version-controlled, code-first. Python rather than YAML.

**Honest read on both:** If your team is comfortable writing threat models by hand and prefers fully-deterministic tooling (no AI), Threagile or pytm are the right choice. Loupe accepts higher variance in exchange for less manual work.

---

## Manual / commercial threat-modelling tools

### IriusRisk

**Largest commercial threat-modelling product by market share** (42.1% per PeerSpot, March 2026[^peerspot-iriusrisk]). AI-augmented since 2023. SaaS deployment.

| IriusRisk | Loupe |
|---|---|
| SaaS, cloud-managed | Local-first, runs in your repo |
| Pattern-library-based threat generation + AI | AI-drafted with Pydantic-typed artefacts |
| Single-vendor | Multi-LLM, multi-lens |
| Enterprise sales motion | Self-serve, OSS |
| Mature (many years in market) | Pre-alpha |

If you need a mature commercial product *now* and your procurement prefers SaaS with a vendor relationship: IriusRisk. If you want full control over data, multi-LLM flexibility, and platform extensibility: Loupe.

### Devici

**What it is:** Commercial. Founded by ex-OWASP Threat Dragon team. Diagrammatic + AI-augmented threat modelling. SaaS. Built-in threat libraries and visual workflows.

Closest in spirit to "Threat Dragon, but with AI added." Diagram-first like Threat Dragon; AI-enhanced like IriusRisk.

### OWASP Threat Dragon

Open-source, manual. (Detailed earlier draft retained below in the "Pre-AI threat-modelling tools" comparison context.)

| Threat Dragon | ThreatLens |
|---|---|
| Manual diagram drawing | Mermaid diagrams generated/maintained from code |
| Human authors all content | AI drafts, human approves |
| One-shot artefact | Living artefact, updated on every PR |
| Single JSON output | Threats + mitigations + VEX + SBOM, all standards-conformant |
| No CI integration | First-class CI integration |
| No regulatory framing | CRA Annex I-shaped evidence by default |

### Microsoft Threat Modeling Tool v4.2

Windows-only. Now includes AI-assisted threat detection (added in v4.2). Same lineage as Threat Dragon visual, manual, with AI augmentation.

---

## Snyk

**What Snyk does**: SCA (Software Composition Analysis) + SAST (Static Application Security Testing) + container scanning + IaC scanning + secrets detection. Commercial; cloud-managed UI.

**Where it overlaps with Loupe**:
- SBOM generation and CVE matching. Snyk does both, well.
- Some level of "fix this" suggestions, AI-augmented.

**Where Loupe goes beyond Snyk**:
- **Loupe produces a structured *threat model*** (per-element STRIDE threats, mitigations with evidence pointers). Snyk produces vuln lists, not threat models.
- **Loupe produces CRA-shaped evidence** (OpenVEX statements with rationale, decision logs as ADRs). Snyk's reports are designed for security teams, not auditors.
- **Loupe is local-first** (artefacts live in your repo). Snyk's data lives in Snyk's cloud.
- **Loupe is multi-LLM**. Snyk's AI features are proprietary.

**Where Snyk goes beyond Loupe**:
- Container scanning, IaC scanning, secrets detection, and SAST none of which Loupe attempts.
- A polished SaaS dashboard with role-based access, integrations, etc.
- Auto-PR-fix flows.

**When to use which**:
- Use **Snyk** (or Trivy, or both) as your vuln/dep scanner Loupe wraps Syft+Grype/osv-scanner internally but isn't trying to compete on scan quality.
- Use **Loupe** when you also need a structured threat model that responds to code changes, with CRA-shaped artefacts.
- They can co-exist: Snyk in CI scanning for vulns, Loupe in CI producing threat-modelling evidence. Different jobs.

---

## Trivy

**What Trivy does**: Open-source vulnerability scanner from Aqua Security. SBOM generation, CVE matching, container/IaC/secrets scanning. CLI-first.

**Where it overlaps with Loupe**:
- SBOM + CVE matching (Loupe wraps Syft+Grype, but Trivy could substitute).
- Both are CLI-first, scriptable.

**Where they differ**:
- Trivy stops at vulnerability data. Loupe takes vulnerability data and folds it into a threat-model + VEX evidence pack with rationale.
- Trivy has no threat-modelling concept; Loupe is *built* around threat modelling.

**Possible future integration**: A `loupe-trivy-adapter` lens could replace Syft+Grype with Trivy as the scanning back-end. The lens API is designed to support this kind of substitution.

---

## cdxgen

**What it does**: Open-source CycloneDX SBOM generator from the OWASP CycloneDX project. Strong coverage of language ecosystems Syft is weaker on (notably JVM build graphs and some scripting-language manifests).

**Relationship to Loupe**: Bundled as a registered `sbom` capability backend. Operators who want belt-and-braces SBOM coverage can set `capabilities.sbom.mode: union` and list `[syft, cdxgen]` so both run and findings are deduped by purl.

---

## osv-scanner

**What it does**: Google's open-source CVE matcher. Reads SBOMs or lockfiles and checks them against the OSV.dev database. Different vulnerability source from Grype (which leans on the NVD-derived Anchore feed).

**Relationship to Loupe**: Bundled as a registered `cve` capability backend. A common composition is `capabilities.cve.mode: union, backends: [grype, osv-scanner]` so that CVEs missed by either DB are caught by the other.

---

## gitleaks

**What it does**: Open-source secret scanner. Pattern-matched detection of common credential shapes (AWS keys, GitHub tokens, private keys) across git history.

**Relationship to Loupe**: Bundled as a registered `secret_detect` capability backend. Pairs well with TruffleHog under `mode: union` — gitleaks catches pattern-matched keys; TruffleHog catches high-entropy strings and verifies live credentials.

---

## TruffleHog

**What it does**: Open-source secret scanner from Truffle Security. Combines high-entropy detection with credential-verifier plugins that actually attempt to use a found secret to confirm it's live.

**Relationship to Loupe**: Bundled as a registered `secret_detect` capability backend. The verification step makes it complementary to pattern-matching scanners — TruffleHog distinguishes "looks like a token" from "is an active token."

---

## detect-secrets

**What it does**: Open-source pattern-based secret scanner from Yelp. Built around an auditable baseline file so previously-acknowledged findings don't re-fire; widely used inside pre-commit hooks.

**Relationship to Loupe**: Bundled as a registered `secret_detect` capability backend. Useful as a third corroborating scanner under `mode: consensus` for teams that want at least two of three tools to agree before treating a secret-detection finding as real.

---

## CodeQL

**What it does**: GitHub's open-source query-based static analysis engine. Treats code as a database queryable in QL; strong on data-flow and taint analysis across many languages.

**Relationship to Loupe**: Bundled as a registered `static_analysis` capability backend. Heavier and slower than Semgrep — best deployed under `mode: consensus` alongside Semgrep so the corroboration filters CodeQL's slower runtime against Semgrep's faster pattern matches.

---

## Bandit

**What it does**: Open-source Python-specific SAST from the PyCQA project. AST-based detection of Python anti-patterns and security smells (subprocess shell-injection, weak crypto, hard-coded passwords).

**Relationship to Loupe**: Bundled as a registered `static_analysis` capability backend. The narrow Python focus makes it a useful third opinion in consensus mode for Python-heavy projects; on non-Python repos the backend's `is_available()` keeps it dormant.

---

## Wiz

**What Wiz does**: Cloud security posture management (CSPM) + CNAPP. Inventories cloud resources, finds misconfigurations and exposed attack paths in running cloud infrastructure. Commercial; cloud-managed.

**Where it overlaps with Loupe**: Almost nowhere. Wiz operates at runtime against cloud APIs; Loupe operates at code-change time against a repo.

**Why they're complementary**: If you ship on AWS, you probably want both Wiz for the runtime story and Loupe for the code-change-evidence story. They feed different audit asks. Wiz can show "your S3 bucket is public *right now*"; Loupe can show "your PR introduced a code path that writes to S3 with no encryption-at-rest assertion in the threat model."

---

## Semgrep

**What Semgrep does**: Static analysis via pattern-matching rules. Open-source + commercial cloud. Strong at finding known anti-patterns, security smells, and policy violations in code.

**Where it overlaps with Loupe**: Both can flag security-relevant code patterns. Semgrep does it via rules; Loupe does it via AI threat-modelling.

**Where they're complementary**:
- A future Loupe lens (or even an enhancement to ThreatLens) could *call Semgrep as a tool* during analysis. The agent says "I want to know if this codebase has unparameterised SQL queries" Semgrep answers definitively, the agent uses the result in its threat reasoning.
- Semgrep finds known anti-patterns; ThreatLens identifies novel threat scenarios. Different abilities.

**When to use which**:
- Use **Semgrep** for codified policy checks (e.g., "no insecure deserialization patterns", "all HTTP routes must call `require_auth()`"). It's deterministic and fast.
- Use **Loupe** for threat reasoning that requires understanding what the code *does*, not just what patterns it matches.

---

## GitHub Advanced Security (CodeQL, Dependabot, secret scanning)

**What GHAS does**: Code scanning (CodeQL queries for vulnerabilities), dependency scanning (Dependabot), secret scanning. GitHub-integrated.

**Where they overlap**: SBOM/CVE territory (Dependabot equivalent). Loupe gets this via Syft+Grype/osv-scanner; GHAS does it through its own integration.

**Where they're complementary**:
- GHAS finds known issues (CodeQL queries, known vulnerable deps, leaked secrets). Loupe builds the threat model around them.
- GHAS's findings could be ingested by ThreatLens (or a future lens) as inputs to threat reasoning.
- They run in the same place (GitHub Actions) so combining them is natural.

**When to use which**:
- Use **GHAS** for the defect-detection layer. It's well-integrated and broadly capable.
- Use **Loupe** for the threat-modelling and CRA-evidence layer.

---

## Claude Code / Cursor / Aider / generic AI coding assistants

**What they do**: General-purpose AI assistants for coding.

**Where they overlap**: Both Loupe and these tools use LLMs to reason about code.

**Where they differ fundamentally**:
- Generic AI assistants help you *write code*. Loupe helps you *reason about risk in code*.
- Generic AI assistants have an open tool surface (Read/Edit/Bash/Search/etc.). Loupe has a narrow, audited tool surface (`write_agent_artifact`, `propose_patch`, lens-specific structured tools).
- Generic AI assistants produce code. Loupe produces structured artefacts (Pydantic-validated, standards-conformant).

**How they relate**: Loupe exposes its tools and workflows over MCP. Claude Code, Cursor, ChatGPT desktop can attach to a running `loupe mcp` server and *drive* Loupe "what threats does this PR introduce?" answered by Claude Code calling `loupe.workflows.run_for_diff`. The two are complementary at the protocol level.

---

## Renovate / Dependabot

**What they do**: Automate dependency-update PRs.

**Relationship to Loupe**: Fully orthogonal. Renovate raises a PR with a dep bump; Loupe runs against that PR and identifies new threat surface, draft VEX statements for newly-introduced CVEs, etc.

They're a natural pair in CI: Renovate opens the PR, Loupe analyses it, both contribute to a unified review.

---

## When Loupe is the wrong choice

To save you and us time:

- **You're shipping consumer software with no regulatory exposure.** The artefact set is overkill. Use a simpler threat-modelling tool, or skip formal threat modelling.
- **Your team explicitly forbids AI involvement in security decisions.** Loupe's default workflow assumes AI-drafted, human-approved. If that's not OK, use Threat Dragon or similar.
- **You want a turnkey SaaS with role-based access, SSO, and a polished UI.** Loupe is local-first and pre-alpha. Use IriusRisk.
- **You only need vulnerability scanning.** Use Snyk / Trivy / GHAS; they're better at that specific job.
- **You're looking for a generic AI assistant.** Use Claude Code, Cursor, or Aider.

## When Loupe is the right choice

- **You're subject to CRA, ISO/SAE 21434, or similar regulation** and need evidence-grade artefacts in your repo, updated as code changes.
- **You have multiple regulated teams** (security, safety, privacy) who could share infrastructure rather than running parallel point-tools.
- **You care about LLM-vendor independence** and don't want a tool that only works on one provider's API.
- **You want AI assistance with strong write-boundary guarantees** rather than "trust the system prompt."
- **You're an AI-augmented engineering team** wanting your AI assistants to share a structured risk model via MCP, instead of re-prompting the model with the same context every conversation.

If those describe you, Loupe is the right shape. If they don't, one of the tools above is probably better.

---

## Sources

External claims in this page are anchored to footnotes. URLs marked `pending` need to be filled in from the original references — they were not fabricated and are not yet verified.

[^peerspot-iriusrisk]: IriusRisk market-share figure. Source: PeerSpot "Threat Modeling Tools" category review, March 2026. URL pending. Accessed: pending.
[^ms-tmt-v42]: Microsoft Threat Modeling Tool v4.2 release notes — AI-assisted threat detection. URL pending. Accessed: pending.
[^concordance]: Concordance product page / documentation — coverage of CRA Annex I and 50-protocol mapping. URL pending. Accessed: pending.
[^maestro]: MAESTRO framework — Cloud Security Alliance publication. URL pending. Accessed: pending.
[^stridegpt]: StrideGPT (mrwadams/stride-gpt) — supported providers documented in the project README. URL pending. Accessed: pending.
[^threatcompute]: ThreatCompute — paper at the 2025 ACM Cloud Computing Security Workshop (CCSW). URL pending. Accessed: pending.
[^cra-reporting]: EU CRA reporting-obligation start date — Regulation (EU) 2024/2847. Reporting obligations apply from 11 September 2026; full applicability 11 December 2027. URL pending (Official Journal of the EU). Accessed: pending.
