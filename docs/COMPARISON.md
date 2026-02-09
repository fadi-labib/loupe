# Loupe vs. adjacent tools

> Honest comparisons against tools in adjacent spaces. Some are competitors; most are complements. The goal is to help you decide *what to use Loupe for* and *what to keep using your existing tools for*.

---

## TL;DR

| Tool | Category | Relationship to Loupe |
|---|---|---|
| **Snyk** | SCA + SAST (proprietary) | Complementary; Loupe wraps similar SBOM/CVE tooling but doesn't try to be a SAST |
| **Trivy** | Vuln scanner (OSS) | Complementary; could be a `loupe-trivy-adapter` lens later |
| **Wiz** | Cloud security posture | Different layer; cloud runtime, not code |
| **Semgrep** | Static analysis (OSS + cloud) | Complementary; Loupe could call Semgrep as a tool in a future lens |
| **OWASP Threat Dragon** | Manual threat-modelling tool (OSS) | Closest competitor *in spirit*; Loupe is AI-driven and diff-aware |
| **Microsoft Threat Modeling Tool** | Manual threat-modelling tool (Windows-only) | Same category as Threat Dragon |
| **IriusRisk** | Commercial threat-modelling platform (with AI features) | Closest *commercial* competitor; different deployment model |
| **GitHub Advanced Security** (CodeQL, Dependabot, secret scanning) | Defect detection (cloud-managed) | Complementary; Loupe consumes Dependabot-equivalent data via SBOM/Grype, doesn't replace CodeQL |
| **Claude Code / Cursor / Aider** | Generic AI coding assistants | Complementary via MCP; they can drive Loupe |
| **Renovate / Dependabot** | Dependency-update automation | Complementary; orthogonal concern |

The pattern: Loupe doesn't try to be a vulnerability scanner, a SAST, a SCA, or a generic AI assistant. It's a **threat-modelling-and-CRA-evidence platform** with multi-lens extensibility, and most existing tools are complementary inputs to it (SBOMs, CVE data, code analysis) rather than substitutes for it.

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
- Container scanning, IaC scanning, secrets detection, and SAST — none of which Loupe attempts.
- A polished SaaS dashboard with role-based access, integrations, etc.
- Auto-PR-fix flows.

**When to use which**:
- Use **Snyk** (or Trivy, or both) as your vuln/dep scanner — Loupe wraps Syft+Grype/osv-scanner internally but isn't trying to compete on scan quality.
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

## Wiz

**What Wiz does**: Cloud security posture management (CSPM) + CNAPP. Inventories cloud resources, finds misconfigurations and exposed attack paths in running cloud infrastructure. Commercial; cloud-managed.

**Where it overlaps with Loupe**: Almost nowhere. Wiz operates at runtime against cloud APIs; Loupe operates at code-change time against a repo.

**Why they're complementary**: If you ship on AWS, you probably want both — Wiz for the runtime story and Loupe for the code-change-evidence story. They feed different audit asks. Wiz can show "your S3 bucket is public *right now*"; Loupe can show "your PR introduced a code path that writes to S3 with no encryption-at-rest assertion in the threat model."

---

## Semgrep

**What Semgrep does**: Static analysis via pattern-matching rules. Open-source + commercial cloud. Strong at finding known anti-patterns, security smells, and policy violations in code.

**Where it overlaps with Loupe**: Both can flag security-relevant code patterns. Semgrep does it via rules; Loupe does it via AI threat-modelling.

**Where they're complementary**:
- A future Loupe lens (or even an enhancement to ThreatLens) could *call Semgrep as a tool* during analysis. The agent says "I want to know if this codebase has unparameterised SQL queries" — Semgrep answers definitively, the agent uses the result in its threat reasoning.
- Semgrep finds known anti-patterns; ThreatLens identifies novel threat scenarios. Different abilities.

**When to use which**:
- Use **Semgrep** for codified policy checks (e.g., "no insecure deserialization patterns", "all HTTP routes must call `require_auth()`"). It's deterministic and fast.
- Use **Loupe** for threat reasoning that requires understanding what the code *does*, not just what patterns it matches.

---

## OWASP Threat Dragon

**What Threat Dragon does**: Open-source, manual threat-modelling tool. You draw the data-flow diagram, mark trust boundaries, and the tool prompts you with STRIDE questions per element. Outputs a JSON file.

**This is the closest competitor to ThreatLens in spirit.** They both produce threat models. They differ in how:

| Threat Dragon | ThreatLens |
|---|---|
| Manual diagram drawing | Mermaid diagrams generated/maintained from code |
| Human authors all content | AI drafts, human approves |
| One-shot artefact (you re-do it when architecture changes) | Living artefact, updated on every PR |
| Single JSON output | Threats + mitigations + VEX + SBOM, all standards-conformant |
| No CI integration | First-class CI integration |
| No regulatory framing | CRA Annex I-shaped evidence by default |

**When to use which**:
- Use **Threat Dragon** if your team prefers manual threat modelling, a visual tool, and doesn't have AI budget.
- Use **Loupe** if you want the threat model to stay in sync with the code as it changes, with less ongoing manual effort.

You can also use both: draft the initial architecture in Threat Dragon as a kick-off exercise, then transfer the assets/elements into Loupe's `context.md` and `knowledge.yaml`, and let Loupe maintain it from there.

---

## Microsoft Threat Modeling Tool

Conceptually similar to Threat Dragon (manual STRIDE-based modelling), but Windows-only and more enterprise-y. Same tradeoff vs. Loupe.

---

## IriusRisk

**What IriusRisk does**: Commercial threat-modelling platform. Pattern-library-based threat generation, integrates with Jira/CI, has AI-augmented features. SaaS deployment.

**This is Loupe's closest *commercial* competitor.** They differ in:

| IriusRisk | Loupe |
|---|---|
| SaaS, cloud-managed | Local-first, runs in your repo |
| Proprietary patterns + AI | Open architecture, multi-LLM, multi-lens |
| Single vendor lock-in | Provider-agnostic |
| Enterprise sales motion | Self-serve, OSS |
| Mature (many years in market) | Pre-alpha |

**When to choose which**:
- **IriusRisk** if you need a mature commercial product *now* and your procurement prefers SaaS with a vendor relationship.
- **Loupe** if you want full control over data, multi-LLM flexibility, and a platform you can extend with your own lenses.

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

**How they relate**: Loupe exposes its tools and workflows over MCP. Claude Code, Cursor, ChatGPT desktop can attach to a running `loupe mcp` server and *drive* Loupe — "what threats does this PR introduce?" answered by Claude Code calling `loupe.workflows.run_for_diff`. The two are complementary at the protocol level.

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
- **You only need vulnerability scanning.** Use Snyk / Trivy / GHAS — they're better at that specific job.
- **You're looking for a generic AI assistant.** Use Claude Code, Cursor, or Aider.

## When Loupe is the right choice

- **You're subject to CRA, ISO/SAE 21434, or similar regulation** and need evidence-grade artefacts in your repo, updated as code changes.
- **You have multiple regulated teams** (security, safety, privacy) who could share infrastructure rather than running parallel point-tools.
- **You care about LLM-vendor independence** and don't want a tool that only works on one provider's API.
- **You want AI assistance with strong write-boundary guarantees** rather than "trust the system prompt."
- **You're an AI-augmented engineering team** wanting your AI assistants to share a structured risk model via MCP, instead of re-prompting the model with the same context every conversation.

If those describe you, Loupe is the right shape. If they don't, one of the tools above is probably better.
