# About Loupe

> A loupe is the small, high-precision lens jewellers, watchmakers, and document examiners use to inspect detail others miss.

## The problem

Software-engineering risk activities (threat modelling, hazard analysis, privacy review, AI-risk review) share a structural problem: the artefacts they produce drift out of sync with the code they describe, and the work needed to keep them in sync is the slow, careful, evidence-shaped work most engineers will not do without external pressure.

The two failure modes are stale documents and compliance theatre. A threat model written in a wiki in 2023 still says the system uses session cookies after it moved to OAuth two years ago; the document exists, an auditor reads it, the auditor is satisfied, but the document does not reflect reality. Or a scanner emits a 200-page PDF on every commit that says everything is fine, and nobody reads it; the artefact exists, the process runs, no actual analysis happens.

The EU Cyber Resilience Act (fully applicable December 2027) makes this worse. Manufacturers of "products with digital elements" must maintain a current risk assessment, a secure-by-design rationale, an SBOM, and per-vulnerability impact statements. Regulators have signalled they expect these to be living documents, not point-in-time PDFs filed after release.

## The bet

Three claims, in order of how much they shape the design.

AI agents can do the slow, careful, evidence-shaped work that engineers will not, provided their outputs are structured, auditable, and human-reviewed at the boundaries that matter.

A plugin platform with separate domain lenses is the right shape, not a monolithic agent. Threat modelling, safety analysis, and privacy review have different methods but share infrastructure (diff parsing, SBOM generation, artefact storage, enforcement, MCP exposure). Building this once and adding lenses costs less than building N point tools.

The platform must be auditor-credible from day one or it loses to the spreadsheet. That means outputs follow industry standards (CycloneDX, OpenVEX, STRIDE), artefacts are versioned in Git, every change is traceable to a human or to a logged AI run, protected files cannot be silently overwritten, and the enforcement is in code, not in policy.

## How the platform is organised

Loupe is the platform. It is domain-agnostic. It knows nothing about STRIDE, ISO 26262, LINDDUN, or NIST AI RMF. It parses diffs, generates SBOMs, talks to multiple LLM providers, builds cache-friendly prompts, enforces write boundaries, persists structured artefacts, exposes tools over MCP, and coordinates multiple lenses cheaply.

Two extension points sit on top of the platform.

A **lens** is a domain plugin (the noun): ThreatLens for security, SafetyLens for functional safety, PrivacyLens for data protection. A lens reasons about a domain. It contributes a PydanticAI agent, Pydantic-typed artefacts, MCP tools and workflows, and a pure-Python `is_relevant()` function the coordinator uses to skip the lens when a diff does not touch its domain.

A **capability** is a tool-agnostic operation plugin (the verb): `SbomCapability`, `CveCapability`, `SecretDetectionCapability`, `StaticAnalysisCapability`. A capability does one job and is fulfilled by a backend (Syft, Trivy, gitleaks, Semgrep, others). Multiple backends per capability can compose through modes like `union` or `consensus`. Lenses declare which capabilities they need; the platform resolves backends from `config.yaml`.

The result is no tool lock-in alongside no LLM lock-in. A team can run Loupe on Syft or Trivy, with one CVE scanner or three, with belt-and-braces secret detection or a single fast scanner, all through configuration.

v1 ships ThreatLens. It looks for STRIDE-shaped threats, maintains a threat-model narrative and machine-readable threat and mitigation indexes, and generates per-CVE VEX statements. Its outputs feed CRA Annex I conformity evidence.

Future lenses we anticipate:

| Lens | Domain | Standards it would feed |
|---|---|---|
| SafetyLens | Functional safety | ISO 26262 (automotive), IEC 61508 (industrial), IEC 62304 (medical) |
| PrivacyLens | Data protection | GDPR DPIA, LINDDUN threat modelling |
| AIRiskLens | AI/ML risk | NIST AI RMF, EU AI Act high-risk requirements |

None of these are committed. The work to deliver each one is roughly "build one lens," significantly less than the platform work v1 represents.

## CRA Annex I coverage

The artefact set in `.loupe/` was designed against the EU CRA Annex I conformity evidence pack from the start, with STRIDE as the natural method.

| CRA Annex I requirement | Loupe artefact |
|---|---|
| §1 Risk assessment | `threats.yaml`, `threat-model.md`, `mitigations.yaml` |
| §1(b)(c) Secure-by-design rationale | `decisions/*.md` (ADR-style risk acceptances) |
| §2 SBOM | `sbom.cdx.json` (CycloneDX) |
| §2(c) Vulnerability handling | `vex.json` (OpenVEX) |
| Audit trail of conformity-assessment activities | `runs/*.json` (hash-chained) |

You can hand these files to an auditor, or to a CRA submission platform such as Concordance that ingests engineering data into a submission package.

## Trade-offs worth stating

Pre-alpha. The platform, capability registry, CLI, and GitHub Action exist; the ThreatLens PydanticAI agent is scaffolded but not yet wired to a live LLM. Quality of threat-modelling output is unproven until that lands.

One lens at v1. The multi-domain design is real, but the second lens has not been built.

STRIDE only. No attack trees, no DREAD scoring, no Gherkin test-case generation. StrideGPT has these.

GitHub-first. GitLab, Gitea, and Bitbucket adapters are part of the design but not implemented.

No managed UI. Loupe is local-first by choice. If you need a dashboard, you build one on top of the structured outputs.

Self-supported. Apache 2.0, no commercial support contract.

If any of those are dealbreakers, [`COMPARISON.md`](COMPARISON.md) points to alternatives.

## Why the name avoids "compliance"

A product that calls itself a "compliance agent" sends two unintended signals. To engineers it says "this is here to slow you down with paperwork." To auditors it says "this is here to make compliance look done." Both audiences need to take Loupe seriously for it to work.

The name comes from the engineering activity (close inspection through the right lens), not the regulatory regime it happens to feed. Compliance is a side effect of doing the work properly. Each lens is named after what it looks at, not what it complies with: ThreatLens, not "ISO/SAE 21434 Agent." SafetyLens, not "ISO 26262 Agent." The standard is implementation detail; the activity is identity.

## See also

The eleven principles that guide every decision: [`PRINCIPLES.md`](PRINCIPLES.md). The decision log itself: [`DESIGN-DECISIONS.md`](DESIGN-DECISIONS.md).
