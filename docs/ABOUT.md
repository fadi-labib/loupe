# About Loupe

> *A loupe is the small, high-precision lens used by jewellers, watchmakers, and document examiners to inspect detail others miss. The name is deliberate.*

## The problem Loupe addresses

Software-engineering risk activities — threat modelling, hazard analysis, privacy review, AI-risk review — have a structural problem in common: **the artefacts they produce drift out of sync with the code they describe**, and the work needed to keep them in sync is the kind of slow, careful, evidence-shaped work that most engineers will not do without external pressure.

The result is one of two failure modes:

1. **Stale documents.** A threat model written in a wiki in 2023 still says the system uses session cookies long after it moved to OAuth. The document exists, an auditor reads it, the auditor is satisfied — but the document no longer reflects reality. This is the dominant outcome.
2. **Compliance theatre.** A scanner emits a 200-page PDF on every commit that says everything is fine, and nobody reads it. The artefact exists, the process runs, but no actual analysis happens. This is the second-dominant outcome.

The EU Cyber Resilience Act (fully applicable December 2027) requires, among other things, that manufacturers of "products with digital elements" maintain a current risk assessment, a secure-by-design rationale, a software bill of materials, and per-vulnerability impact statements. The regulators have explicitly signalled that they expect these artefacts to be *living* documents, not point-in-time PDFs filed after release. The pressure to solve this problem is going to grow, not shrink.

## The bet Loupe makes

The bet has three parts:

1. **AI agents can do the slow, careful, evidence-shaped work** that engineers won't do — but only if their outputs are structured, auditable, and human-reviewed at the boundaries that matter.
2. **The right design is plug-in lenses on a shared platform**, not a monolithic agent. Threat modelling and safety analysis and privacy review have different methods but share infrastructure (diff parsing, SBOM generation, artefact storage, enforcement, MCP exposure). Building this once and adding lenses is cheaper, in the long run, than building N point-tools.
3. **The platform must be auditor-credible from day one**, or it loses to the spreadsheet. That means: outputs follow industry standards (CycloneDX, OpenVEX); artefacts are versioned in Git; every change is traceable to a human or to a logged AI run; protected files (the human-authored context, the decision log) cannot be silently overwritten; and the enforcement of all this is in *code*, not in *policy*.

## What "Loupe" means in practice

Loupe is **the platform**. It is domain-agnostic. It knows nothing about STRIDE, ISO 26262, LINDDUN, or NIST AI RMF. It knows about: parsing diffs, generating SBOMs, talking to multiple LLM providers, building cache-friendly prompts, enforcing write boundaries, persisting structured artefacts, exposing tools over MCP, coordinating multiple lenses to share context cheaply, and analysing either an incremental change (a PR diff) or a whole codebase from scratch (`loupe scan`) — same artefacts, same enforcement, different scope of analysis (see [`DESIGN-DECISIONS.md` D-15](DESIGN-DECISIONS.md#d-15--full-repo--no-diff-scans-are-first-class-via-loupe-scan)).

A **lens** is a Python package that registers with Loupe (via standard Python entry points) and contributes:
- A PydanticAI agent specialised for one domain
- Pydantic-typed artefacts that lens owns
- MCP tools and workflows other agents can call
- A pure-Python `is_relevant()` function that lets the coordinator skip the lens cheaply when a particular diff doesn't touch its domain

v1 ships exactly one lens: **ThreatLens**. It looks for STRIDE-shaped threats, maintains a threat-model document and a machine-readable threat/mitigation index, generates SBOMs and per-CVE VEX statements. Its outputs are structured to feed CRA Annex I conformity evidence.

Future lenses we anticipate (in roadmap order):

| Lens | Domain | Standards it would feed |
|---|---|---|
| **SafetyLens** | Functional safety | ISO 26262 (automotive), IEC 61508 (industrial), IEC 62304 (medical) |
| **PrivacyLens** | Data protection | GDPR DPIA, LINDDUN threat modelling |
| **AIRiskLens** | AI/ML risk | NIST AI RMF, EU AI Act high-risk requirements |

None of these are committed; they're directional. The work to deliver each one is roughly "build one lens" — significantly less than the platform work that v1 represents.

## Why the name avoids "compliance"

A product that calls itself a "compliance agent" sends two unintended signals:

- **To engineers**, it signals "this is here to slow you down with paperwork." Adoption suffers.
- **To auditors**, it signals "this is here to make compliance look done." Credibility suffers.

Both audiences need to take Loupe seriously for it to work. So Loupe takes its name from the *engineering activity* it accelerates — close inspection, with the right lens — rather than from the *regulatory regime* it happens to feed. Compliance is a side-effect of doing the work properly, not the framing.

The lens metaphor extends this: each lens is named after *what it looks at*, not *what it complies with*. "ThreatLens" not "ISO/SAE 21434 Agent". "SafetyLens" not "ISO 26262 Agent". The standard is implementation detail; the activity is identity.

## Who Loupe is for

In rough order of likely adoption:

1. **Security engineers in companies subject to the EU CRA.** They need evidence-grade threat models that update with every PR, and they need them quickly because the CRA's December 2027 deadline is closer than people think.
2. **Functional-safety engineers in regulated industries** (automotive, medical, industrial). They've been doing hazard analysis on spreadsheets for years and would benefit from structured tooling — eventually, when SafetyLens lands.
3. **Platform / DevSecOps teams** building shared infrastructure for multiple regulated teams. They want one workflow instead of one tool per regulation.
4. **AI-augmented engineering teams** who want their AI assistants (Claude Code, Cursor, ChatGPT) to be able to query and update a structured risk model via MCP, rather than re-prompting the model with the same context every conversation.

Loupe is **not** for:

- Teams whose primary product is consumer software with no regulatory exposure (the artefact set is overkill).
- Teams looking for a generic AI coding assistant (use Claude Code or Cursor directly).
- Teams whose process explicitly forbids AI involvement in security decisions (Loupe assumes AI-drafted, human-approved as the default workflow).

## Where Loupe came from

Loupe started as a brainstorming conversation about a "compliance-but-not-called-compliance" AI agent. The original idea was a single agent that helped with CRA, security standards, safety standards (ISO 26262), risk management, etc. — broad in scope, with the user explicitly wanting it to "not look like fake compliance."

Through a structured brainstorming session, the design narrowed:

- From "many regulations" to "one well-fit method (STRIDE) producing CRA-shaped evidence" (with a plugin architecture so other domains can be added as lenses later).
- From "an agent" to "a platform of lenses on a shared core."
- From "ThreatLens-as-the-product" to "Loupe-as-the-platform, ThreatLens-as-the-first-lens" — because making the product *be* the threat-modelling tool would have locked in the domain unnecessarily.
- From "use whatever LLM framework" to "PydanticAI specifically" — because (a) provider-agnostic from day one, (b) Pydantic models double as artefact schemas + tool I/O + MCP schemas, three jobs from one definition, (c) lightweight without LangChain's abstraction tax.
- From "save context" interpreted as session-resumption-over-time, then (when the user clarified) re-interpreted as **cost-saving via shared blackboard within one run** — which led to the explicit three-lever cost design (prompt cache + blackboard + coordinated dispatch).

The full decision log lives at [`DESIGN-DECISIONS.md`](DESIGN-DECISIONS.md). The values that emerged through those decisions are at [`VALUES.md`](VALUES.md).
