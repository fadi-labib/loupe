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

## Why Loupe exists — the value proposition

Each of these is a deliberate choice, not a marketing claim. The "why we picked it" reasoning is at least as important as the choice itself.

### Open source, Apache 2.0-licensed
Threat modelling is a security activity. Security tools that are closed-source ask you to trust their analysis without verification. **Apache 2.0 means you can read every line, fork the project, integrate it into a commercial product, audit it for backdoors, or strip pieces out for your own use.** Apache 2.0 adds an explicit patent grant from contributors to users and a trademark non-grant that protects the project name. No GPL viral effects, no AGPL deployment restrictions, no "free for community, contact sales for enterprise" upsell. The author's name is in `LICENSE`; everything else is yours.

The trade-off: no formal SLA, no commercial support contract. We accept that explicitly. For a security tool with auditor implications, transparency is more valuable than vendor backing.

### Free
No per-seat fees, no usage limits, no SaaS subscription. You pay only for the LLM tokens consumed by whatever provider you choose — and Loupe's cost-saving levers (prompt caching, shared blackboard, coordinated dispatch) keep that bill realistic. For a docs-only PR, the marginal cost is **less than a tenth of a cent**.

The trade-off: you provide the compute and the LLM API key. We can't promise "your bill will be zero." But we can promise the bill scales with use, not with seats.

### No vendor lock-in (multi-LLM)
PydanticAI-native multi-provider support means `THREATLENS_MODEL=anthropic:claude-opus-4-7` or `openai:gpt-5` or `google-gla:gemini-2.5-pro` or `ollama:llama-3.3-70b` — same code, different provider. This matters because:

- **Approved-LLM lists exist.** Regulated customers (finance, healthcare, automotive) often have an internal list of permitted LLM vendors. Lock-in eliminates them.
- **Cross-provider verification is a legitimate audit ask.** "Did you cross-check this threat model against a second model?" — Loupe enables it as a one-line config change.
- **Cost optimisation works.** Cheap model for bulk CVE annotation; smart model for nuanced threat reasoning. Mix per task.
- **Vendor risk is real.** Providers go down, raise prices, pivot APIs, get acquired. Lock-in concentrates that risk.

The trade-off: harder to deeply optimise for one provider's edge features. We accept that trade.

### No vendor lock-in (no SaaS, local-first)
All artefacts live in your repo as plain files. There is no Loupe-hosted service, no telemetry, no cloud database. Migration cost is zero — your `.loupe/` directory IS the state. See [`DATA-HANDLING.md`](DATA-HANDLING.md) for the full data flow.

The trade-off: no centralised dashboard, no cross-repo aggregation in v1. If you need those, you build them on top — the artefacts are structured data, perfectly consumable.

### Multi-flow: one core, three frontends
Same engine, three ways to invoke:

- **`loupe ci`** — runs on every PR via a tiny GitHub Action (or any CI). Producer of the proposal-PR pattern.
- **`loupe chat`** — interactive terminal session. Default-N confirmations on every protected-path change.
- **`loupe mcp`** — exposes Loupe's tools and workflows over the Model Context Protocol. Claude Code, Cursor, ChatGPT desktop, or any MCP-aware client can drive Loupe directly.

Each frontend is thin; the core does all the work. The same artefacts, the same enforcement, the same RunContext blackboard apply to all three. This was a deliberate decision (D-02): both modes first-class from day one, so the platform never becomes one mode bolted onto another.

### Plugin-extensible (multiple domains)
v1 ships **ThreatLens** for STRIDE-based security threat modelling. The platform supports more lenses on the same core:

- **SafetyLens** (future) — ISO 26262 / HARA for functional safety
- **PrivacyLens** (future) — LINDDUN / GDPR DPIA for data protection
- **AIRiskLens** (future) — NIST AI RMF / MAESTRO for AI/ML risk

Each is a separately-installable pip package that registers via Python entry points. Adding a domain doesn't fork the project; it just installs another lens. The plugin contract (six methods, recorded in D-11) is intentionally minimal — we'll refine it when the second lens lands rather than over-design upfront (D-04).

### Auditor-credible by design
Four enforcement layers (D-08):

1. **Tool surface** — the agent's filesystem-write tools enforce a path allow-list in code, not in prompt instructions
2. **Branch namespace** — the CI runner can only push to `loupe/proposal-*` branches; CODEOWNERS gates protected paths
3. **`loupe verify`** — local pre-commit hook + required CI check; verifies hash chain + authorship
4. **Interactive UX gate** — every protected-path proposal renders as a diff with default-N prompt

Plus standards-conformant outputs (CycloneDX SBOM, OpenVEX statements, STRIDE threats with stable IDs) so a regulator's tooling can verify Loupe's outputs without trusting Loupe. Git history is the audit substrate.

### CI-friendly and cost-disciplined
Three cost-saving levers (D-10), each built into the architecture rather than relying on individual lens authors to remember:

1. **Stable-prefix prompt assembly** — the part of the prompt that's identical across lens calls (system framing, `context.md`, diff summary, SBOM delta) is paid full price once and ~10% on subsequent calls via Anthropic's prompt cache
2. **Shared blackboard (RunContext)** — diff parsing, SBOM generation, CVE matching happens once per run; lenses read, never re-derive
3. **Coordinated dispatch** — the coordinator skips lenses with low relevance to a given diff. A docs-only PR triggers zero LLM calls.

Illustrative per-PR cost (Claude Opus): docs-only ~$0.001, single-dependency change ~$0.07, new-endpoint PR ~$0.11, three-lens analysis ~$0.21. Naive baselines (no cache, no skip) are 3–5× higher.

### AI-assistant native (MCP)
The MCP server exposes Loupe's capabilities in two namespaces:

- **`loupe.tools.*`** — granular operations (list threats, propose a threat, query the knowledge graph)
- **`loupe.workflows.*`** — high-level workflows (analyse a diff, draft an audit pack)

This means Claude Code, Cursor, ChatGPT desktop, or any MCP-aware client can drive Loupe directly. Your developer asks Claude Code "what threats does this PR introduce?" and Claude Code calls `loupe.workflows.run_for_diff` — same enforcement, same artefacts.

The trade-off: an extra moving piece in the architecture. We accept it because the alternative (engineers re-explaining context to their AI every conversation) is a worse user experience than "Claude Code already knows the threat model because Loupe maintains it."

### CRA-Annex-I-shaped from day one
The artefact set (D-06) wasn't designed for threat modelling first and then retrofitted to CRA. It was designed for **the EU CRA Annex I conformity evidence pack** from the start, with STRIDE as the natural method:

| CRA Annex I Requirement | Loupe artefact that addresses it |
|---|---|
| §1 — Risk assessment | `threats.yaml` + `threat-model.md` + `mitigations.yaml` |
| §1(b)(c) — Secure by design rationale | `decisions/*.md` (ADR-style risk acceptances) |
| §2 — SBOM | `sbom.cdx.json` (CycloneDX) |
| §2(c) — Vulnerability handling | `vex.json` (OpenVEX) |
| Audit trail of conformity-assessment activities | `runs/*.json` (hash-chained) |

You can hand these files to an auditor, or to the Concordance / similar platforms that ingest engineering data into a CRA submission package.

---

## Honest trade-offs

A balanced statement of value means stating the costs too:

- **Pre-alpha.** Phases 4–10 of the implementation plan remain. Quality of threat-modelling output is unproven until Phase 6 lands.
- **One lens at v1.** Multi-domain is the design intent; the second lens hasn't been built yet.
- **STRIDE only.** No attack trees, no DREAD scoring, no Gherkin test-case generation in v1. StrideGPT has these.
- **GitHub-first VCS.** GitLab / Gitea / Bitbucket adapters are designed-for but not implemented.
- **No managed UI.** Loupe is local-first by choice; if you need a dashboard, you build it from the structured outputs.
- **Self-supported.** Open-source, Apache 2.0, no commercial support contract.

If those are dealbreakers for you, the comparison table in [`COMPARISON.md`](COMPARISON.md) points to alternatives that might fit better.

---

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
