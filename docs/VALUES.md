# Loupe — Design Values and Principles

> The values below were not pre-stated; they emerged from specific decisions made during the brainstorming session. Each one explains a rule we now follow throughout the codebase. When evaluating a future change, ask: which value would it violate?

---

## 1. Produce evidence, not theatre

A "compliance scanner" that emits a 200-page green-tick PDF and passes its own audit is theatre. Loupe's artefacts must be *verifiable by an external auditor who runs them through their own tooling*. This rules out:

- Free-form text reports designed to be read once and filed
- Proprietary output formats nobody else can parse
- "Trust us, we ran the analysis" without auditable inputs and outputs
- Compliance scores or risk ratings detached from underlying evidence

It rules in:

- Industry-standard formats (CycloneDX SBOM, OpenVEX statements)
- Structured artefacts with stable IDs and cross-references
- Run records with hash chains so tampering is detectable
- Git history as the audit trail

**The practical consequence**: when in doubt, choose the format an auditor's tooling already understands.

---

## 2. The write boundary is a Python function, not a prompt instruction

Most "AI safety" enforcement in the wild lives in a system prompt: "do not edit files outside this directory." This is unreliable against prompt injection and against model drift. It also creates an asymmetry between *what the agent is told* and *what the agent can actually do* — and an attacker only needs to find the gap once.

Loupe's Layer 1 enforcement is a `PathBoundary` Python object the tool functions consult before any write. The agent has only two write tools: `write_agent_artifact` (path must be in the allow-list) and `propose_patch` (writes to `.proposed/` for human review). There is no general "write any file" tool. There is no `Bash` tool that could write a file as a side-effect. The boundary is in the code path.

This value extends beyond writes: any agent capability that needs to be constrained must be constrained by tool surface, not by instruction. If a constraint is important enough to enforce, it's important enough to enforce in code.

**The practical consequence**: every time you find yourself writing "the agent must not …" in a prompt, ask whether the corresponding tool surface makes the violation impossible.

---

## 3. Defence in depth — no single layer is load-bearing

The write-boundary problem is solved by *four* layers, not one:

1. **Tool surface** (in-process) — the strongest, see Value 2
2. **Branch namespace** (CI runtime) — the GitHub App's token can only push to `loupe/proposal-*` branches; CODEOWNERS gates protected paths regardless of branch
3. **`loupe verify`** (pre-commit hook + required CI check) — authorship checks, run-record hash chain, schema consistency
4. **Interactive UX gate** — every protected-path proposal renders as a diff with default-No prompt; no `--yes` flag

If any one layer has a bug, the others catch the failure. The cost is ~1–2 weeks of extra implementation. The benefit is that the audit story holds even when something goes wrong — which is the only kind of audit story that matters.

**The practical consequence**: when adding a new constraint, ask which layer enforces it. If only one does, ask whether a second is cheap enough to add.

---

## 4. Cost discipline is a first-class design property

A multi-lens agent running on every PR can easily spend money 3–5× faster than it needs to. Three levers, baked into the architecture rather than retrofitted:

- **Stable-prefix prompt assembly.** The portion of the prompt that's the same across lens calls (system framing, context.md, diff summary, SBOM delta) is paid full price once and then ~10% per subsequent call (prompt-cache hit). The portion that varies per lens (its task, prior findings handover) is paid full price every time. This is enforced by the `PromptParts` model's structure, not by individual lens authors getting it right.
- **Shared blackboard, no recompute.** `RunContext.bootstrap()` parses the diff, generates the SBOM, computes the CVE list, loads the knowledge graph — once. Every lens reads from `RunContext` rather than re-deriving. The agent has no tool that *could* re-derive any of these inputs.
- **Coordinated dispatch.** The coordinator asks each lens `is_relevant(ctx)` (a cheap pure-Python heuristic, no LLM call). Lenses that return below-threshold relevance are skipped entirely. A docs-only PR runs no LLM calls; a single-dependency change runs one lens, not all.

The illustrative result: ~$0.001 for a docs-only PR; ~$0.07 for a dependency change; ~$0.11 for a new endpoint; ~$0.21 for a three-lens analysis. Naive baselines (no cache, no skip) are 3–5× higher.

**The practical consequence**: features that involve LLM calls must be evaluated against the three levers. A feature that breaks prompt-cache leverage (e.g., variable content in the stable prefix) is a regression even if it works correctly.

---

## 5. Humans stay in the decision seat

The agent drafts. Humans decide. Specifically:

- **Risk acceptances** (`decisions/*.md` with `type: risk_acceptance`) are authored by humans, signed by a human identity, and can only be *drafted* (not committed) by the agent.
- **Project context** (`context.md`) is authored by humans. The agent may propose patches via `propose_patch`, but cannot edit it directly.
- **VEX `not_affected` statements** require human approval. The agent can record `affected` and `fixed` directly (mechanical CVE matches), but `not_affected` is an analytical judgment and must go through `propose_patch` for review.
- **Configuration** (`config.yaml`) is human-managed. The agent reads it.

In CI, "human approval" means PR review with CODEOWNERS. In interactive mode, it means a `[y/N/edit/skip]` prompt with default-N. There is no `--auto-confirm` flag and no environment variable that lowers the bar.

**The practical consequence**: every feature that involves the agent making an irreversible decision must have an explicit "and a human approves" step in its design.

---

## 6. Standard formats over proprietary ones

When an industry standard exists for what we're producing, we use it:

- **CycloneDX 1.6** for SBOMs (not our own JSON)
- **OpenVEX 0.2** for vulnerability impact statements (not our own)
- **STRIDE** for threat categorisation (not our own)
- **Pydantic / JSON Schema** for tool I/O (so MCP clients get full type info for free)
- **Markdown + YAML frontmatter** for human-readable artefacts (so any editor can edit them)
- **JSON-RPC over stdio or HTTP** for MCP (it's the spec)

The cost of a proprietary format compounds forever: every downstream consumer (auditor, customer, partner) has to learn it. The cost of a standard format is one-time: write a converter once if needed. Always pay the one-time cost.

**The practical consequence**: when designing a new artefact, the default is "find the existing standard."

---

## 7. Multi-LLM by default, never single-vendor lock-in

The agent must be able to run on Claude, OpenAI, Google, local Ollama, or any provider PydanticAI supports — switched via environment variable. This is a hard requirement, not a nice-to-have. The reasoning is layered:

- **Regulated customers often have approved-LLM lists.** A tool locked to one vendor loses these customers.
- **Cross-checking outputs against a second model** is a legitimate audit request that single-vendor tools can't satisfy.
- **Cost optimisation** (cheap model for grunt work, smart model for hard reasoning) is impossible without multi-provider.
- **Vendor risk** (a provider going down, raising prices, pivoting their API) is real and we don't want to be exposed.

This shaped the framework choice: PydanticAI over Claude Agent SDK, even though the latter has nicer agentic primitives (plan mode, hooks, subagents) — because the Claude Agent SDK is Claude-only.

**The practical consequence**: a feature that only works on one provider is a v1.x feature, not a v1.0 feature. If it's important, find the cross-provider equivalent.

---

## 8. Plugin contracts grow with the second instance, not the first

The rule of three says: design an abstraction when you have three instances. We have one (ThreatLens) and a credible expectation of more (SafetyLens, PrivacyLens). That's enough justification to start with a *minimal* plugin seam (one base class, one entry point group, six required methods), but not enough to design the "complete" plugin contract for hypothetical needs.

We will redesign the contract when SafetyLens lands. The cost of that redesign is bounded (it's one big PR, not a re-architecture). The cost of designing the contract upfront for imagined needs is invariably wrong, expensive, and locked in.

**The practical consequence**: when tempted to add a feature to the plugin API for a hypothetical future lens, write it down as a deferred concern and revisit when the lens actually arrives.

---

## 9. Test discipline: VCR or no LLM, never live calls in CI

LLM tests are non-deterministic, slow, and expensive. Live LLM calls in test suites are an anti-pattern that bites every project that adopts them. Loupe's rule:

- **Unit tests** (Pydantic models, path boundary, prompt builder, diff parsing) never call an LLM. They are pure-Python and fast.
- **Integration tests** with an agent use **VCR.py** to record HTTP fixtures once (with an API key) and replay forever (without one). Cassettes are committed to the repo.
- **End-to-end CI** (the runner workflow itself) is driven by the same VCR cassettes.

The exception, for completeness: a developer iterating on a prompt re-records the cassette explicitly with `--record-mode=once`. The new cassette is then reviewed in the PR.

**The practical consequence**: `uv run pytest` works in zero seconds, with no API keys, on every CI run.

---

## 11. No tool lock-in — pluggable capabilities

The same logic that rules out LLM-vendor lock-in (§7) rules out tool-vendor lock-in. Loupe's analysis pipeline calls out to non-LLM tools — SBOM generators (Syft, Trivy, cdxgen, GitHub API), CVE scanners (Grype, osv-scanner, Trivy), secret detectors (TruffleHog, gitleaks, detect-secrets), static analysers (Semgrep, CodeQL, Bandit), and others. Each of these is a category, not a single tool.

The v1 spec accidentally re-introduced lock-in here: `loupe_core/sbom.py` calls `syft` directly. The capability abstraction (D-18) corrects this by making each tool category a typed Protocol with multiple registerable backends:

- A lens declares `requires_capabilities=["sbom", "cve", "secret_detect"]` — it doesn't know or care which tool fulfils each.
- The capability registry resolves to a configured backend (`syft`, or `trivy`, or `github-api`, etc.).
- Composition modes (`single` / `fallback` / `union` / `consensus` / `pipeline`) let operators run multiple backends for the same capability — e.g., "merge findings from TruffleHog and gitleaks" because either alone has gaps.

**The practical consequence**: when a new tool category appears (SAST that beats Semgrep; SBOM signing via Sigstore; PII-detection libraries), we add it as a new Capability Protocol and a backend package — no fork, no rewrite. And the auditor can read the project's `config.yaml`, see `secret_detect: mode: union, backends: [trufflehog, gitleaks]`, and immediately understand the team's posture.

See [`CAPABILITIES.md`](CAPABILITIES.md) for the full design.

---

## 10. Naming reflects activity, not regulation

The platform is "Loupe" (an inspection instrument), not "ComplianceMate."
Lenses are named after the *activity* they perform (threat modelling, safety analysis, privacy review), not the *regulation* they happen to feed (CRA, ISO 26262, GDPR).

This is partly marketing — "fake-compliance" branding repels both engineers and auditors — but mostly engineering. Naming after the regulation lock the code's identity to a specific regulation's lifecycle. Regulations change. CRA will get amended. ISO 26262 has gone through five revisions. Activities change much more slowly.

**The practical consequence**: when naming a new component, ask whether the name will still make sense after the current regulatory landscape has shifted.
