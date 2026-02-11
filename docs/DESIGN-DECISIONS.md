# Loupe — Design Decisions Log

> A chronological record of the major decisions made during the design of Loupe v1, with what was considered, what was chosen, and why. Decisions are numbered roughly in the order they were made. Each one has a permanent identifier (`D-NN`) so future code and docs can reference them.

The conversation that produced these decisions happened on 2026-05-13. The full design spec is at [``](specs/2026-05-13-loupe-design.md). The principles that emerged are at [`VALUES.md`](VALUES.md).

---

## D-01 — Scope: diff-aware threat modelling + CRA evidence (not "broad compliance agent")

**Considered:**
- TARA (automotive cybersecurity, ISO/SAE 21434) — strong diff-fit, but automotive-only audience
- HARA (functional safety, ISO 26262) — lives at system level, weak diff-fit
- CRA-driven SBOM + vulnerability evidence — diff-friendly, broad audience, real deadline
- Threat modelling (STRIDE/LINDDUN, standard-agnostic) — reusable but no regulatory anchor
- A "compliance agent" covering all of the above

**Chosen:** A merge of "STRIDE threat modelling" and "CRA Annex I evidence." STRIDE is the method; CRA is the shape of the outputs. The agent identifies threats and mitigations on each diff; its outputs (`threats.yaml`, `mitigations.yaml`, `threat-model.md`, `sbom.cdx.json`, `vex.json`) are structured to feed CRA Annex I conformity documentation.

**Why:**
- STRIDE is broadly applicable (any product, not just automotive), giving the platform wide reach.
- CRA gives the outputs a regulatory anchor, making them "real evidence" rather than just analysis.
- The two overlap heavily: CRA mandates risk assessment + secure-by-design rationale + SBOM + VEX, and STRIDE plus standard SBOM/VEX tooling produces exactly these.
- "Broad compliance agent" was rejected as too unfocused for v1 — the platform design (D-04) lets us add other domains later as separate lenses.

---

## D-02 — Both CI and interactive modes are first-class peers

**Considered:**
- CI-first with an interactive CLI bolted on
- Interactive-first with a CI mode bolted on
- Both equally first-class from day one

**Chosen:** Both equally first-class, sharing one core engine with thin frontends.

**Why:**
- The user explicitly wanted both modes to be first-class, not derivative.
- This forced a clean separation between "core agent engine" and "frontend (CLI / CI runner)" — which turned out to be the right architecture anyway.
- The MCP server became the natural "third frontend" (D-09) once this pattern was established.
- The practical cost was minor: ~1 extra week to design the seam, vs. weeks to retrofit it later.

---

## D-03 — Tech stack: Python 3.13 + PydanticAI + multi-LLM via env-var

**Considered:**
- TypeScript + Vercel AI SDK + Vercel AI Gateway — best multi-LLM dev experience, but TS lockout from Python-heavy security tooling
- Claude Agent SDK (TS or Python) — most agentic features, but Claude-only
- OpenAI Agents SDK + LiteLLM — multi-LLM via translation layer
- LangGraph — most flexible, heaviest abstraction
- Roll your own with raw provider SDKs
- **PydanticAI**

**Chosen:** Python 3.13 + PydanticAI as the agent framework; multi-LLM via env-var (`THREATLENS_MODEL=anthropic:claude-opus-4-7` or `openai:gpt-5` etc.); the Vercel AI Gateway as an optional LLM router (callable from Python because it exposes an OpenAI-compatible HTTPS endpoint).

**Why:**
- The user pushed back on the Vercel AI SDK ("don't feel it's state of the art") — and they're right that for Python projects, it's not in the running.
- Python is the lingua franca of security/safety engineering and the SBOM/CVE ecosystem (cyclonedx-python-lib, openvex parsers).
- PydanticAI's typed `deps` mechanism is exactly the shape we need for the shared `RunContext` blackboard pattern (D-07).
- Pydantic models double as artefact schemas + tool I/O + MCP schemas — three jobs from one definition. No other framework gives this synergy.
- Multi-LLM is a hard requirement (see [VALUES.md §7](VALUES.md#7-multi-llm-by-default-never-single-vendor-lock-in)). PydanticAI supports Anthropic, OpenAI, Google, Mistral, Groq, Cohere, Ollama, Bedrock natively.
- Claude Agent SDK was the strongest alternative but is Claude-only. Its features (plan mode, hooks, subagents) would have to be rebuilt for multi-LLM, eliminating most of the benefit.

---

## D-04 — Plugin architecture from v1 with minimal API ("Option 4")

**Considered:**
- Monolithic package — one `threatlens` with subcommands, simplest, but couples concerns
- Core library + thin shells ("Option 2") — clean for one product but no plugin seam
- Microagents (specialist sub-agents from day one) — flexible, overkill for v1
- **Plugin architecture with minimal API ("Option 4")**
- Plugin architecture with fully designed API from day one

**Chosen:** Plugin architecture with the *minimum* lens API needed to ship one lens. The contract will be refined when the second lens lands.

**Why:**
- The user explicitly mentioned future lenses (safety analysis and others).
- The "rule of three" says: design an abstraction when you have three instances. We have one (ThreatLens) and credible expectation of more. Enough justification for a *minimal* seam.
- Designing the "complete" plugin contract upfront is almost always wrong — you design for hypothetical needs, then redesign when reality bites. Cost: ~1 extra week upfront, saves 1-2 weeks per future plugin.
- This decision shaped the naming choice (D-05): the platform can't be called "ThreatLens" if it hosts multiple lenses.

---

## D-05 — Naming: platform = "Loupe", lenses = `<Domain>Lens`

**Considered:**
- "ThreatLens" as the platform name (rejected once D-04 made plugin architecture central)
- Prism (best metaphor, but PyPI namespace likely taken)
- Aperture (strong metaphor)
- **Loupe** (the inspection instrument)
- Optica, Sightline, Lumen (alternatives)

**Chosen:** Platform is "Loupe." Lenses follow the `<Domain>Lens` suffix pattern: `ThreatLens`, `SafetyLens`, `PrivacyLens`, `AIRiskLens`.

**Why:**
- The user pointed out that calling the core "ThreatLens" was conceptually wrong once we had a plugin architecture — the core is domain-agnostic, the *lens* is the domain-specific part.
- The "loupe" metaphor connotes precision inspection — auditor-credible work — which matches the values [§1 evidence not theatre](VALUES.md#1-produce-evidence-not-theatre).
- Loupe is distinctive (less collision risk on PyPI), pronounceable, and short enough to be a CLI name (`loupe ci`, `loupe chat`, `loupe mcp`).
- The `<Domain>Lens` suffix is consistent and self-documenting: when a user sees "PrivacyLens" they immediately understand "this is a lens for privacy."
- Naming reflects activity, not regulation (see [VALUES.md §10](VALUES.md#10-naming-reflects-activity-not-regulation)).

---

## D-06 — Nine artifact files in `.loupe/`, two-file pattern (markdown + YAML)

**Considered:**
- Minimal evidence pack (5 file types)
- Full CRA technical-documentation skeleton
- Diagrams-first (Mermaid + threat model)
- **Defer-to-co-design** (the user opted for this)

**Chosen:** Nine artifact files in `.loupe/`, designed together:

| File | Purpose | Writer |
|---|---|---|
| `context.md` | Human-authored project brief (anti-hallucination anchor) | Human (agent proposes patches) |
| `threat-model.md` | Narrative threat model for auditors | Agent (ThreatLens) |
| `threats.yaml` | Machine-readable threat index | Agent (ThreatLens) |
| `mitigations.yaml` | Machine-readable mitigation index | Agent (ThreatLens) |
| `sbom.cdx.json` | CycloneDX SBOM | Tool (Syft) |
| `vex.json` | OpenVEX statements | Agent + human approval |
| `decisions/*.md` | ADR-style human risk acceptances | Human (agent drafts) |
| `runs/*.json` | Audit trail of every agent run, with hash chain | Agent (core) |
| `config.yaml` | Project config | Human |

**Why:**
- For each "living" concept (threats, mitigations), keep human-readable markdown alongside a machine-readable YAML/JSON index. The markdown is for engineers and auditors; the index is for the agent and CI gates. The agent's job is to keep them in sync. This is the two-file pattern.
- Every artefact gets a stable ID scheme (`T-001`, `M-007`, `D-2026-05-13-x`). Without IDs, nothing can be cross-referenced and the threat model becomes prose, not evidence.
- The `context.md` is the most under-rated file: most AI threat-modelling demos fail because the LLM doesn't know what the product actually does. A short human-authored brief anchors every run.
- `sbom.cdx.json` is generated by Syft, *not* LLM-written. LLMs are bad at SBOMs; established tools are good at them.
- The `runs/*.json` hash chain (D-08) makes tampering with history detectable.
- Standards-conformance (CycloneDX, OpenVEX, STRIDE) is non-negotiable — see [VALUES.md §6](VALUES.md#6-standard-formats-over-proprietary-ones).

---

## D-07 — Shared state: within-run `RunContext` blackboard + persistent knowledge graph

This decision evolved through the conversation. Initially I misread the user's "save context" requirement as **session-resumption-over-time** (save chat sessions, resume tomorrow). The user clarified twice:

1. First clarification: not session-resumption, but "cross-agent shared knowledge" — different lenses coordinating without re-sending each other's context.
2. Second clarification: not just coordination, but **cost-saving** — within one invocation, share the parsed diff, SBOM, project context across all lenses so we don't pay LLM tokens for re-derivation.

**Chosen:** Two layers of shared state:

- **Within-run `RunContext` blackboard** — in-memory, passed via PydanticAI's `deps` parameter to every lens agent. Holds the parsed diff, SBOM delta, context, plan, and a namespaced findings dict + facts list that lenses read from and write to.
- **Persistent knowledge graph** (`.loupe/knowledge.yaml`) — survives across runs. Holds stable assets, architectural elements, decisions, cross-references between lenses. Promoted from in-memory `Fact`s only when `confidence: high` AND corroborated by ≥1 human decision OR ≥2 runs.

**Why:**
- Cost is dominated by tokens × number of LLM calls. The blackboard eliminates redundant CPU work (parsing the diff once, generating SBOM once) AND eliminates redundant LLM work (one lens doesn't need to re-derive what another already found).
- PydanticAI's `deps` mechanism is built for exactly this — typed dependency injection into tool functions. We get it nearly for free.
- The **two-level model** (lens-private `findings` + cross-cutting `facts`) prevents both over-sharing (clobbering) and under-sharing (re-deriving). One namespace per lens for working notes; one shared `Fact` list for assertions all lenses should see.
- The **promotion rule** (high-confidence + corroboration) prevents the knowledge graph from filling with low-confidence noise that future runs would have to filter through (token cost) or that would mislead future analyses.

---

## D-08 — Write boundary enforced in four layers

**Considered:**
- Layer 1 only (tool surface)
- Layers 1 + 4 only (tool surface + interactive UX)
- Layers 1 + 2 + 4 (skip hash chain)
- **All four layers**

**Chosen:** All four layers, no single one load-bearing:

1. **Tool surface** (in-process) — agent's only write tools are `write_agent_artifact` (path must match allow-list) and `propose_patch` (writes to `.proposed/`). The `PathBoundary` is a Python object, not a prompt instruction.
2. **Branch namespace** (CI runtime) — GitHub App token can only push to `loupe/proposal-*` branches; CODEOWNERS gates `.loupe/context.md`, `.loupe/decisions/**`, `.loupe/config.yaml` regardless of branch.
3. **`loupe verify`** (pre-commit hook + required CI check) — authorship check, run-record hash chain, schema consistency check.
4. **Interactive UX gate** — every protected-path proposal renders as diff with `[y/N/edit/skip]` prompt, default-N, no `--auto-confirm` flag.

**Why:**
- The user explicitly requested "enforce by tooling, not policy" — see [VALUES.md §2](VALUES.md#2-the-write-boundary-is-a-python-function-not-a-prompt-instruction).
- The audit story has to hold even when one layer has a bug. Defense in depth is what makes the artefacts "evidence-grade" — auditors trust deterministic checks they can run themselves, not policy assertions.
- This adds ~1-2 weeks of v1 work. The cost-benefit was clear: skipping it would make the CRA framing un-defensible.

---

## D-09 — MCP server is a peer frontend with both granular tools and high-level workflows

**Considered:**
- Granular tools only (each agent operation as a separate MCP tool)
- Workflows only (high-level operations like "analyse this diff")
- **Both, in separate namespaces** (`loupe.tools.*` + `loupe.workflows.*`)

**Chosen:** Both. Granular tools (`loupe.tools.threatlens.propose_threat`, etc.) for clients that want to compose their own workflows. High-level workflows (`loupe.workflows.run_for_diff`, etc.) for clients that just want to invoke the whole thing.

**Why:**
- The user explicitly requested MCP exposure as a hard requirement.
- The "both namespaces" approach future-proofs both audiences: power users (Claude Code, custom agents) can compose; casual users can invoke whole workflows.
- The MCP server is the third frontend alongside the CLI and CI runner. All three use the same `loupe-core` engine. This was the structural payoff of D-02 (both modes first-class) and D-04 (plugin architecture).
- All Layer 1-4 enforcement applies identically over MCP. An external MCP client cannot exceed the local agent's authority.

---

## D-10 — Three cost-saving levers as first-class architectural concerns

After D-07 reframed "save context" as cost-saving, three levers were formalised as required architectural properties:

1. **Stable-prefix prompt assembly** — every lens call structures its prompt as (stable prefix) + (variable suffix). The prefix is cache-pinned via Anthropic prompt-cache `cache_control` markers. Three sequential lens calls in one run pay full price once, ~10% for the next two.
2. **Shared blackboard (no recompute)** — `RunContext.bootstrap()` parses diff, generates SBOM, computes CVE list, loads knowledge graph once. Agent has no tool that *could* re-derive these.
3. **Coordinated dispatch (skip irrelevant lenses)** — coordinator calls `lens.is_relevant(ctx)` (pure-Python heuristic, no LLM). Below-threshold lenses are skipped. A docs-only PR triggers zero LLM calls.

**Why:**
- Cost discipline was elevated from "nice to have" to "first-class design property" after the user's clarification. See [VALUES.md §4](VALUES.md#4-cost-discipline-is-a-first-class-design-property).
- Illustrative savings: 3–5× vs. naive baselines. On 1k PRs/month, ~$200–$500 saved per month — not negligible.
- Each lever is implemented in a specific core component (`PromptParts`, `RunContext`, `Coordinator.build_run_plan`), not as a pattern that individual lens authors have to remember.

---

## D-11 — Lens contract is six methods, minimal v1 API

**Chosen:** Every lens implements:

```python
class Lens(Protocol):
    capabilities: LensCapabilities          # name, domain, intent keywords, artifact paths
    def build_agent(self, deps_type) -> Agent: ...
    def mcp_tools(self) -> list[McpTool]: ...
    def mcp_workflows(self) -> list[McpWorkflow]: ...
    def is_relevant(self, run_ctx) -> RelevanceScore: ...
    async def run(self, ctx, plan_entry, boundary, loupe_dir) -> None: ...
```

Six methods, one declared attribute. Anything else is implementation detail.

**Why:**
- See D-04 — we don't know what the second lens will need. Designing too much upfront is more expensive than redesigning when SafetyLens lands.
- `is_relevant` MUST be a pure-Python heuristic (no LLM call) — this is what makes lever 3 (coordinated dispatch) cheap.
- `capabilities.artifact_paths` is the lens's declaration of which paths in `.loupe/` it owns. Loupe-core checks for conflicts at registration time (two lenses can't both claim `.loupe/threats.yaml`).

---

## D-12 — Run records form a tamper-evident hash chain

**Chosen:** Each `runs/*.json` contains a `self_hash` (SHA-256 of its own content, excluding the `self_hash` field itself) and a `prev_run_hash` (the previous record's `self_hash`). `loupe verify` walks the chain.

**Why:**
- Auditors need to be able to detect history rewriting. Without the chain, a malicious actor could insert a fake "we considered this CVE and decided not_affected" run record.
- The chain is implemented in `loupe_core/artifacts/run_record.py` via deterministic JSON canonicalisation (sorted keys, no whitespace).
- This is part of Layer 3 enforcement. Combined with Layer 2 (CODEOWNERS + branch protection) it's hard to bypass undetectably.

---

## D-13 — VCR-based testing, no live LLM calls in CI

**Chosen:** Integration tests with an agent use `pytest-vcr`. Cassettes are recorded once (with an API key) by a developer and committed. CI replays them without any API key.

**Why:**
- LLM tests are non-deterministic, slow, and expensive if they hit a real API.
- VCR makes them deterministic, fast, and free.
- This is the only way to keep `uv run pytest` working in zero seconds for every contributor.
- See [VALUES.md §9](VALUES.md#9-test-discipline-vcr-or-no-llm-never-live-calls-in-ci).

---

## D-15 — Full-repo / no-diff scans are first-class via `loupe scan`

**Considered:**
- Diff-only mode (current implicit assumption — would skip ThreatLens on any no-diff run because `is_relevant()` looks at `ctx.diff.changed_paths`)
- Treat absence-of-diff as "everything is in scope" implicitly inside `is_relevant()`
- Two parallel pipelines (diff-pipeline and full-repo-pipeline)
- **One pipeline with a `scope` field on `RunContext`, plus an explicit `loupe scan` CLI command**

**Chosen:** Add `RunContext.scope: Literal["diff", "full", "scoped"]` (default `"diff"`); when `scope != "diff"`, `Lens.is_relevant()` returns high relevance unconditionally (the lens is being *explicitly* invoked); the agent's system prompt gains a scope-aware section; a new `loupe scan [--paths …]` command bootstraps a `RunContext` with `scope=full` or `scoped`. Same dispatcher, same artefacts, same enforcement.

**Why:**
- The diff-only assumption silently broke five real scenarios: first-time onboarding, periodic re-baseline, architectural review, audit kickoff, and `loupe chat` questions not tied to a recent change. For many adopters, the *first* time they ever run Loupe will be a no-diff run.
- Both modes produce the same artefact types (`threats.yaml`, `mitigations.yaml`, `threat-model.md`, `vex.json`, etc.). The difference is in *scope of analysis*, not output shape — which means it's expressible as a field, not a parallel pipeline.
- Treating no-diff implicitly inside `is_relevant()` would have been clever-but-wrong: the user invoking `loupe scan` is making an explicit choice to pay the higher cost; the system should honour that rather than silently filter.
- An explicit `loupe scan` command is honest about cost: full-repo runs can easily blow `per_run_max_usd`. We'll require an explicit `--budget-usd <N>` flag when the configured limit is exceeded, rather than failing partway through.

**Implementation impact:**
- `loupe-core/run_context.py` gains a `scope` field on `RunContext` and a `scope_paths` field on `BootstrapInputs`.
- `loupe-core/coordinator.py`'s `build_run_plan()` short-circuits the relevance check when `scope != "diff"` (still calls `is_relevant()` for the reason string, but always includes the lens).
- `loupe-cli` gains a `scan` command in Phase 7.
- `loupe-threatlens/agent.py` system prompt branches on scope.
- ThreatLens's `is_relevant()` should still return a useful reason in full mode (e.g., "explicit full-repo scan"), but its `score` is overridden by the coordinator.

**Deferred to v1.x:**
- `--baseline` workflow (marking a known-good threat model, then comparing future diffs against it).
- `--since <revision>` for arbitrary git revision diffs.
- Sampling for very large repos (don't send 200k LOC; pick relevant slices).
- Scheduled re-baseline (cron-style).

These are real concerns but each adds a meaningful concept (baselines, time-windowed scope, sampling heuristics). v1 keeps the design minimal: diff mode, full mode, scoped-to-paths mode.

---

## D-16 — Relationship with StrideGPT: learn + attribute, don't fork

**Considered:**
- Fork StrideGPT and add Loupe's architecture on top of it
- Integrate StrideGPT at runtime (call it as a subprocess from ThreatLens)
- Ignore StrideGPT entirely and build clean
- **Learn from + attribute, build independently**

**Chosen:** Learn from StrideGPT's prompts and STRIDE technique; attribute the influence in Phase 6's `prompts/system.md` and in [`COMPARISON.md`](COMPARISON.md); don't fork or integrate; build the platform independently. Use StrideGPT as a quality benchmark for ThreatLens output.

**Why:**
- StrideGPT's architecture is fundamentally different from Loupe's: it is a one-shot Streamlit web UI, ~500 lines, with no in-repo persistence, no plugin seam, no write-boundary enforcement, no MCP, no continuous-CI operation. Forking would force us to either gut 80% of it (most of which is the Streamlit UI we don't want) or contort our platform shape to fit theirs.
- StrideGPT's *prompts and STRIDE category framing*, on the other hand, are battle-tested across many users and refined over multiple iterations. That's the high-value reusable piece. They live in `threat_model.py`, `attack_tree.py`, `mitigations.py`, `dread.py`, `test_cases.py` (no central `prompts.py`).
- StrideGPT's licence is **MIT** (verified by web fetch on 2026-05-14). Adaptation with attribution is licence-clean.
- StrideGPT is actively maintained (173 commits, supports recent models like Claude 4.5, GPT-5, Gemini 3) so it remains a trustworthy reference point.
- Runtime integration would require running their Streamlit app headless or adapting the modules — significant adapter work for less benefit than re-implementing the parts we want.

**Practical actions:**
1. When writing Phase 6's `packages/loupe-threatlens/loupe_threatlens/prompts/system.md`, study `mrwadams/stride-gpt/threat_model.py` for prompt structure and STRIDE category questions; adapt useful framing with a comment crediting StrideGPT.
2. Add an explicit attribution line in [`COMPARISON.md`](COMPARISON.md) (already mentions StrideGPT as prior art).
3. After Phase 6 ships, benchmark ThreatLens output against StrideGPT on 3–5 reference scenarios. If ThreatLens is materially worse, iterate on prompts.
4. Note in our prompt that this is *inspired by* StrideGPT's approach.

**Things StrideGPT offers that we deliberately defer:**
- Attack tree generation
- DREAD risk scoring
- Gherkin test case generation

These are interesting v1.x features. ThreatLens v1 stays focused on STRIDE threats + mitigations + VEX.

---

## D-18 — Capability abstraction (tool-agnostic functional building blocks)

**Considered:**
- Hardcode each tool (current state: `loupe_core/sbom.py` calls Syft directly; future SBOM/CVE/secret tools would each become a hardcoded module)
- Pluggable per-tool (e.g., introduce only an `SbomBackend` abstraction; keep CVE / secrets / static-analysis hardcoded)
- **Generalised capability abstraction** — every non-LLM tool category becomes a typed Protocol with multiple backends discoverable via entry points

**Chosen:** Generalised capability abstraction. A **Capability** is a typed Python `Protocol` describing one functional operation (`SbomCapability`, `CveCapability`, `SecretDetectionCapability`, `StaticAnalysisCapability`, `LicenseScanCapability`, `VulnDbCapability`). **Backends** are concrete implementations that register via entry points (`loupe.capabilities.sbom`, `loupe.capabilities.cve`, etc.). **Composition modes** (`single`, `fallback`, `union`, `consensus`, `pipeline`) let the operator configure how multiple backends interact. Lenses declare `requires_capabilities` and access them via `ctx.capabilities.*`.

Full design at [`CAPABILITIES.md`](CAPABILITIES.md).

**Why:**
- **Parity with the LLM-provider value.** [VALUES.md §7](VALUES.md#7-multi-llm-by-default-never-single-vendor-lock-in) commits us to no LLM-vendor lock-in via PydanticAI. The original v1 spec accidentally re-introduced lock-in at the tool layer (Syft hardcoded in `sbom.py`). Capabilities extend the same pattern down a layer.
- **Cross-lens reuse.** ThreatLens needs SBOM, CVE matching, secret detection. SafetyLens (future) will need static analysis, dependency-graph analysis. PrivacyLens will need PII detection, data-flow analysis. Without capabilities, each lens re-implements its own tool wrappers. With capabilities, a `SecretDetectionCapability` is shared infrastructure.
- **Composition is audit-relevant.** "Run TruffleHog AND gitleaks and merge" (`union`) catches what either alone misses. "Require 2-of-3 static analysers to corroborate" (`consensus`) reduces false-positive noise. These are real audit patterns the current code can't express.
- **Tool availability varies.** A CI runner may have Trivy but not Syft, or vice versa. The agent's logic shouldn't care which is installed; that's the registry's job.
- **The naming insight from D-04/D-05 applies again.** Capabilities are verbs ("do SBOM generation"); lenses are nouns ("ThreatLens does security"). Conflating them in a single class hierarchy would have produced the same domain-locking problem we hit when we briefly named the platform "ThreatLens."

**Why not just an SBOM-only abstraction:**
- The same problem recurs in CVE matching (Grype vs osv-scanner vs Trivy), secret detection (gitleaks vs TruffleHog vs detect-secrets), static analysis (Semgrep vs CodeQL vs Bandit), license scanning (ScanCode vs FOSSA), and vuln-DB lookup (NVD vs OSV vs GHSA). Solving it five times in five ad-hoc ways is worse than solving it once with a small framework.
- The cost of generalising is real (one extension point to maintain, configuration surface area, versioning concerns) but bounded. The cost of *not* generalising compounds — each new capability category becomes its own design decision.

**Trade-offs accepted:**
- **More framework code.** ~1 week to land the registry + Protocols + RunContext integration. Worth it because every subsequent backend is a pip-install, not a fork.
- **Versioning across capability protocols is a real concern.** Mitigated by versioning each Protocol's input/output models with Pydantic schema versions; we'll evolve them carefully when a real second backend lands and tests their compatibility.
- **The `loupe-core` install grows the surface area but not the dependency count.** Core ships zero backends. Users install `loupe-capabilities-essential` (Syft + Grype + gitleaks) or `-full` (more backends) or pick individual `loupe-cap-*` packages.

**Implementation:** Deferred to v1.x. Sequencing in [`CAPABILITIES.md`](CAPABILITIES.md#implementation-roadmap). Recording the decision now so:
1. Contributors can write capability backends today against the documented Protocols
2. Phase 6 (ThreatLens real agent) doesn't paint itself into a corner with new hardcoded tools
3. The competitive distinctness vs StrideGPT/Devici/IriusRisk has another structural argument behind it

**Migration path for existing code:**
- Phase 6 (Task 6.3) lands ThreatLens with hardcoded Syft (the current state) — keeps Phase 6 scope tight
- Phase v1.x-A migrates `loupe_core/sbom.py` to `SbomCapability` with `SyftBackend` as the bundled default
- One minor version of deprecation warning on the old function signature; then removed

---

## D-17 — Licence: Apache 2.0

**Considered:**
- MIT — permissive, shortest licence text, but no explicit patent grant or trademark protection
- Apache 2.0 — permissive + explicit patent grant + patent retaliation + trademark non-grant
- GPL v3 — copyleft (viral)
- AGPL v3 — copyleft + network-use clause
- BSL (Business Source Licence) — eventual-open, time-limited commercial restriction
- MPL 2.0 — file-level copyleft
- Proprietary / "all rights reserved"

**Chosen:** **Apache 2.0**. See [`LICENSE`](../LICENSE) at the repo root.

**Why:**
- **Patent protection.** A security-analysis tool may involve specific analysis methods that could be patentable. Apache 2.0 §3 explicitly grants patent rights from contributors to users, with a retaliation clause that revokes the grant if a licensee sues over patents in the code. MIT is silent on patents — legal theory says they may be implicitly licensed but US case law is inconsistent. For an enterprise-security audience the explicit grant is the right call.
- **Trademark protection.** Apache 2.0 §6 explicitly states the licence does NOT grant trademark rights. Stops "trademark squatting via fork" — someone can fork the code but can't legally market their fork as "Loupe." MIT is silent.
- **Contributor IP clarity.** Apache 2.0 §5 spells out that any intentional submission is licensed under the project terms unless explicitly stated otherwise. Removes ambiguity that MIT leaves open.
- **Enterprise procurement default.** Apache 2.0 is the boring-correct choice for an enterprise-adopted security tool. The CRA audience (regulated industries) has procurement processes that often specifically prefer or require Apache 2.0 over MIT.
- **Neighbour-licence alignment.** Loupe's adjacent OSS security tools — Syft, Grype, Trivy, OpenSSL (since 3.0) — are all Apache 2.0. Same-licence neighbours reduce procurement friction when teams compose multiple tools.
- **MPL 2.0** was a serious contender for file-level copyleft, but Loupe is a complete tool (not an embedded library), so file-level copyleft adds friction without clear benefit. Saved for cases where the share-back requirement materially matters.
- **AGPL** would catch SaaS competitors but creates real adoption friction; the dual-licence model (AGPL + commercial) requires CLA infrastructure that's premature for the project's stage.
- **Proprietary** would contradict the value proposition (transparency for security audits).

The trade-off accepted: **no commercial support contract.** Users self-support, file issues, contribute fixes. Acceptable for a project whose deployment is local-first and whose maintenance burden is bounded.

**Copyright holder:** Fadi Labib (`github@fadilabib.com`), as the originating author. Future contributors retain copyright on their contributions per usual Apache 2.0 custom; no CLA required at this stage.

---

## D-14 — Defer commit signing and off-repo retention to v1.x

**Considered as v1.0 features, deferred:**
- Commit signing (Sigstore, GPG) — could come if a customer demands cryptographic provenance
- Off-repo retention store — could come if legal retention requirements need a separate substrate
- C2PA-style cryptographic provenance for AI outputs — speculative

**Why:**
- Git's SHA history plus the run-record hash chain (D-12) is sufficient evidence for v1.
- These features add real implementation cost and operational complexity. We add them when a real customer asks for them.
- See the spec's risk section: "Off-repo append-only log can be added as a v1.x feature without core changes."

---

## Decisions about the implementation plan execution

These are about *how* we build v1, not *what* it is.

### D-E1 — Implementation plan organised into 11 phases

**Chosen:** One plan document with 11 phases, ~50 TDD-shaped tasks, each phase producing working/testable software at its boundary. Not split into separate plans because the layers are interdependent (you can't ship `loupe-threatlens` without `loupe-core`).

### D-E2 — TDD per task: failing test → implementation → commit

**Chosen:** Every task starts with a failing test, implements the minimum to make it pass, then commits. No "batch implementation then add tests later."

**Why:** Forces verification at every step. Failing tests document expected behaviour better than prose. Avoids the "we'll add tests later" debt that never gets paid.

### D-E3 — Personal git identity (`github@fadilabib.com`), no `Co-Authored-By` lines

**Chosen:** All commits use the user's personal email (per their global instructions for personal projects). No "Co-Authored-By: Claude" or similar AI-attribution lines.

**Why:** The user's stated preference for personal projects, recorded in their global CLAUDE.md.

### D-E4 — Phase 0 + 1 trial-run inline, then user decision on continuing

**Chosen:** Execute Phases 0 (workspace + skeletons) and 1 (artifact schemas) inline in-session, then pause for user review before continuing.

**Why:** The plan is large (~50 tasks). Letting the user see how the first few phases feel before committing to the rest is cheaper than discovering misalignment late.

---

## Plan deviations during execution (Phases 0–3)

Small, all justified, none invalidate the spec:

| What | Why |
|---|---|
| Added `packages/loupe-action/pyproject.toml` (plan didn't specify) | uv's `packages/*` workspace glob requires every member to have a pyproject.toml |
| Switched pytest to `--import-mode=importlib` | Default importmode collides on same-named test files across packages (`test_smoke.py` × 3) |
| Removed `tests/__init__.py` files | With importlib mode they're unnecessary and would cause the same collision differently |
| `datetime.utcnow()` → `datetime.now(timezone.utc)` | Python 3.13 deprecation warning, future-proofed |
| `RunContext.bootstrap` as proper `@classmethod` (plan suggested monkey-patch) | The classmethod form is correct Pydantic V2 and cleaner. Plan documentation drift, not correctness issue. |
| `PathBoundary` no longer pre-rejects absolute paths | Necessary for `tmp_path`-using tests. The `..` traversal check and the allow-list match together still reject `/etc/passwd`. |

---

## Open decisions (deferred to specific triggers)

- **PyPI namespace** — needs to be checked before publishing. Fallback names recorded: `loupekit`, `loupe-platform`.
- **First canonical demo project** — web API vs embedded firmware vs Python library — to be picked before Phase 10's end-to-end smoke test.
- **GitLab/Gitea VCS adapter** — out of scope for v1; adapter abstraction designed so it can be added without core changes.
- **Coordinator LLM-fallback policy** — when `is_relevant()` returns 0.4–0.7 for multiple lenses (ambiguous), use a cheap LLM call to decide. Threshold and prompt format to be tuned in Phase 5.
- **Knowledge-graph promotion thresholds** — starting heuristic is "≥1 human decision OR ≥2 runs." Tunable in `config.yaml` once we have real usage data.

---

## How to read this log

Each decision should be readable on its own. When considering a change that touches one of these areas, find the relevant decision, see what was considered and chosen, and ask whether the new change updates an existing decision or creates a new one. If new: add to this log with the next available `D-NN`. If updating: keep the old decision visible but mark it superseded.
