---
tags:
  - reference
  - decision-log
---

# Design decisions

A record of the major decisions made during the design of Loupe v1. Each has a permanent identifier (`D-NN`) referenced from code and other docs. Numbered roughly in the order they were made; reordered into numeric sequence here for navigation.

The principles that emerged from these decisions are at [`principles.md`](../principles.md).

## Index

[D-01](#d-01) Scope · [D-02](#d-02) CI + interactive · [D-03](#d-03) PydanticAI · [D-04](#d-04) Plugin architecture · [D-05](#d-05) Name = Loupe · [D-06](#d-06) Ten artefacts · [D-07](#d-07) Blackboard + knowledge graph · [D-08](#d-08) Four-layer write boundary · [D-09](#d-09) MCP · [D-10](#d-10) Three cost levers · [D-11](#d-11) Lens contract · [D-12](#d-12) Hash chain · [D-13](#d-13) VCR · [D-14](#d-14) Deferred signing · [D-15](#d-15) `loupe scan` · [D-16](#d-16) StrideGPT lineage · [D-17](#d-17) Apache 2.0 · [D-18](#d-18) Capability abstraction · [D-19](#d-19) Benchmark tiers · [D-20](#d-20) MkDocs Material · [Open decisions](#open-decisions)

---

## D-01: scope is diff-aware threat modelling plus CRA evidence { #d-01 }

The candidates were TARA (automotive cybersecurity, automotive-only audience), HARA (functional safety, weak diff-fit), CRA-driven SBOM and vulnerability evidence (broad audience, real deadline), standard-agnostic threat modelling (reusable but no regulatory anchor), and a "broad compliance agent" covering all of the above.

The chosen scope is a merge: STRIDE is the method, CRA Annex I is the shape of the outputs. The agent identifies threats and mitigations on each diff and emits `threats.yaml`, `mitigations.yaml`, `threat-model.md`, `sbom.cdx.json`, and `vex.json`.

STRIDE applies to any product, not just automotive. CRA gives the outputs a regulatory anchor so they read as evidence rather than analysis. The two overlap heavily: CRA wants risk assessment, secure-by-design rationale, SBOM, and VEX, and STRIDE plus standard SBOM/VEX tooling produces exactly those. The broad-compliance framing was rejected as too unfocused for v1; D-04's plugin architecture lets us add other domains later as separate lenses.

---

## D-02: CI and interactive modes are first-class peers { #d-02 }

Three options: CI-first with an interactive CLI bolted on, interactive-first with a CI mode bolted on, or both equal from day one.

Both equal won. The two modes share one core engine with thin frontends. The user wanted both first-class rather than derivative, and that forced a clean separation between core agent engine and frontend, which turned out to be the right architecture anyway. The MCP server (D-09) became the natural third frontend once this pattern was established. Cost: about a week of design overhead, versus weeks of retrofit later.

---

## D-03: Python 3.13 plus PydanticAI, multi-LLM via env var { #d-03 }

The candidates were TypeScript with the Vercel AI SDK (best multi-LLM developer experience but locked out of Python's security/SBOM ecosystem), Claude Agent SDK (most agentic features, Claude-only), OpenAI Agents SDK with LiteLLM (multi-LLM through a translation layer), LangGraph (most flexible, heaviest abstraction), raw provider SDKs, or PydanticAI.

PydanticAI on Python 3.13 won. Multi-LLM lives in an environment variable: `THREATLENS_MODEL=anthropic:claude-opus-4-7` or `openai:gpt-5` or `google-gla:gemini-2.5-pro`. The Vercel AI Gateway remains optional as an OpenAI-compatible HTTPS router.

Python is the lingua franca of security and SBOM tooling (`cyclonedx-python-lib`, `openvex` parsers). PydanticAI's typed `deps` mechanism is the exact shape the shared `RunContext` blackboard needs (D-07). Pydantic models double as artefact schemas, tool I/O, and MCP schemas: three jobs from one definition. Multi-LLM is a hard requirement ([principles.md §3](../principles.md#principle-3)) and PydanticAI ships Anthropic, OpenAI, Google, Mistral, Groq, Cohere, Ollama, and Bedrock natively. Claude Agent SDK was the strongest alternative but is Claude-only; its plan-mode, hooks, and subagent features would have to be rebuilt for multi-LLM, eliminating most of the benefit.

---

## D-04: plugin architecture with a minimal v1 API { #d-04 }

Considered a monolithic single package, a core library with thin shells but no plugin seam, microagents from day one, a plugin architecture with a fully designed API, and a plugin architecture with the minimum API needed to ship one lens.

The minimum-API plugin architecture won. We refine the contract when the second lens lands rather than design for hypothetical needs.

The user mentioned future lenses (safety analysis, others) from the start. The rule of three says design an abstraction at three instances; we have one with credible expectation of more, which justifies a minimal seam but not a complete contract. Designing the full contract upfront is invariably wrong: cost is about a week up front but saves one to two weeks per future plugin. This decision shaped D-05's naming.

---

## D-05: platform is "Loupe", lenses are `<Domain>Lens` { #d-05 }

The candidates were "ThreatLens" as the platform name (rejected once D-04 made plugin architecture central), Prism (best metaphor, PyPI namespace likely taken), Aperture (strong metaphor), Loupe (the inspection instrument), and a handful of alternatives (Optica, Sightline, Lumen).

Loupe is the platform; lenses follow the `<Domain>Lens` pattern: `ThreatLens`, `SafetyLens`, `PrivacyLens`, `AIRiskLens`.

Calling the core "ThreatLens" was wrong once the plugin architecture was central. The loupe metaphor connotes precision inspection, which matches [principles.md §1](../principles.md#principle-1). Loupe is short enough to be a CLI name. The `<Domain>Lens` suffix is self-documenting: a reader who sees "PrivacyLens" knows what it does. Naming reflects activity, not regulation ([principles.md §11](../principles.md#principle-11)).

---

## D-06: ten artefacts in `.loupe/`, markdown plus YAML pattern { #d-06 }

Ten files live in `.loupe/`, paired markdown (human-readable) and YAML/JSON (machine-readable) where the concept is "living":

| File | Purpose | Writer |
|---|---|---|
| `context.md` | Human-authored project brief (anti-hallucination anchor) | Human (agent proposes patches) |
| `knowledge.yaml` | Persistent cross-run knowledge graph (assets, elements, decisions, cross-refs) | Loupe-core (lens-promoted facts) |
| `threat-model.md` | Narrative threat model for auditors | Agent (ThreatLens) |
| `threats.yaml` | Machine-readable threat index | Agent (ThreatLens) |
| `mitigations.yaml` | Machine-readable mitigation index | Agent (ThreatLens) |
| `sbom.cdx.json` | CycloneDX SBOM | Tool (Syft) |
| `vex.json` | OpenVEX statements | Agent plus human approval |
| `decisions/*.md` | ADR-style human risk acceptances | Human (agent drafts) |
| `runs/*.json` | Audit trail of every run, hash-chained | Agent (core) |
| `config.yaml` | Project config | Human |

The markdown is for engineers and auditors; the YAML is for the agent and CI gates; the agent's job is to keep them in sync. Every artefact has a stable ID scheme (`T-001`, `M-007`, `D-2026-05-13-x`); without IDs nothing cross-references and the threat model becomes prose, not evidence. `context.md` is the most under-rated file: most AI threat-modelling demos fail because the LLM does not know what the product actually does. The SBOM is generated by Syft, not LLM-written. Standards conformance (CycloneDX, OpenVEX, STRIDE) is non-negotiable ([principles.md §2](../principles.md#principle-2)).

---

## D-07: within-run blackboard plus persistent knowledge graph { #d-07 }

This decision evolved through two clarifications. The initial misread was that "save context" meant session resumption (save chat, resume tomorrow). The user clarified it twice: first to cross-agent shared knowledge (lenses coordinating without re-sending context), then to cost-saving (within one invocation, share the diff, SBOM, and project context across all lenses).

Two layers of shared state. Within a run, `RunContext` is an in-memory blackboard passed via PydanticAI's `deps` to every lens agent; it holds the parsed diff, SBOM delta, project context, plan, and a namespaced findings dict plus a facts list that lenses read from and write to. Across runs, `.loupe/knowledge.yaml` holds stable assets, architectural elements, decisions, and cross-references; facts get promoted there only when high-confidence and corroborated by one human decision or two runs.

The blackboard eliminates redundant CPU work (parsing the diff once, generating the SBOM once) and redundant LLM work (one lens does not re-derive what another already found). The two-level model (lens-private findings, cross-cutting facts) prevents both over-sharing and under-sharing. The promotion rule prevents the knowledge graph from filling with low-confidence noise.

---

## D-08: write boundary enforced in four layers { #d-08 }

The candidates were Layer 1 only, Layers 1 plus 4, Layers 1 plus 2 plus 4 (skip the hash chain), or all four.

All four. No single one is load-bearing.

1. Tool surface (in-process). The agent's only write tools are `write_agent_artifact` (allow-list path) and `propose_patch` (writes to `.proposed/`). The `PathBoundary` is a Python object, not a prompt instruction.
2. Branch namespace (CI runtime). The GitHub App token can only push to `loupe/proposal-*` branches; CODEOWNERS gates `context.md`, `decisions/`, and `config.yaml` regardless of branch.
3. `loupe verify` (pre-commit hook plus required CI check). Authorship, hash chain, schema consistency.
4. Interactive UX gate. Every protected-path proposal renders as a diff with a `[y/N/edit/skip]` prompt, default-N. No `--auto-confirm` flag.

The audit story has to hold when one layer has a bug. Defence in depth is what makes the artefacts evidence-grade. Cost: one to two weeks of v1 work. Skipping it would have made the CRA framing undefensible.

---

## D-09: MCP server with both granular tools and high-level workflows { #d-09 }

The MCP server is the third frontend, alongside the CLI and CI runner, using the same `loupe-core` engine. Two namespaces: `loupe.tools.*` for granular operations (propose a threat, query the knowledge graph) for clients that want to compose their own workflows, and `loupe.workflows.*` for high-level operations (analyse this diff) for clients that just want to invoke the whole thing.

The user wanted MCP exposure as a hard requirement. Both namespaces future-proof both audiences: power users compose, casual users invoke. All Layer 1–4 enforcement applies identically over MCP. An external MCP client cannot exceed the local agent's authority.

---

## D-10: three cost levers as architectural concerns { #d-10 }

After D-07 reframed "save context" as cost-saving, three levers were formalised as required properties of the architecture.

Stable-prefix prompt assembly. Every lens call structures its prompt as a stable prefix plus a variable suffix. The prefix is cache-pinned via Anthropic prompt-cache `cache_control` markers. Three sequential lens calls in one run pay full price once and roughly 10% for the next two.

Shared blackboard (no recompute). `RunContext.bootstrap()` parses the diff, generates the SBOM, computes the CVE list, and loads the knowledge graph once. The agent has no tool that could re-derive any of these inputs.

Coordinated dispatch (skip irrelevant lenses). The coordinator calls `lens.is_relevant(ctx)` (pure-Python heuristic, no LLM). Below-threshold lenses are skipped entirely. A docs-only PR triggers zero LLM calls.

Each lever lives in a specific core component (`PromptParts`, `RunContext`, `Coordinator.build_run_plan`), not as a pattern individual lens authors have to remember. Illustrative savings: three to five times naive baselines. On a thousand PRs a month, $200–$500 saved.

---

## D-11: lens contract is six methods { #d-11 }

```python
class Lens(Protocol):
    capabilities: LensCapabilities          # name, domain, intent keywords, artefact paths
    def build_agent(self, deps_type) -> Agent: ...
    def mcp_tools(self) -> list[McpTool]: ...
    def mcp_workflows(self) -> list[McpWorkflow]: ...
    def is_relevant(self, run_ctx) -> RelevanceScore: ...
    async def run(self, ctx, plan_entry, boundary, loupe_dir) -> None: ...
```

Six methods, one declared attribute. Anything else is implementation detail.

`is_relevant` must be pure Python with no LLM call; that is what makes lever 3 of D-10 cheap. `capabilities.artifact_paths` declares which paths in `.loupe/` the lens owns; `loupe-core` checks for conflicts at registration time (two lenses cannot both claim `.loupe/threats.yaml`). The contract gets refined when SafetyLens lands (D-04), not earlier.

---

## D-12: run records form a tamper-evident hash chain { #d-12 }

Each `runs/*.json` contains a `self_hash` (SHA-256 of its own content, excluding the `self_hash` field) and a `prev_run_hash` (the previous record's `self_hash`). `loupe verify` walks the chain.

Auditors need to detect history rewriting. Without the chain, a malicious actor could insert a fake "we considered this CVE and decided not_affected" run record. The chain is implemented in `loupe_core/artifacts/run_record.py` via deterministic JSON canonicalisation (sorted keys, no whitespace). This is part of Layer 3 enforcement; combined with Layer 2 (CODEOWNERS and branch protection) it is hard to bypass undetectably.

---

## D-13: VCR for LLM tests, never live calls in CI { #d-13 }

Integration tests with an agent use `pytest-vcr`. A developer records cassettes once (with an API key) and commits them. CI replays them without any API key.

LLM tests are non-deterministic, slow, and expensive when they hit a real API. VCR makes them deterministic, fast, and free. This is the only way to keep `uv run pytest` working in zero seconds for every contributor. See [principles.md §9](../principles.md#principle-9).

---

## D-14: defer commit signing and off-repo retention { #d-14 }

Sigstore or GPG commit signing, an off-repo retention store, and C2PA-style cryptographic provenance for AI outputs are all real concerns and all deferred. Git's SHA history plus the run-record hash chain (D-12) is sufficient evidence for v1. These features add real implementation cost and operational complexity; we add them when a real customer asks. The spec notes "Off-repo append-only log can be added as a v1.x feature without core changes."

---

## D-15: full-repo scans are first class via `loupe scan` { #d-15 }

The candidates were diff-only (would have skipped ThreatLens on no-diff runs because `is_relevant()` looks at `ctx.diff.changed_paths`), treating no-diff implicitly as "everything in scope" inside `is_relevant()`, two parallel pipelines (diff and full-repo), or one pipeline with a `scope` field on `RunContext` plus an explicit `loupe scan` command.

The last option won. `RunContext.scope` is `"diff"` (default), `"full"`, or `"scoped"`. When scope is not `"diff"`, `is_relevant()` returns high relevance unconditionally because the lens is being explicitly invoked. The agent's system prompt gains a scope-aware section. A new `loupe scan [--paths ...]` command bootstraps a `RunContext` with `scope=full` or `scoped`. Same dispatcher, same artefacts, same enforcement.

The diff-only assumption silently broke five real scenarios: first-time onboarding, periodic re-baseline, architectural review, audit kickoff, and `loupe chat` questions not tied to a recent change. For many adopters the first run ever will be a no-diff one. Both modes produce the same artefact types; the difference is scope of analysis, not output shape, which means it is expressible as a field, not a parallel pipeline.

Treating no-diff implicitly inside `is_relevant()` would have been clever-but-wrong: the user invoking `loupe scan` is making an explicit choice to pay the higher cost, and the system should honour that. The explicit command is also honest about cost: full-repo runs can blow `per_run_max_usd`. We require an explicit `--budget-usd <N>` flag when the configured limit is exceeded, rather than failing partway through.

Deferred to v1.x: a `--baseline` workflow (mark a known-good model, compare future diffs against it), `--since <revision>` for arbitrary git revisions, sampling for very large repos, and scheduled re-baseline.

---

## D-16: learn from StrideGPT, do not fork { #d-16 }

The candidates were forking StrideGPT, integrating it at runtime (calling it as a subprocess), ignoring it entirely, or learning from it and attributing the influence.

Last option. We study StrideGPT's prompts and STRIDE technique, attribute the influence in `prompts/system.md` and in `comparison.md`, do not fork or integrate, and use StrideGPT as a quality benchmark for ThreatLens output.

StrideGPT's architecture is fundamentally different from Loupe's: a one-shot Streamlit web UI, around 500 lines, with no in-repo persistence, no plugin seam, no write-boundary enforcement, no MCP, no continuous-CI operation. Forking would force us to gut 80% of it (mostly Streamlit) or contort our platform shape to fit theirs. The prompts and STRIDE category framing, on the other hand, are battle-tested across many users; that is the high-value reusable piece.

StrideGPT is MIT-licensed (verified by web fetch on 2026-05-14), so adaptation with attribution is licence-clean. It is actively maintained (173 commits, supports Claude 4.5, GPT-5, Gemini 3) and remains a trustworthy reference point. Runtime integration would require running their Streamlit app headless or adapting modules; significant adapter work for less benefit than re-implementing the parts we want.

Practical actions: when writing Phase 6's `prompts/system.md`, study `mrwadams/stride-gpt/threat_model.py` for prompt structure and STRIDE category questions, adapt useful framing with a comment crediting StrideGPT, and benchmark ThreatLens output against StrideGPT on three to five reference scenarios after Phase 6 ships.

Deliberately deferred from StrideGPT's feature set: attack-tree generation, DREAD scoring, Gherkin test-case generation. v1 stays focused on STRIDE threats, mitigations, and VEX.

---

## D-17: Apache 2.0 { #d-17 }

The candidates were MIT (permissive, no explicit patent grant or trademark protection), Apache 2.0 (permissive with explicit patent grant, patent retaliation, trademark non-grant), GPL v3 (copyleft), AGPL v3 (copyleft plus network-use clause), BSL (eventual-open with time-limited commercial restriction), MPL 2.0 (file-level copyleft), and proprietary.

Apache 2.0. See [`LICENSE`](../LICENSE) at the repo root.

A security-analysis tool may involve patentable analysis methods; Apache 2.0 §3 explicitly grants patent rights with a retaliation clause that revokes the grant if a licensee sues over patents in the code. MIT is silent on patents and US case law is inconsistent there. Apache 2.0 §6 explicitly does not grant trademark rights, blocking trademark squatting via fork. §5 spells out that intentional submissions are licensed under the project terms unless explicitly stated otherwise. Apache 2.0 is the boring-correct choice for enterprise-procured security tools; the CRA audience often requires it.

MPL 2.0 was a serious contender for file-level copyleft, but Loupe is a complete tool rather than an embedded library, so file-level copyleft adds friction without clear benefit. AGPL would catch SaaS competitors but creates real adoption friction; the dual-licence model would require CLA infrastructure premature for the project's stage. Proprietary would contradict the value proposition.

Trade-off: no commercial support contract. Acceptable for a local-first project with bounded maintenance burden. Copyright holder: Fadi Labib, as the originating author. Future contributors retain copyright on their contributions per usual Apache 2.0 custom; no CLA at this stage.

---

## D-18: capability abstraction for tool-agnostic operations { #d-18 }

The candidates were hardcoded tools (Syft directly in `loupe_core/sbom.py`, each future SBOM/CVE/secret tool similarly), per-tool pluggability (introduce `SbomBackend` but keep CVE/secrets/static-analysis hardcoded), or a generalised capability abstraction.

The generalised abstraction won, and it has shipped: `loupe-core/loupe_core/capabilities/` contains the protocol definitions, the registry, the composition modes, and the bundled Syft and Grype backends. A Capability is a typed Protocol describing one functional operation (`SbomCapability`, `CveCapability`, `SecretDetectionCapability`, `StaticAnalysisCapability`). Backends register through Python entry points under a single `loupe.capabilities` group; the class's `name` attribute declares which capability it satisfies. Composition modes (`single`, `fallback`, `union`, `consensus`, `pipeline`) let the operator configure how multiple backends interact. Lenses declare `requires_capabilities`; before the lens runs, `bootstrap_capabilities()` populates typed slots (`ctx.sbom`, `ctx.cve_findings`, `ctx.secrets`, `ctx.static_findings`) that every lens reads from the shared blackboard. `bootstrap_capabilities()` is wired into `ci_cmd.py` since commit 1e8405b; the slots populate before lens dispatch on real runs. Full design in [`../concepts/capabilities.md`](../concepts/capabilities.md).

Parity with the LLM-provider value matters: [principles.md §3](../principles.md#principle-3) commits us to no LLM-vendor lock-in via PydanticAI, and the original v1 spec accidentally re-introduced lock-in at the tool layer. Capabilities extend the same pattern down a layer. Cross-lens reuse matters too: ThreatLens needs SBOM, CVE matching, secret detection; SafetyLens will need static analysis and dependency-graph analysis; PrivacyLens will need PII detection. Without capabilities each lens re-implements its own tool wrappers.

Composition is audit-relevant: "run TruffleHog and gitleaks and merge" (`union`) catches what either alone misses; "require two of three static analysers to corroborate" (`consensus`) reduces false-positive noise. These are real audit patterns the current code cannot express. Tool availability also varies by environment; the agent's logic should not care which is installed.

The same problem recurs in CVE matching (Grype, osv-scanner, Trivy), secret detection (gitleaks, TruffleHog, detect-secrets), static analysis (Semgrep, CodeQL, Bandit), license scanning (ScanCode, FOSSA), and vuln-DB lookup (NVD, OSV, GHSA). Solving it five times ad hoc is worse than solving it once with a small framework.

Trade-offs accepted: about a week to land the registry plus protocols plus `RunContext` integration; versioning each Protocol's input/output models with Pydantic schema versions; `loupe-core` ships zero backends (users install `loupe-capabilities-essential` or individual `loupe-cap-*` packages).

Migration: Phase 6 (Task 6.3) lands ThreatLens with hardcoded Syft; Phase v1.x-A migrates `loupe_core/sbom.py` to `SbomCapability` with `SyftBackend` as the bundled default; one minor version of deprecation warning on the old function signature; then removed.

---

## D-19: two-tier benchmark, Mongoose plus Mosquitto { #d-19 }

The candidates were libpng/libtiff/libwebp (rich CVE history but memory-safety-dominated, STRIDE coverage too narrow), dropbear SSH (tiny, good protocol CVEs, but less mixed-level), paho.mqtt.c (client-side only), OpenSSL/cURL/nghttp2 (too large), Mosquitto alone (best STRIDE breadth and CRA framing, but five times slower per scenario than smaller alternatives), Mongoose alone (fastest iteration loop, smaller CVE corpus), or both in two tiers.

Two tiers. Cesanta Mongoose for Tier 1 (fast smoke test, per PR), Eclipse Mosquitto for Tier 2 (release evaluation). Full methodology in [`evaluation.md`](evaluation.md).

|  | Tier 1 (Mongoose) | Tier 2 (Mosquitto) |
|---|---|---|
| What | Embedded networking library | MQTT broker |
| Size | ~15k LOC core | ~70k LOC |
| Languages | C (single-file) | C broker plus C++ plugins |
| CVE history (5y) | ~12 | ~15 |
| STRIDE breadth | Mostly T/I/D | All six categories |
| Licence | dual GPL-2 / commercial | EPL-2.0 |
| When run | Per Loupe PR | Per Loupe release |
| Target scenarios | ~10 | ~15 |
| Target wall time | < 5 minutes | < 30 minutes |
| Public report | Optional | Yes |

Iteration speed and evaluation rigour are in tension. A single big suite is rigorous but slow; the cost stops people running it. A single small suite iterates fast but biases toward memory-safety CVEs where Loupe is honestly weakest. Two tiers separates the concerns. Tier 1 has to be fast enough that contributors actually run it (under five minutes). Tier 2 has to be representative for the result to be publishable (STRIDE breadth, architectural richness, CRA relevance).

The methodology is shared: same scoring engine, same per-scenario manifest schema, same StrideGPT comparison pattern (D-16). Only the scenario catalogues differ.

Mongoose specifically (over dropbear or paho) for Tier 1: smallest viable option (five times smaller than dropbear), single-file design makes failures easy to localise, embedded/IoT framing keeps both tiers thematically aligned with the CRA story. Mosquitto specifically (over Mongoose-alone or OpenSSL) for Tier 2: only Mosquitto combines audit-able size, STRIDE breadth across all six categories in real CVE history, mixed C/C++ architecture, clean EPL licence, and CRA-product-shape relevance.

Mongoose's dual GPL-2 / commercial licence does not bite for evaluation purposes (fork, run Loupe, record results, no redistribution of modified Mongoose). The scenarios catalogue and scoring code Loupe ships are Apache-2.0 and reference upstream commit SHAs rather than including Mongoose code.

Honest expected outcomes (recorded in `evaluation.md` so the result is not a surprise). Tier 1 will be heavy on parser/protocol-state CVEs; Loupe will under-perform on the memory-safety-pure ones, which is the explicit motivation for D-18's `StaticAnalysisCapability`. Tier 2 will spread more broadly; Loupe should do well on auth and ACL CVEs, mixed on memory-safety, mediocre on race conditions. The asymmetric results between tiers are themselves a finding: they show where the capability backends earn their keep.

Acceptance thresholds for v1.0: Tier 1 detection ≥ 50%, median cost ≤ $0.10/scenario. Tier 2 detection ≥ 70%, classification accuracy ≥ 80%, specific-match ≥ 50%, severity within one level, median cost ≤ $0.50/scenario.

Implementation timing: methodology recorded now; the `benchmarks/tier1-mongoose/` and `benchmarks/tier2-mosquitto/` directories, scoring code, and initial scenario catalogues land in Phase 10. Contributors can write scenarios today against the documented schema. The shared scoring methodology is publishable as an industry rubric; other STRIDE-tool authors can run the same scenarios against their own tools.

---

## D-20: docs publishing via MkDocs Material + GitHub Pages { #d-20 }

The candidates were raw GitHub Pages on `/docs/` (zero build, but no search and no nav), Sphinx (Python's reference choice, RST-oriented, heavy setup), Docusaurus (React-based, polished but pulls in a Node toolchain), and MkDocs Material (Python-native, Markdown-first, used by FastAPI, Pydantic, Typer, ruff, uv).

MkDocs Material won. With it, four supporting choices fell into place:

- **mkdocstrings (with the Python handler)** renders the artefact and capability schema pages directly from the Pydantic models. The pages shrink to a one-line `:::` directive; drift between docs and code goes to zero. Same trick OPA and others use; the Pydantic source is authoritative.
- **`pymdownx.snippets` with `check_paths: true`** lets a doc include real source ranges (e.g., `--8<-- "packages/.../path_boundary.py"`). A missing target fails the build the same way a broken link does.
- **`git-revision-date-localized` plus Material's social-card plugin** put a "Last update" footer on every page and generate per-page OG previews. Both fight the staleness-and-trust signals an auditor would otherwise have to take on faith.
- **`mkdocs-callouts`** converts GitHub-style `> [!WARNING]` and `> [!NOTE]` alerts to Material admonitions, so the same source renders as styled callouts in both readers without a Material-specific syntax leaking into the .md files.

Voice and link health are gated separately by Vale (four custom rules under `.vale/styles/Loupe/` enforcing the post-humanizer-pass voice) and lychee (link integrity). Both run on every PR; the pre-commit hook covers the docs-build and ruff checks locally so contributors fail fast.

Deploy uses `actions/deploy-pages@v4` (OIDC-based, no `gh-pages` branch). When the project tags v0.1, `mike` will write versioned doc copies to a `gh-pages` branch and the deploy workflow switches its upload source; the change is bounded. Until then, single-version publishing is enough.

The path not taken: a hand-written static HTML site or a JS-heavy generator (Docusaurus, Nextra). The maintenance burden of a custom theme or a JS toolchain pays off only when the doc site is a primary marketing surface. Loupe's docs are technical reference; Material's defaults are already polished enough.

---

## D-21: MCP server uses the official `mcp` SDK, not third-party `fastmcp` { #d-21 }

Three options for building the Loupe MCP server (Phase 9):

1. **`mcp.server.lowlevel.Server`** — the official Anthropic SDK's raw handler API. You wire `list_tools` / `call_tool` / `read_resource` yourself and hand-author every JSON Schema.
2. **`mcp.server.fastmcp.FastMCP`** — the high-level decorator API ALSO shipped inside the official `mcp` SDK. Auto-generates JSON Schema from Python type hints; same protocol guarantees as the lowlevel API.
3. **`fastmcp`** — the third-party package by jlowin (`pypi.org/project/fastmcp`). Decorator-based with a near-identical surface to option 2, but maintained outside Anthropic.

We chose option 2. The reasoning:

The official `mcp` SDK has been the spec-blessed reference implementation since 2024 and the `mcp.server.fastmcp` sub-module gives us the same decorator ergonomics as the third-party package without taking a bus-factor risk on a parallel maintainer. The third-party `fastmcp` arrived in our environment transitively — nothing we declared — and that's an audit-credibility smell for a project whose first principle is "evidence, not theatre" (you do not want an unexplained dependency carrying a security-adjacent server). Adding `mcp>=1.0` to `loupe-core`'s `dependencies` and importing from `mcp.server.fastmcp` makes the choice explicit.

The `*_impl` functions in `loupe_core/mcp_server.py` are deliberately decoupled from the FastMCP wiring. They take a `Path` to `.loupe/` and return plain `dict` / `list[dict]`. If the MCP spec or our framework choice changes, only the registration layer in `build_mcp_server` moves; the data-access layer survives untouched. This mirrors the capability-layer split between Protocol and backend (D-18) and the lens-vs-platform split (D-04).

Trade-offs accepted: the lowlevel API would let us emit hand-authored JSON Schema with richer constraints than Python type hints can express (e.g., regex `pattern` on `threat_id`). For the v1 read-only surface this isn't worth the boilerplate; if we add write tools later that need stricter input validation, we can drop to the lowlevel API for those specific tools while keeping the high-level decorator for the read ones — `FastMCP` and `Server` interoperate at the same protocol layer.

---

## Open decisions

Deferred until a specific trigger:

- **PyPI namespace** check before publishing. Fallback names recorded: `loupekit`, `loupe-platform`.
- **First canonical demo project**, picked before Phase 10's end-to-end smoke test.
- **GitLab/Gitea VCS adapter**, designed so it can be added without core changes.
- **Coordinator LLM-fallback policy** when `is_relevant()` returns 0.4–0.7 for multiple lenses, tuned in Phase 5.
- **Knowledge-graph promotion thresholds** beyond the initial "≥1 human decision OR ≥2 runs."

---

## How to read this log

Each decision is self-contained. When considering a change that touches one of these areas, find the relevant decision, see what was chosen and why, then ask whether the change updates an existing decision or creates a new one. Add to this log with the next available `D-NN`. If updating, keep the old decision visible but mark it superseded.
