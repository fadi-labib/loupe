# Loupe principles

Eleven things we will not compromise on. These came out of the design conversation rather than being declared upfront. When reviewing a change, ask which one it would break.

## Evidence, not theatre { #principle-1 }

A compliance scanner that emits a 200-page green-tick PDF and passes its own audit is theatre. We want the opposite: artefacts an auditor can verify with their own tooling. In practice that means CycloneDX for SBOMs, OpenVEX for vulnerability statements, structured threats with stable IDs, hash-chained run records, and git as the audit substrate. It rules out free-form reports, proprietary formats, "trust us" claims, and risk scores divorced from the underlying evidence.

## The write boundary is a Python function { #principle-2 }

Most AI-safety enforcement in the wild lives in a system prompt: "do not edit files outside this directory." That is unreliable against prompt injection and against model drift. An attacker has to find the gap once.

Loupe's Layer 1 enforcement is a `PathBoundary` object the tool functions consult before any write. The agent has two write tools: `write_agent_artifact` (path must be in the allow-list) and `propose_patch` (writes to `.proposed/` for human review). There is no general "write any file" tool. There is no Bash tool that could write as a side effect. The boundary is in the code path.

This extends past writes. Any agent capability that needs to be constrained must be constrained by the tool surface, not by instruction. If a constraint is worth enforcing, it is worth enforcing in code.

## Defence in depth { #principle-3 }

The write boundary problem is solved by four layers, not one. Tool surface (in-process Python function, strongest). Branch namespace (the CI token can only push to `loupe/proposal-*` branches; CODEOWNERS gates protected paths). `loupe verify` (pre-commit hook plus required CI check; authorship plus hash chain). And the interactive UX gate (every protected-path proposal shows a diff with a default-N prompt; no `--yes` flag).

If one layer has a bug, the others catch the failure. The cost was one to two weeks of extra implementation. The benefit is that the audit story holds when something goes wrong, which is the only audit story that matters.

When you add a new constraint, ask which layer enforces it. If only one does, ask whether a second is cheap to add.

## Cost discipline { #principle-4 }

A multi-lens agent running on every PR can burn money three to five times faster than it needs to. Three levers, baked in rather than retrofitted.

Stable-prefix prompt assembly. The portion of the prompt that is the same across lens calls (system framing, `context.md`, diff summary, SBOM delta) gets paid for once and then around 10% per subsequent call via Anthropic prompt caching. The variable portion (per-lens task, prior-finding handover) pays full price every time. The `PromptParts` model enforces this structurally so individual lens authors cannot regress it.

Shared blackboard. `RunContext.bootstrap()` parses the diff, generates the SBOM, computes the CVE list, loads the knowledge graph once. Every lens reads from `RunContext`. The agent has no tool that could rederive any of these inputs.

Coordinated dispatch. The coordinator asks each lens `is_relevant(ctx)` (pure Python, no LLM call). Lenses below threshold are skipped entirely. A docs-only PR runs no LLM calls. A single-dependency change runs one lens, not all of them.

Illustrative result: about $0.001 for a docs-only PR, $0.07 for a dependency change, $0.11 for a new endpoint, $0.21 for a three-lens analysis. Naive baselines (no cache, no skip) are three to five times higher.

A feature that breaks prompt-cache leverage is a regression even when it works correctly.

## Humans stay in the decision seat { #principle-5 }

The agent drafts. Humans decide. Risk acceptances under `decisions/` are authored by humans and signed by a human identity; the agent can only draft. `context.md` is human-authored; the agent can propose patches but cannot edit it directly. VEX `not_affected` statements require human approval (the agent can record `affected` and `fixed` directly because those are mechanical CVE matches, but `not_affected` is an analytical judgment). `config.yaml` is human-managed; the agent reads it.

In CI, "human approval" means PR review with CODEOWNERS. In interactive mode, it means a `[y/N/edit/skip]` prompt with default-N. There is no `--auto-confirm` flag and no environment variable that lowers the bar.

## Standard formats { #principle-6 }

When an industry standard exists for what we produce, we use it. CycloneDX 1.6 for SBOMs. OpenVEX 0.2 for vulnerability statements. STRIDE for threat categorisation. Pydantic and JSON Schema for tool I/O (so MCP clients get full type info for free). Markdown plus YAML frontmatter for human-readable artefacts (so any editor can edit them). JSON-RPC over stdio or HTTP for MCP because that is the spec.

Proprietary formats compound forever: every downstream consumer has to learn them. Standard formats are a one-time conversion cost. Always pay it once.

## Multi-LLM by default { #principle-7 }

The agent must run on Claude, OpenAI, Google, Ollama, or any provider PydanticAI supports, switched via environment variable. This is a hard requirement, not a nice-to-have.

Regulated customers often have approved-LLM lists; a tool locked to one vendor loses those customers. Cross-checking outputs against a second model is a reasonable audit ask that single-vendor tools cannot satisfy. Cost optimisation (cheap model for grunt work, smart model for hard reasoning) is impossible without multi-provider. Vendor risk is real: providers go down, raise prices, pivot APIs.

This shaped the framework choice. PydanticAI over Claude Agent SDK, even though the latter has nicer agentic primitives (plan mode, hooks, subagents), because the Claude Agent SDK is Claude-only. A feature that only works on one provider is a v1.x feature, not a v1.0 feature.

## Plugin contracts grow with the second instance { #principle-8 }

The rule of three says design an abstraction when you have three instances. We have one (ThreatLens) and a credible expectation of more (SafetyLens, PrivacyLens). Enough to start with a minimal plugin seam: one base class, one entry-point group, six required methods. Not enough to design the "complete" plugin contract for hypothetical needs.

We redesign the contract when SafetyLens lands. That redesign is bounded (one big PR, not a rearchitecture). Designing the contract upfront for imagined needs is invariably wrong, expensive, and locked in.

## VCR or no LLM in CI { #principle-9 }

LLM tests are non-deterministic, slow, and expensive. Live LLM calls in test suites are an anti-pattern that bites every project that adopts them.

Unit tests (Pydantic models, path boundary, prompt builder, diff parsing) never call an LLM. Integration tests with an agent use VCR.py to record HTTP fixtures once (with an API key) and replay forever (without one). Cassettes are committed to the repo. End-to-end CI runs against the same cassettes.

A developer iterating on a prompt re-records the cassette explicitly with `--record-mode=once`; the new cassette is reviewed in the PR.

The payoff: `uv run pytest` works in zero seconds with no API keys, on every CI run.

## Naming reflects activity, not regulation { #principle-10 }

The platform is "Loupe" (an inspection instrument), not "ComplianceMate." Lenses are named after the activity they perform (threat modelling, safety analysis, privacy review), not the regulation they happen to feed (CRA, ISO 26262, GDPR).

This is partly marketing (fake-compliance branding repels both engineers and auditors), but mostly engineering. Naming after the regulation locks the code's identity to the regulation's lifecycle. Regulations change: CRA will get amended, ISO 26262 has gone through five revisions. Activities change much more slowly.

When naming a new component, ask whether the name will still make sense after the current regulatory landscape has shifted.

## No tool lock-in { #principle-11 }

The same logic that rules out LLM-vendor lock-in rules out tool-vendor lock-in. Loupe's analysis pipeline calls out to non-LLM tools: SBOM generators (Syft, Trivy, cdxgen, GitHub API), CVE scanners (Grype, osv-scanner, Trivy), secret detectors (TruffleHog, gitleaks, detect-secrets), static analysers (Semgrep, CodeQL, Bandit). Each is a category, not a single tool.

A lens declares `requires_capabilities=["sbom", "cve", "secret_detect"]`; it does not know or care which tool fulfils each. The capability registry resolves to a configured backend. Composition modes (`single`, `fallback`, `union`, `consensus`, `pipeline`) let operators run multiple backends for the same capability: merging findings from TruffleHog and gitleaks, for example, because either alone has gaps.

When a new tool category appears (SAST that beats Semgrep, SBOM signing via Sigstore, PII-detection libraries), we add it as a new Capability Protocol and a backend package. No fork, no rewrite. The auditor can read the project's `config.yaml`, see `secret_detect: mode: union, backends: [trufflehog, gitleaks]`, and immediately understand the team's posture.
