# Capabilities — Tool-Agnostic Functional Building Blocks

> **Status:** Design recorded; implementation deferred to v1.x. The current `loupe-core` ships only `sbom.py` with a hardcoded Syft backend (Phase 3, Task 3.3). This document captures the design we're committing to so that when v1.x lands, the work has a clear specification — and so contributors can write capability backends today against the documented contract.

---

## The shape of the problem

Loupe's value proposition has two pluggable layers:

1. **Lenses** are domain-specific *agents* (a noun): ThreatLens does security threat modelling; SafetyLens (future) does ISO 26262 hazard analysis; PrivacyLens (future) does GDPR DPIA. A lens is the thing that reasons.

2. **Capabilities** are tool-agnostic *operations* (a verb): "generate an SBOM", "match CVEs against an SBOM", "find secrets in code", "run static analysis with rule R". A capability is the thing that produces an input or verifies a fact.

The original v1 design conflated these. `loupe_core/sbom.py` calls `syft` directly — Syft is hardcoded, not a backend. As a result:

- **Vendor lock-in at the tool layer.** Anchore's Syft is fine, but the spec also wants no lock-in (see [PRINCIPLES.md §7](PRINCIPLES.md#7-multi-llm-by-default-never-single-vendor-lock-in)). We achieve that for LLMs and abandon it for tools — inconsistent.
- **No way to compose tools.** "Run both TruffleHog and gitleaks and merge findings" is a real audit pattern (different tools find different secrets); the current shape can't express it.
- **Cross-lens reuse is limited.** Both ThreatLens (security) and a future SafetyLens (functional safety) will want static-analysis output. Each shouldn't re-implement Semgrep wrappers.
- **Tool availability varies by environment.** Some CI runners have Syft installed; some don't; some have Trivy instead. The agent's behaviour shouldn't depend on which tool the operator preferred.

The fix is a second extension point — **capabilities** — alongside lenses.

---

## The model

### Definition

A **Capability** is a typed Protocol describing a single, focused operation. A **CapabilityBackend** is a concrete implementation of that Protocol (e.g., `SyftBackend` implements the `SbomCapability` Protocol). Backends register via Python entry points under a per-capability group (e.g., `loupe.capabilities.sbom`).

Loupe's core ships a small set of Protocol definitions in `loupe_core/capabilities/`. It does *not* ship backends except for trivial built-ins. Real backends live in their own pip-installable packages — exactly like lenses.

### Mental model

```
                         ┌─────────────────────────────────┐
                         │     loupe-core (the platform)   │
                         │   ┌─────────────────────────┐   │
                         │   │  CapabilityRegistry     │   │
                         │   │  - SbomCapability       │   │
                         │   │  - CveCapability        │   │
                         │   │  - SecretDetectCap...   │   │
                         │   │  - StaticAnalysisCap... │   │
                         │   │  - VulnDbCapability     │   │
                         │   └────────────┬────────────┘   │
                         └────────────────│────────────────┘
                                          │
            ┌─────────────────────────────┼─────────────────────────────┐
            │                             │                             │
   ┌────────▼─────────┐         ┌────────▼─────────┐         ┌────────▼─────────┐
   │ loupe-cap-sbom-  │         │ loupe-cap-secret-│         │  loupe-cap-cve-  │
   │      syft        │         │   trufflehog     │         │     grype        │
   │  (pip package)   │         │   (pip package)  │         │  (pip package)   │
   └──────────────────┘         └──────────────────┘         └──────────────────┘
   ┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
   │ loupe-cap-sbom-  │         │ loupe-cap-secret-│         │  loupe-cap-cve-  │
   │      trivy       │         │     gitleaks     │         │   osv-scanner    │
   └──────────────────┘         └──────────────────┘         └──────────────────┘
   ┌──────────────────┐
   │ loupe-cap-sbom-  │         …(more backends as needed)
   │   github-api     │
   └──────────────────┘
```

Lenses *request* capabilities; the registry resolves them from installed backends according to per-project config.

---

## Capability Protocols (the contracts)

Each capability is one Python Protocol. Six are planned for v1.x; more can be added without breaking the model.

### `SbomCapability`

```python
class SbomCapability(Protocol):
    name: str                                                    # "syft", "trivy", "cdxgen", "github-api"
    cost_class: Literal["fast", "moderate", "slow"]              # rough hint for the coordinator
    def is_available(self) -> bool: ...                          # is the underlying tool installed/reachable
    def generate(self, repo_path: Path) -> CycloneDXDocument: ...
```

Candidate backends: Syft (Anchore), Trivy (Aqua), cdxgen (CycloneDX), Microsoft SBOM Tool, GitHub Dependency-Graph API, GitLab Dependency List API.

### `CveCapability`

```python
class CveCapability(Protocol):
    name: str                                                    # "grype", "osv-scanner", "trivy"
    cost_class: Literal["fast", "moderate", "slow"]
    def is_available(self) -> bool: ...
    def scan(self, sbom: CycloneDXDocument) -> list[CveMatch]: ...
```

Candidate backends: Grype (Anchore), osv-scanner (Google), Trivy (Aqua), Snyk API (commercial), GitHub Advisory API.

### `SecretDetectionCapability`

```python
class SecretDetectionCapability(Protocol):
    name: str                                                    # "trufflehog", "gitleaks", "detect-secrets"
    cost_class: Literal["fast", "moderate", "slow"]
    def is_available(self) -> bool: ...
    def scan(self, repo_path: Path, since: str | None) -> list[SecretFinding]: ...
```

Candidate backends: TruffleHog, gitleaks, detect-secrets, GitHub secret scanning API, Semgrep (with secret-detection rules).

### `StaticAnalysisCapability`

```python
class StaticAnalysisCapability(Protocol):
    name: str                                                    # "semgrep", "codeql", "bandit", "ruff", ...
    cost_class: Literal["fast", "moderate", "slow"]
    supported_languages: list[str]                               # ["python", "javascript", ...]
    def is_available(self) -> bool: ...
    def scan(self, repo_path: Path, rules: list[str] | None) -> list[StaticFinding]: ...
```

Candidate backends: Semgrep, CodeQL, Bandit (Python), ESLint security plugins, ShellCheck, RuboCop security.

### `LicenseScanCapability`

```python
class LicenseScanCapability(Protocol):
    name: str                                                    # "scancode", "fossology", "github-api"
    def is_available(self) -> bool: ...
    def scan(self, sbom: CycloneDXDocument) -> list[LicenseFinding]: ...
```

Candidate backends: ScanCode Toolkit, Fossology, GitHub license API, Tidelift.

### `VulnDbCapability`

```python
class VulnDbCapability(Protocol):
    name: str                                                    # "nvd", "osv", "ghsa", "epss"
    def is_available(self) -> bool: ...
    def lookup(self, cve_id: str) -> VulnRecord | None: ...
    def list_for_package(self, package: str, ecosystem: str) -> list[VulnRecord]: ...
```

Candidate backends: NVD (NIST), OSV (Google), GHSA (GitHub Security Advisories), EPSS (FIRST exploit prediction). Useful for the agent to look up details mid-reasoning.

### Future capabilities (sketched, not v1.x committed)

- `DependencyGraphCapability` — produce a typed dep tree (different shape from SBOM)
- `PiiDetectionCapability` — find PII in code / logs (needed for PrivacyLens)
- `DataFlowAnalysisCapability` — taint analysis (needed for some STRIDE-I threats)
- `ContainerImageCapability` — analyse container layers (Tern, Syft container mode)
- `IacScanCapability` — IaC misconfigurations (Trivy IaC, Checkov, tfsec)
- `SbomVerifyCapability` — verify SBOM authenticity / signing (Sigstore, in-toto)

A future lens like `AIRiskLens` would need new capabilities specific to its domain (e.g., `ModelCardCapability`, `DatasetAuditCapability`). The pattern stays the same.

---

## Composition modes

A single capability is fine for many cases ("generate one SBOM"). But the auditor-credibility framing benefits from *more than one* tool. The registry supports four modes:

### `single` (default)

Use the first available backend in priority order. Simple, cheap, predictable.

```yaml
capabilities:
  sbom:
    mode: single
    backends: [syft, trivy, github-api]   # use first available
```

### `fallback`

Try in order; if backend N fails (timeout, missing, error), try N+1. Identical interface from the lens's perspective.

```yaml
capabilities:
  sbom:
    mode: fallback
    backends: [syft, trivy, github-api]   # try each on failure
```

### `union`

Run all configured backends in parallel; merge results with deduplication by stable key. Use when different backends genuinely find different things.

```yaml
capabilities:
  secret_detect:
    mode: union
    backends: [trufflehog, gitleaks]      # union of findings, deduped by (file, line, hash)
```

**The reason this matters:** TruffleHog finds high-entropy strings; gitleaks finds pattern-matched API keys; neither is a strict superset. Running both and merging is the responsible default.

### `consensus`

Run all backends; emit only findings that ≥N backends report. Use when false-positive rate matters (one backend's noise is filtered by requiring corroboration).

```yaml
capabilities:
  static_analysis:
    mode: consensus
    backends: [semgrep, codeql, bandit]
    threshold: 2                          # at least 2 of 3 must agree
```

### `pipeline`

Output of backend N becomes input to backend N+1. Useful for chained operations like "SBOM → CVE-scan → license-check."

```yaml
capabilities:
  vuln_evidence:
    mode: pipeline
    backends:
      - sbom:syft                         # → CycloneDXDocument
      - cve:grype                         # consumes SBOM, → CveMatch[]
      - license:scancode                  # consumes SBOM, → LicenseFinding[]
```

The result types are stable Pydantic models, so pipelines compose safely.

---

## How a lens declares its needs

The lens contract grows by exactly one field: `requires_capabilities`.

```python
class LensCapabilities(BaseModel):
    name: str
    domain: str
    handles_intent_keywords: list[str] = Field(default_factory=list)
    artifact_paths: list[str] = Field(default_factory=list)
    requires_lenses: list[str] = Field(default_factory=list)
    requires_capabilities: list[str] = Field(default_factory=list)  # NEW
```

Example for ThreatLens v1.x:

```python
class ThreatLens:
    capabilities = LensCapabilities(
        name="threatlens",
        domain="security",
        handles_intent_keywords=["threat", "STRIDE", "CRA", ...],
        artifact_paths=[".loupe/threats.yaml", ".loupe/vex.json", ...],
        requires_capabilities=["sbom", "cve", "secret_detect"],   # ← NEW
    )

    async def run(self, ctx, plan_entry, boundary, loupe_dir):
        sbom = await ctx.capabilities.sbom.generate(repo_path)
        cves = await ctx.capabilities.cve.scan(sbom)
        secrets = await ctx.capabilities.secret_detect.scan(repo_path, since=ctx.diff.base_sha)
        # Hand structured results to the agent, no LLM call needed for these inputs
```

The lens does not know which backend(s) produced the results. That's the point.

---

## Coordinator behaviour

The coordinator's existing relevance + dependency logic gains one new check: **does the project have backends installed for every capability the selected lenses require?**

```python
def build_run_plan(ctx, lenses, capabilities, config) -> list[LensRunPlan]:
    # ... existing relevance + dependency logic ...

    # NEW: drop lenses whose required capabilities aren't satisfiable
    for name, (lens, _) in list(selected.items()):
        for cap_name in lens.capabilities.requires_capabilities:
            if not capabilities.has_satisfiable(cap_name, config):
                selected.pop(name)
                ctx.record_finding(
                    "coordinator",
                    f"dropped:{name}",
                    {"reason": f"capability '{cap_name}' has no available backend"},
                )
                break
```

A lens never silently runs without its capabilities. Same contract guarantee as `requires_lenses`.

---

## RunContext integration

`RunContext` gains a `capabilities` attribute:

```python
class RunContext(BaseModel):
    # ... existing fields ...
    capabilities: CapabilityRegistry         # NEW — resolved at bootstrap

# Usage from inside a lens
sbom = await ctx.capabilities.sbom.generate(repo_path)
findings = await ctx.capabilities.secret_detect.scan(repo_path, since=None)
```

`CapabilityRegistry` is a small facade that:

- Discovers backends via entry points at startup (same mechanism as lenses)
- Reads `config.yaml`'s `capabilities` section for backend selection + composition mode
- Calls `is_available()` on each backend; logs (doesn't crash) when an expected one is missing
- Caches results within a single run (don't regenerate the same SBOM twice)
- Routes per-capability calls through the configured composition mode

---

## Entry-point convention

Mirrors the lens convention exactly. Backend packages declare:

```toml
# loupe-cap-sbom-syft/pyproject.toml

[project.entry-points."loupe.capabilities.sbom"]
syft = "loupe_cap_sbom_syft.backend:SyftBackend"

# loupe-cap-secret-trufflehog/pyproject.toml

[project.entry-points."loupe.capabilities.secret_detect"]
trufflehog = "loupe_cap_secret_trufflehog.backend:TruffleHogBackend"
```

`loupe-core` discovers everything under `loupe.capabilities.*` at startup.

---

## Config example (the auditor-friendly composition)

```yaml
# .loupe/config.yaml — illustrative for a CRA-conformity-minded project
capabilities:
  sbom:
    mode: fallback
    backends: [syft, trivy, github-api]      # any one is fine; prefer Syft

  cve:
    mode: union                              # different DBs catch different CVEs
    backends: [grype, osv-scanner]           # merge results, dedupe by CVE ID

  secret_detect:
    mode: union                              # belt and braces
    backends: [trufflehog, gitleaks]

  static_analysis:
    mode: consensus                          # require corroboration
    backends: [semgrep, codeql]
    threshold: 2

  vuln_db:
    mode: single
    backends: [osv]                          # cheap, fast, sufficient for lookups
```

This config says: "any SBOM tool will do, but I want two CVE scanners agreeing; I want both secret scanners running because false negatives in secrets are catastrophic; I want two static analysers to corroborate before I treat a finding as real." That's a credible audit posture — and it's expressible as configuration, not code.

---

## Default backends (what ships with loupe-core v1.x)

To keep `loupe-core` light, core ships **zero** capability backends by default. The standard install adds two recommended bundles:

- **`loupe-capabilities-essential`** (a meta-package) — installs `loupe-cap-sbom-syft`, `loupe-cap-cve-grype`, `loupe-cap-secret-gitleaks`. Covers ThreatLens's `requires_capabilities` with sane defaults.
- **`loupe-capabilities-full`** — adds Trivy, TruffleHog, Semgrep, CodeQL CLI bindings, scancode, OSV. Bigger install footprint, richer composition options.

A bare `pip install loupe-cli loupe-threatlens` installs neither — ThreatLens will run, but its `requires_capabilities` will fail at coordinator time with a clear "install `loupe-capabilities-essential` (or equivalent)" message.

---

## Trade-offs accepted

This is genuinely more architecture than the v1 spec. The trade-offs:

| What we gain | What we pay |
|---|---|
| No tool lock-in (parity with our LLM stance) | One more extension point to maintain |
| Cross-lens capability reuse (SafetyLens can reuse SBOM, secret-detect from day one) | Lens authors must declare `requires_capabilities` honestly |
| Composition modes (`union`, `consensus`) the auditor story benefits from | More config knobs for users to get wrong |
| Capability backends can ship independently (third parties can publish) | Versioning + compatibility across capability protocols is a real concern |
| The current `sbom.py` mistake (hardcoded Syft) doesn't repeat for CVE / secret / static analysis | Phase 6's planned timeline grows |

The net argument: **paying this complexity once means we never pay it again per tool category.** Adding a new backend later is a pip-install, not a code change.

---

## Implementation roadmap

This is a v1.x feature. Sequencing:

1. **D-18 record** (this conversation) — captures the design publicly so contributors can write backend packages today against the documented Protocols.
2. **Phase v1.x-A — Capability protocols + registry skeleton** (~1 week)
   - Add `loupe_core/capabilities/` with the 6 Protocol definitions
   - Add `CapabilityRegistry` with entry-point discovery
   - Add `CapabilityRegistry` to `RunContext`
   - Coordinator dependency check
   - Unit tests with fake backends
3. **Phase v1.x-B — SBOM capability + Syft backend** (~3 days)
   - Refactor `loupe_core/sbom.py` into a `SbomCapability` Protocol with `SyftBackend` as a backend package
   - Migration: existing `generate_sbom()` becomes a thin facade for backward compat for one minor version, then removed
4. **Phase v1.x-C — CVE capability + Grype/osv-scanner backends** (~3 days)
5. **Phase v1.x-D — Secret-detection capability + gitleaks/TruffleHog backends** (~3 days)
6. **Phase v1.x-E — Static-analysis capability + Semgrep backend** (~3 days)
7. **Phase v1.x-F — Composition modes (union/consensus/pipeline)** (~1 week)
   - `single` and `fallback` ship in v1.x-A
   - The richer modes come once we have ≥2 backends per capability to compose

Total estimated v1.x effort: **~4–5 weeks** distributed across releases. Each phase produces working, shippable software on its own.

---

## What this is *not* trying to do

Worth stating explicitly so the design stays focused:

- **Not a generic plugin framework.** Capabilities are typed, schema-checked, narrowly-scoped. We will not let arbitrary code mount "any tool" — every backend must conform to a published Protocol.
- **Not a marketplace.** Anyone can publish a capability backend on PyPI; Loupe doesn't curate. But installation is a deliberate `pip install` by the operator (see [PRINCIPLES.md §1](PRINCIPLES.md#1-produce-evidence-not-theatre) on transparency).
- **Not a substitute for lenses.** A capability does *one* thing. A lens *reasons* about a domain using one or more capabilities. The agent — and therefore the LLM — lives in the lens, not the capability.
- **Not an abstraction over LLM providers.** PydanticAI already handles that. Capabilities are about *non-LLM* tools (scanners, generators, validators).

---

## Cross-references

- [D-18 in DECISIONS.md](DECISIONS.md#d-18--capability-abstraction-tool-agnostic-functional-building-blocks) — the decision record
- [PRINCIPLES.md §7 (no LLM lock-in)](PRINCIPLES.md#7-multi-llm-by-default-never-single-vendor-lock-in) — the parallel principle for LLMs
- [PRINCIPLES.md §11 (no tool lock-in)](PRINCIPLES.md#11-no-tool-lock-in-pluggable-capabilities) — the new principle this capability layer enforces
- [ABOUT.md "Why Loupe"](ABOUT.md) — the value proposition this strengthens
- [COMPARISON.md](COMPARISON.md) — competitive context (Trivy vs Syft; gitleaks vs TruffleHog; etc.)
- [GLOSSARY.md](GLOSSARY.md) — `Capability`, `CapabilityBackend`, `CapabilityRegistry`, `composition mode`, individual capability types
