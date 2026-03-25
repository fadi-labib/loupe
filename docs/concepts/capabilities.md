---
tags:
  - concept
  - capability
---

# Capabilities: tool-agnostic functional building blocks

> [!NOTE]
> **Status:** D-18 has shipped end-to-end. `loupe-core/loupe_core/capabilities/` holds the protocol definitions, the registry, the composition modes, and the bundled Syft + Grype backends; the `loupe.capabilities` entry-point group is wired in `loupe-core/pyproject.toml`; `loupe ci` calls `bootstrap_capabilities()` so the typed `ctx.sbom` and `ctx.cve_findings` slots are populated on real runs. The remaining work is the ThreatLens agent consuming those slots against a live LLM.

## Why two extension points

Loupe has two distinct pluggable layers. Lenses are domain-specific agents (the noun): ThreatLens does security threat modelling, SafetyLens (future) does ISO 26262 hazard analysis, PrivacyLens (future) does GDPR DPIA. A lens reasons about a domain.

Capabilities are tool-agnostic operations (the verb): generate an SBOM, match CVEs against an SBOM, find secrets in code, run static analysis with a rule pack. A capability produces an input or verifies a fact; lenses consume those outputs.

The original v1 spec conflated the two: `loupe_core/sbom.py` called `syft` directly with no abstraction. That introduced vendor lock-in at the tool layer (the same lock-in the principles forbid for LLMs) and made cross-tool composition impossible (no way to express "run TruffleHog and gitleaks and merge"). The downstream effect was that each lens re-implemented its own tool wrappers, and the agent's behaviour depended on which tool the operator had installed.

The fix is a second extension point sitting alongside lenses.

---

## The model

### Definition

A **Capability** is a typed Protocol describing a single, focused operation. A **CapabilityBackend** is a concrete implementation of that Protocol (e.g., `SyftSbomBackend` implements the `SbomCapability` Protocol). Backends register via Python entry points under the single `loupe.capabilities` group; the `name` attribute on each backend class declares which capability it implements.

Loupe's core ships the Protocol definitions in `loupe_core/capabilities/protocols/` plus 10 bundled default backends under `loupe_core/capabilities/backends/`:

| Capability | Bundled backends |
|---|---|
| `sbom` | `syft`, `cdxgen` |
| `cve` | `grype`, `osv-scanner` |
| `secret_detect` | `gitleaks`, `trufflehog`, `detect-secrets` |
| `static_analysis` | `semgrep`, `codeql`, `bandit` |

Third-party backends live in their own pip-installable packages and register under the same `loupe.capabilities` entry-point group; the core never imports a backend by name.

### Mental model

```mermaid
flowchart TB
    subgraph core["loupe-core (the platform)"]
        registry["CapabilityRegistry"]
        subgraph protocols["Typed Protocols"]
            sbom["SbomCapability"]
            cve["CveCapability"]
            sd["SecretDetectionCapability"]
            sast["StaticAnalysisCapability"]
        end
        registry --> protocols
    end

    subgraph sbom_backends["SBOM backends"]
        b_syft["syft (bundled)"]
        b_cdxgen["cdxgen (bundled)"]
        b_trivy["trivy (third-party)"]
    end

    subgraph cve_backends["CVE backends"]
        b_grype["grype (bundled)"]
        b_osv["osv-scanner (bundled)"]
        b_trivy_cve["trivy (third-party)"]
    end

    subgraph sd_backends["Secret-detect backends"]
        b_th["trufflehog (bundled)"]
        b_gl["gitleaks (bundled)"]
        b_ds["detect-secrets (bundled)"]
    end

    subgraph sast_backends["SAST backends"]
        b_sem["semgrep (bundled)"]
        b_cq["codeql (bundled)"]
        b_ba["bandit (bundled)"]
    end

    sbom -.->|"`loupe.capabilities`<br/>entry points"| sbom_backends
    cve -.-> cve_backends
    sd -.-> sd_backends
    sast -.-> sast_backends

    classDef coreNode fill:#fef3c7,stroke:#a16207,stroke-width:2px
    classDef protoNode fill:#f3e8ff,stroke:#7e22ce,stroke-width:2px
    classDef bundledNode fill:#dcfce7,stroke:#15803d,stroke-width:1px
    classDef thirdPartyNode fill:#ffe4e6,stroke:#be123c,stroke-width:1px
    class registry coreNode
    class sbom,cve,sd,sast protoNode
    class b_syft,b_cdxgen,b_grype,b_osv,b_th,b_gl,b_ds,b_sem,b_cq,b_ba bundledNode
    class b_trivy,b_trivy_cve thirdPartyNode
```

The core holds typed Protocols. Each Protocol is satisfied by one or more backends, which register through the single `loupe.capabilities` entry-point group. Lenses request a capability category (`sbom`, `cve`, `secret_detect`, `static_analysis`); the registry resolves to the operator-configured backend list, runs each backend, and combines results via the composition mode declared in `config.yaml`.

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

- `DependencyGraphCapability` produce a typed dep tree (different shape from SBOM)
- `PiiDetectionCapability` find PII in code / logs (needed for PrivacyLens)
- `DataFlowAnalysisCapability` taint analysis (needed for some STRIDE-I threats)
- `ContainerImageCapability` analyse container layers (Tern, Syft container mode)
- `IacScanCapability` IaC misconfigurations (Trivy IaC, Checkov, tfsec)
- `SbomVerifyCapability` verify SBOM authenticity / signing (Sigstore, in-toto)

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

TruffleHog finds high-entropy strings; gitleaks finds pattern-matched API keys; neither is a strict superset. Running both and merging is the responsible default.

### `consensus`

Run all backends; emit only findings that ≥N backends report. Use when false-positive rate matters (one backend's noise is filtered by requiring corroboration).

```yaml
capabilities:
  static_analysis:
    mode: consensus
    backends: [semgrep, codeql, bandit]
    consensus_threshold: 2                          # at least 2 of 3 must agree
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
        # ctx.sbom and ctx.cve_findings are populated by bootstrap_capabilities()
        # before any lens runs. Each lens reads typed results off the blackboard.
        sbom = ctx.sbom                # SbomResult, or None if no SBOM backend ran
        cves = ctx.cve_findings        # CveResult, or None
        # Hand structured results to the agent; no LLM call needed for these inputs.
```

The lens does not know which backend(s) produced the results. That's the point.

---

## Coordinator behaviour

The coordinator's existing relevance + dependency logic gains one new check: **does the project have backends installed for every capability the selected lenses require?**

> [!NOTE]
> The snippet below is illustrative. The real `build_run_plan(ctx, lenses, config)` lives in `loupe_core/coordinator.py`; the capability-satisfiability filter shown here is sketched against the registry available via `bootstrap_capabilities()`.

```python
def build_run_plan(ctx, lenses, config) -> list[LensRunPlan]:
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

`RunContext` carries one typed slot per capability, populated before any lens runs:

```python
class RunContext(BaseModel):
    # ... existing fields ...
    sbom: SbomResult | None = None
    cve_findings: CveResult | None = None
    secrets: SecretDetectionResult | None = None
    static_findings: StaticAnalysisResult | None = None

# Usage from inside a lens
sbom = ctx.sbom              # SbomResult or None
findings = ctx.secrets       # SecretDetectionResult or None
```

`bootstrap_capabilities()` in `loupe_core/capabilities/bootstrap.py` does the population:

- Computes the union of `requires_capabilities` across selected lenses.
- For each, resolves backends through the registry and invokes them under the configured composition mode.
- Stores the typed result on the corresponding RunContext slot.
- Implicit dependencies are handled (declaring `["cve"]` implicitly pulls `sbom`, since every CVE backend in practice consumes an SBOM).

The registry caches results within a single run; multiple lenses asking for the same SBOM pay for it once.

## Entry-point convention

Mirrors the lens convention. Backend packages declare entries under the single `loupe.capabilities` group; the backend class's `name` attribute identifies the capability category.

```toml
# loupe-core/pyproject.toml (bundled defaults)

[project.entry-points."loupe.capabilities"]
syft  = "loupe_core.capabilities.backends.syft_sbom:SyftSbomBackend"
grype = "loupe_core.capabilities.backends.grype_cve:GrypeCveBackend"

# A third-party backend in its own package
[project.entry-points."loupe.capabilities"]
trivy = "loupe_cap_trivy.backend:TrivyBackend"
```

`loupe-core` discovers every entry under `loupe.capabilities` at startup, then indexes by `(capability_name, backend_name)` where `capability_name` comes from the class's `name` attribute (e.g., `"sbom"`, `"cve"`) and `backend_name` comes from the entry-point key (`"syft"`, `"trivy"`).

---

## Config example (the auditor-friendly composition)

```yaml
# .loupe/config.yaml illustrative for a CRA-conformity-minded project
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
    consensus_threshold: 2

  vuln_db:
    mode: single
    backends: [osv]                          # cheap, fast, sufficient for lookups
```

This config says: "any SBOM tool will do, but I want two CVE scanners agreeing; I want both secret scanners running because false negatives in secrets are catastrophic; I want two static analysers to corroborate before I treat a finding as real."

---

## Default backends (what ships with loupe-core v1.x)

`loupe-core` v1.x bundles **ten** capability backends, registered via the `loupe.capabilities` entry-point group in `loupe-core/pyproject.toml`:

| Capability | Bundled backends |
|---|---|
| `sbom` | `syft`, `cdxgen` |
| `cve` | `grype`, `osv-scanner` |
| `secret_detect` | `gitleaks`, `trufflehog`, `detect-secrets` |
| `static_analysis` | `semgrep`, `codeql`, `bandit` |

Each backend's `is_available()` method checks whether the underlying tool is reachable on the system; the registry only invokes backends that say yes. So `pip install loupe-cli loupe-threatlens` gives you a working pipeline as soon as the operator-side tools (Syft, Grype, etc.) are on `PATH`; missing tools are reported through the coordinator's dependency check, not at import time.

Future split-out: if the bundled set ever grows large enough to bloat `loupe-core`'s install, the heavier backends can move to optional `loupe-cap-*` packages without changing the lens-facing API. The entry-point group is the contract; whether a backend ships inside core or as a separate pip package is an install-size optimisation, not a design boundary.

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

Adding a new backend later is a pip-install, not a code change.

---

## Implementation roadmap

The phased sequencing for the capability layer (Phase v1.x-A through v1.x-F) lives in [`../roadmap.md`](../roadmap.md) alongside the broader release plan, so the concept page stays evergreen and the roadmap stays editable as priorities shift.

---

## What this is *not* trying to do

Worth stating explicitly so the design stays focused:

- **Not a generic plugin framework.** Capabilities are typed, schema-checked, narrowly-scoped. We will not let arbitrary code mount "any tool"; every backend must conform to a published Protocol.
- **Not a marketplace.** Anyone can publish a capability backend on PyPI; Loupe doesn't curate. But installation is a deliberate `pip install` by the operator (see [principles.md §1](../principles.md#principle-1) on transparency).
- **Not a substitute for lenses.** A capability does *one* thing. A lens *reasons* about a domain using one or more capabilities. The agent and therefore the LLM lives in the lens, not the capability.
- **Not an abstraction over LLM providers.** PydanticAI already handles that. Capabilities are about *non-LLM* tools (scanners, generators, validators).

---

## Cross-references

- [D-18 in ../reference/decisions.md](../reference/decisions.md#d-18) the decision record
- [principles.md §3 (multi-LLM by default)](../principles.md#principle-3) the parallel principle for LLMs
- [principles.md §4 (no tool lock-in)](../principles.md#principle-4) the principle this capability layer enforces
- [about.md "Why Loupe"](../about.md) the value proposition this strengthens
- [comparison.md](../comparison.md) competitive context (Trivy vs Syft; gitleaks vs TruffleHog; etc.)
- [../reference/glossary.md](../reference/glossary.md) `Capability`, `CapabilityBackend`, `CapabilityRegistry`, `composition mode`, individual capability types
