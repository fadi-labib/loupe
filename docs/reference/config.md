# Config reference

`.loupe/config.yaml` is parsed and validated as a `LoupeConfig`. The Pydantic model in `packages/loupe-core/loupe_core/config.py` is authoritative; this page renders the fields from that source. There is no hand-typed field table to drift.

## Top-level shape

```yaml
schema_version: 1
models:
  default: anthropic:claude-opus-4-7
  threatlens:
    primary: anthropic:claude-opus-4-7
limits:
  per_run_max_usd: 2.5
  per_run_max_tokens_in: 500000
  per_run_max_steps: 30
ci:
  fail_on: [critical, high]
  warn_on: [medium]
  ignore_paths: ["docs/**"]
agent_writable_paths:
  - .loupe/threats.yaml
  - .loupe/mitigations.yaml
  - .loupe/threat-model.md
  - .loupe/vex.json
  - .loupe/sbom.cdx.json
  - .loupe/runs/**
lenses:
  threatlens:
    enabled: true
    minimum_relevance: 0.3
capabilities:
  sbom:
    mode: single
    backends: [syft]
  cve:
    mode: fallback
    backends: [grype, osv-scanner]
```

All keys are optional except where Pydantic marks them required. The file is parsed with `ruamel.yaml` and validated as a `LoupeConfig`. Validation errors are raised at `loupe ci` / `loupe scan` startup, not silently ignored.

Model identifiers use the **PydanticAI native `provider:model` form** (colon, not slash). Examples: `anthropic:claude-opus-4-7`, `openai:gpt-5`, `google-gla:gemini-2.5-pro`, `ollama:llama-3.3-70b`. The environment variable `THREATLENS_MODEL` overrides `models.threatlens.primary` when set.

## LoupeConfig

::: loupe_core.config.LoupeConfig

## ModelsConfig

::: loupe_core.config.ModelsConfig

### LensModelConfig

::: loupe_core.config.LensModelConfig

## LimitsConfig

::: loupe_core.config.LimitsConfig

## CIConfig

::: loupe_core.config.CIConfig

## `lenses` (dict[name, LensActivation])

One key per installed lens. The lens registers itself via the `loupe.lenses` entry-point group; the operator opts each one in or out here. Both fields below are consulted by the coordinator at plan-build time.

A lens key referencing an unknown lens (one not installed via entry point) is allowed and silently ignored, so projects can carry forward-looking configs that work as new lenses are added.

The value type:

::: loupe_core.config.LensActivation

## `capabilities` (dict[name, CapabilityActivation])

One key per capability the operator wants to wire. The capability registers itself via the `loupe.capabilities` entry-point group; this section says which backends to use and how to combine them.

The five composition modes (`single`, `fallback`, `union`, `consensus`, `pipeline`) and their audit-relevance are documented end-to-end in [`concepts/capabilities.md`](../concepts/capabilities.md). Validation summary (enforced by `CapabilityActivation`):

- `backends` must be non-empty.
- If `mode == "consensus"` and `consensus_threshold` is `null`, parsing fails.
- If `consensus_threshold > len(backends)`, parsing fails.

The value type:

::: loupe_core.config.CapabilityActivation

## `agent_writable_paths`

The Layer 1 allow-list. `write_agent_artifact` checks every path the agent tries to write against this list. Anything not matching ends up as a proposal under `.loupe/.proposed/` instead, or fails with `BoundaryViolation`. `PathBoundary` is constructed from this list in `packages/loupe-cli/loupe_cli/ci_cmd.py`.

The default-config template from `loupe init` lists:

- `.loupe/threats.yaml`
- `.loupe/mitigations.yaml`
- `.loupe/threat-model.md`
- `.loupe/vex.json`
- `.loupe/sbom.cdx.json`
- `.loupe/runs/**` (recursive)

The boundary normalises paths and rejects any path containing `..` regardless of the allow-list. Absolute paths are allowed only if explicitly listed.

## Validation behaviour

`load_config(path)` raises `FileNotFoundError` if the file does not exist. Pydantic's `model_validate` raises `ValidationError` with field-level detail on any other shape mismatch. The CLI catches both and prints a structured error before exiting with code 2.

## How the file gets there

`loupe init` writes the template above. After that the file is human-managed. The agent has no tool that can edit `config.yaml`; the path is deliberately not in `agent_writable_paths`. Changes go through git and PR review like any other code change.

## Example configs

=== "Minimal"

    Enough to run `loupe ci`; everything else picks up defaults.

    ```yaml
    schema_version: 1
    lenses:
      threatlens:
        enabled: true
    ```

=== "Production (typical)"

    What most teams will start with: ThreatLens enabled, capability registry wired for SBOM and CVE, sensible CI gate.

    ```yaml
    schema_version: 1
    models:
      default: anthropic:claude-opus-4-7
    ci:
      fail_on: [critical, high]
      warn_on: [medium]
      ignore_paths: ["docs/**", "**/*.md"]
    agent_writable_paths:
      - .loupe/threats.yaml
      - .loupe/mitigations.yaml
      - .loupe/threat-model.md
      - .loupe/vex.json
      - .loupe/sbom.cdx.json
      - .loupe/runs/**
    lenses:
      threatlens:
        enabled: true
        minimum_relevance: 0.3
    capabilities:
      sbom:
        mode: single
        backends: [syft]
      cve:
        mode: fallback
        backends: [grype, osv-scanner]
    ```

=== "Audit-heavy"

    Belt-and-braces secret detection, consensus-based SAST, lower relevance threshold so more PRs get analysed. Higher cost per run, stronger evidence.

    ```yaml
    schema_version: 1
    ci:
      fail_on: [critical, high, medium]
      warn_on: [low]
    limits:
      per_run_max_usd: 5.0
      per_run_max_tokens_in: 1500000
      per_run_max_steps: 60
    lenses:
      threatlens:
        enabled: true
        minimum_relevance: 0.15
    capabilities:
      sbom:
        mode: union
        backends: [syft, trivy]
      cve:
        mode: union
        backends: [grype, osv-scanner, trivy]
      secret_detect:
        mode: union
        backends: [trufflehog, gitleaks]
      static_analysis:
        mode: consensus
        consensus_threshold: 2
        backends: [semgrep, codeql, bandit]
    ```
