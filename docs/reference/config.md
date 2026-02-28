# Config reference

Every field of `.loupe/config.yaml` end-to-end, with defaults and validation rules. Sourced from `packages/loupe-core/loupe_core/config.py` (`LoupeConfig` and its nested models). Treat the Pydantic source as authoritative; this page is a readable companion.

## Top-level shape

```yaml
schema_version: 1
models:
  default: anthropic/claude-opus-4-7
  threatlens:
    primary: anthropic/claude-opus-4-7
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

All keys are optional except where noted. The file is parsed with `ruamel.yaml` and validated as a `LoupeConfig`. Validation errors are raised at `loupe ci` / `loupe scan` startup, not silently ignored.

## `schema_version` (int, default `1`)

Future migrations bump this. v1 today.

## `models` (object)

Per-lens model selection and fallback. Used by lenses (not yet wired into the live agent flow).

| Field | Type | Default | Notes |
|---|---|---|---|
| `models.default` | string | `anthropic/claude-opus-4-7` | Provider:model identifier. Format matches PydanticAI: `anthropic:claude-opus-4-7`, `openai:gpt-5`, `google-gla:gemini-2.5-pro`, `ollama:llama-3.3-70b`. |
| `models.threatlens` | object \| null | `null` | Per-lens override; see below |
| `models.threatlens.primary` | string | (required if override given) | Primary model for ThreatLens |
| `models.threatlens.fallback` | string \| null | `null` | Fallback if primary fails |
| `models.threatlens.cheap_for` | list[string] | `[]` | Task names that should use `cheap_model` |
| `models.threatlens.cheap_model` | string \| null | `null` | Cheaper model for non-critical sub-tasks |

The environment variable `THREATLENS_MODEL` overrides `models.threatlens.primary` if set.

## `limits` (object)

Hard cost and step caps; the runtime aborts a run when any is exceeded.

| Field | Type | Default | Validation |
|---|---|---|---|
| `limits.per_run_max_usd` | float | `2.5` | Must be > 0 |
| `limits.per_run_max_tokens_in` | int | `500000` | Must be > 0 |
| `limits.per_run_max_steps` | int | `30` | Must be > 0 |

These are budgets, not estimates. A run that would exceed any of them stops cleanly with a `budget_exceeded` entry in the run record.

## `ci` (object)

Gate behaviour for the GitHub Action and `loupe ci`. The Action consults this to compute the step exit code.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `ci.fail_on` | list[string] | `[]` | Severities that fail the build (exit 1). Bare strings: `critical`, `high`, `medium`, `low`. Empty list = report-only |
| `ci.warn_on` | list[string] | `[]` | Severities that warn but do not fail. Reserved for future surfacing in the PR comment |
| `ci.ignore_paths` | list[string] | `[]` | Glob patterns the lenses skip when computing relevance |

The richer semantic tokens documented in earlier versions (`new_critical_threat_unmitigated`, etc.) are designed but not yet consumed by the gate logic. Stick to bare severities.

## `agent_writable_paths` (list[string])

The Layer 1 allow-list. `write_agent_artifact` checks every path the agent tries to write against this list. Anything not matching ends up as a proposal under `.loupe/.proposed/` instead, or fails with `BoundaryViolation`.

The default-config template from `loupe init` lists:

- `.loupe/threats.yaml`
- `.loupe/mitigations.yaml`
- `.loupe/threat-model.md`
- `.loupe/vex.json`
- `.loupe/sbom.cdx.json`
- `.loupe/runs/**` (recursive)

The boundary normalises paths and rejects any path containing `..` regardless of the allow-list. Absolute paths are allowed only if explicitly listed.

## `lenses` (dict[name, LensActivation])

One key per installed lens. The lens registers itself via the `loupe.lenses` entry-point group; the operator opts each one in or out here.

| Field per lens | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Run this lens? `false` skips it entirely regardless of relevance |
| `minimum_relevance` | float [0.0–1.0] | `0.3` | Skip the lens when `is_relevant(ctx).score < minimum_relevance` |

A lens key referencing an unknown lens (one not installed via entry point) is allowed and silently ignored, so projects can have ambitious configs that work as lenses get added.

## `capabilities` (dict[name, CapabilityActivation])

One key per capability the operator wants to wire. The capability registers itself via the `loupe.capabilities` entry-point group; this section says which backends to use and how to combine them.

| Field per capability | Type | Default | Meaning |
|---|---|---|---|
| `mode` | enum | `single` | Composition mode: `single`, `fallback`, `union`, `consensus`, `pipeline` |
| `backends` | list[string] | (required, min length 1) | Backend names in the desired order |
| `consensus_threshold` | int \| null | `null` | Required when `mode == "consensus"`; must be ≥1 and ≤`len(backends)` |

The `single` / `fallback` / `union` / `consensus` / `pipeline` modes are documented in [`concepts/capabilities.md`](../concepts/capabilities.md). Validation rules from `CapabilityActivation`:

- `backends` cannot be empty.
- If `mode == "consensus"` and `consensus_threshold` is `null`, parsing fails.
- If `consensus_threshold > len(backends)`, parsing fails.

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
