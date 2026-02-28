# Capability result schemas

The typed return values of the four Capability Protocols. Sourced from `packages/loupe-core/loupe_core/capabilities/protocols/`. These live on `RunContext` (`ctx.sbom`, `ctx.cve_findings`, `ctx.secrets`, `ctx.static_findings`) once `bootstrap_capabilities()` runs.

## SbomResult

Returned by any backend implementing `SbomCapability`.

| Field | Type | Default | Notes |
|---|---|---|---|
| `components` | `list[SbomComponent]` | `[]` | One per package |
| `sbom_format` | `Literal["cyclonedx-json", "spdx-json"]` | `"cyclonedx-json"` | What standard the raw document follows |
| `raw_document` | `str` | `""` | The complete SBOM text |
| `backend_name` | `str` | `""` | Which backend produced it (`syft`, `trivy`, …) |

### SbomComponent

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | `str` | required |   |
| `version` | `str` | required |   |
| `purl` | `str \| null` | `null` | Package URL per the purl-spec |
| `licenses` | `list[str]` | `[]` | SPDX IDs extracted from the SBOM |

## CveResult

Returned by any backend implementing `CveCapability`. Has a `by_severity()` helper that groups the findings.

| Field | Type | Default | Notes |
|---|---|---|---|
| `findings` | `list[CveFinding]` | `[]` |   |
| `backend_name` | `str` | `""` |   |

### CveFinding

| Field | Type | Required | Validation | Notes |
|---|---|---|---|---|
| `cve_id` | `str` | yes |   | e.g., `CVE-2024-12345` |
| `component_name` | `str` | yes |   | Matches an `SbomComponent.name` |
| `component_version` | `str` | yes |   |   |
| `severity` | `Severity` | yes | `critical` / `high` / `medium` / `low` / `informational` |   |
| `summary` | `str` | yes |   | One-line description from the source feed |
| `source_url` | `str \| null` | no, default `null` |   |   |
| `cvss_score` | `float \| null` | no, default `null` | 0.0–10.0 |   |
| `fixed_version` | `str \| null` | no, default `null` |   | Upstream-fixed version, if known |

## SecretDetectionResult

Returned by any backend implementing `SecretDetectionCapability`.

| Field | Type | Default | Notes |
|---|---|---|---|
| `findings` | `list[SecretFinding]` | `[]` |   |
| `backend_name` | `str` | `""` |   |

### SecretFinding

| Field | Type | Required | Validation | Notes |
|---|---|---|---|---|
| `file` | `str` | yes |   | Path inside the repo |
| `line` | `int` | yes | ≥ 0 |   |
| `rule_id` | `str` | yes |   | Backend-specific identifier (e.g., `aws-access-key-id`) |
| `redacted_match` | `str` | yes |   | Sensitive match scrubbed for display |
| `severity` | `Severity` | no, default `high` |   |   |

## StaticAnalysisResult

Returned by any backend implementing `StaticAnalysisCapability`.

| Field | Type | Default | Notes |
|---|---|---|---|
| `findings` | `list[StaticFinding]` | `[]` |   |
| `backend_name` | `str` | `""` |   |

### StaticFinding

| Field | Type | Required | Validation | Notes |
|---|---|---|---|---|
| `rule_id` | `str` | yes |   | e.g., `python.lang.security.dangerous-subprocess-use` |
| `file` | `str` | yes |   |   |
| `line` | `int` | yes | ≥ 0 |   |
| `severity` | `Severity` | yes |   |   |
| `message` | `str` | yes |   |   |

## Composition output

When `compose_run(mode=union, …)` runs, the returned result has `backend_name = "union"` (or `f"consensus>={N}"` for consensus mode). Individual findings retain their original `backend_name` only if you store them separately; the aggregate carries a synthetic name.

For dedup heuristics:

- CVE findings dedup on `(cve_id, component_name, component_version)`.
- Secret and static findings dedup on `(file, line, rule_id)`.

See [`concepts/capabilities.md`](../../concepts/capabilities.md) for the full composition behaviour.

## How a lens reads these

```python
async def run(self, ctx, plan_entry, boundary, loupe_dir):
    sbom = ctx.sbom              # SbomResult | None
    cves = ctx.cve_findings      # CveResult | None
    if cves is None:
        # no CVE backend ran for this invocation; either nothing required it,
        # or the operator did not configure one
        return
    for finding in cves.findings:
        ...
```

`None` means the capability never ran; check before iterating.
