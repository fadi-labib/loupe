# Capability result schemas

The typed return values of the four Capability Protocols. Live on `RunContext` (`ctx.sbom`, `ctx.cve_findings`, `ctx.secrets`, `ctx.static_findings`) once `bootstrap_capabilities()` runs. Rendered from the Pydantic source.

## SbomResult

::: loupe_core.capabilities.protocols.sbom.SbomResult

### SbomComponent

::: loupe_core.capabilities.protocols.sbom.SbomComponent

## CveResult

::: loupe_core.capabilities.protocols.cve.CveResult

### CveFinding

::: loupe_core.capabilities.protocols.cve.CveFinding

## SecretDetectionResult

::: loupe_core.capabilities.protocols.secret_detect.SecretDetectionResult

### SecretFinding

::: loupe_core.capabilities.protocols.secret_detect.SecretFinding

## StaticAnalysisResult

::: loupe_core.capabilities.protocols.static_analysis.StaticAnalysisResult

### StaticFinding

::: loupe_core.capabilities.protocols.static_analysis.StaticFinding

## Composition output

When `compose_run(mode=union, ...)` runs, the returned result has `backend_name = "union"` (or `f"consensus>={N}"` for consensus mode). Individual findings retain their original `backend_name` only if you store them separately; the aggregate carries a synthetic name.

Dedup heuristics:

- CVE findings dedup on `(cve_id, component_name, component_version)`.
- Secret and static findings dedup on `(file, line, rule_id)`.

See [`concepts/capabilities.md`](../../concepts/capabilities.md) for the full composition behaviour.

## How a lens reads these

```python
async def run(self, ctx, plan_entry, boundary, loupe_dir):
    sbom = ctx.sbom              # SbomResult | None
    cves = ctx.cve_findings      # CveResult | None
    if cves is None:
        # No CVE backend ran for this invocation; either nothing required it,
        # or the operator did not configure one.
        return
    for finding in cves.findings:
        ...
```

`None` means the capability never ran; check before iterating.
