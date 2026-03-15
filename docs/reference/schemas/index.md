# Artefact schemas

Every artefact Loupe writes is a Pydantic model. This section is the human-readable companion to those models: field-by-field tables, validation rules, and an example for each.

> [!NOTE]
> The Pydantic source is authoritative. If this page and `packages/loupe-core/loupe_core/artifacts/*.py` disagree, the code is right. The point of these pages is for an auditor to read a table without grepping Python.

## What's documented here

| Schema | What it represents | Path in `.loupe/` | Source |
|---|---|---|---|
| [Threat](threat.md) | One STRIDE-category threat with stable ID | `.loupe/threats.yaml` | `artifacts/threat.py` |
| [Mitigation](mitigation.md) | One mitigation that addresses ≥1 threats | `.loupe/mitigations.yaml` | `artifacts/mitigation.py` |
| [RunRecord](run-record.md) | Tamper-evident audit entry per Loupe run | `.loupe/runs/<id>.json` | `artifacts/run_record.py` |
| [ProjectContext](project-context.md) | The human-authored product brief | `.loupe/context.md` | `artifacts/context.py` |
| [KnowledgeGraph](knowledge.md) | Cross-run knowledge graph (assets, elements, decisions, cross-refs) | `.loupe/knowledge.yaml` | `artifacts/knowledge.py` |
| [LoupeConfig](../config.md) | Operator settings (separate full reference) | `.loupe/config.yaml` | `core/config.py` |
| [Capability results](capabilities.md) | Typed outputs of SBOM, CVE, secret, SAST backends | not on disk; lives on `RunContext` | `capabilities/protocols/` |

## Common enums

These are shared across multiple artefacts.

### Severity

```
low | medium | high | critical
```

Ordered: `low < medium < high < critical`. Used by `Threat.severity` and by `ci.fail_on` in config.

### ThreatStatus

```
proposed | accepted | mitigated | accepted_risk | rejected
```

`proposed` is what the agent writes; the rest reflect human decisions.

### MitigationStatus

```
proposed | planned | implemented | verified | retired
```

### StrideCategory

```
S = Spoofing
T = Tampering
R = Repudiation
I = Information disclosure
D = Denial of service
E = Elevation of privilege
```

Stored as the single-letter code. Validation rejects anything else.

### VexStatus

```
affected | not_affected | fixed | under_investigation
```

`not_affected` requires human approval via `propose_patch`. The agent can write the others directly.

### Stable-ID patterns

| Kind | Pattern | Examples |
|---|---|---|
| Threat | `T-\d{3,}` | `T-001`, `T-2026-05-15-042` |
| Mitigation | `M-\d{3,}` | `M-007` |
| Element (system component) | `E-\d{3,}` | `E-001` |
| Decision (risk acceptance) | `D-YYYY-MM-DD-<slug>` | `D-2026-05-15-cve-7891-accepted` |

Validators reject IDs that do not match.
