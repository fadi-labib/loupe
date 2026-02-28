# Threat

Sourced from `packages/loupe-core/loupe_core/artifacts/threat.py`. Each entry in `.loupe/threats.yaml` is a `Threat` record; the file root is `ThreatsFile`.

## Threat

| Field | Type | Required | Validation | Notes |
|---|---|---|---|---|
| `id` | `str` | yes | matches `^T-\d{3,}$` | Stable identifier; never reuse across runs |
| `element_id` | `str` | yes | matches `^E-\d{3,}$` | Refers to a system component declared in `knowledge.yaml` |
| `stride_category` | `StrideCategory` enum | yes | `S` / `T` / `R` / `I` / `D` / `E` | Single-letter STRIDE category |
| `title` | `str` | yes | length 1–200 | Short label; appears in PR-comment summaries |
| `description` | `str` | yes | length ≥ 1 | Full prose description |
| `severity` | `Severity` enum | yes | `low` / `medium` / `high` / `critical` | Feeds `ci.fail_on` gating |
| `status` | `ThreatStatus` enum | yes | `proposed` / `accepted` / `mitigated` / `accepted_risk` / `rejected` | The agent writes `proposed`; humans transition the rest |
| `mitigation_ids` | `list[str]` | no, default `[]` | each entry is a Mitigation ID | Cross-reference into `mitigations.yaml` |
| `cwe_refs` | `list[str]` | no, default `[]` |   | e.g., `["CWE-79", "CWE-89"]` |
| `attack_pattern_refs` | `list[str]` | no, default `[]` |   | e.g., CAPEC IDs |
| `introduced_in_pr` | `str \| null` | no, default `null` |   | PR number or `null` for pre-existing |
| `last_reviewed` | `date` | yes | ISO date | When a human last reviewed |
| `review_due` | `date \| null` | no, default `null` |   | Schedule next review |
| `rationale` | `str` | yes |   | Why this threat exists and how it was identified |
| `proposed_by` | `str` | yes |   | Agent identity or human name |

## ThreatsFile

The root of `.loupe/threats.yaml`:

| Field | Type | Default | Notes |
|---|---|---|---|
| `schema_version` | `int` | `1` | Bumps on a breaking schema change |
| `threats` | `list[Threat]` | `[]` | All threats for the project |

## Example

```yaml
schema_version: 1
threats:
  - id: T-001
    element_id: E-001
    stride_category: I
    title: API endpoint leaks user IDs in error messages
    description: |
      The /api/users endpoint returns stack traces in 500 responses,
      revealing internal user IDs and database schema names.
    severity: high
    status: proposed
    mitigation_ids: [M-005]
    cwe_refs: [CWE-209]
    attack_pattern_refs: []
    introduced_in_pr: "1234"
    last_reviewed: 2026-05-15
    review_due: 2026-08-15
    rationale: |
      Reviewing the diff for /api/users, I noticed the new exception
      handler raises Exception directly without sanitisation. The
      framework's default 500 handler will echo the message.
    proposed_by: threatlens
```

## Cross-references

- Mitigation IDs in `mitigation_ids` must exist in [Mitigation](mitigation.md).
- Element IDs in `element_id` must exist in `knowledge.yaml` (see ProjectContext / knowledge graph).
- `last_reviewed` and `review_due` participate in the audit trail; the run record references the threats it touched.

## Validation behaviour

`Threat` is validated on load via `ThreatsFile.load(path)`. Errors surface as `pydantic.ValidationError` with field-level detail; the CLI catches them and exits with code 2.
