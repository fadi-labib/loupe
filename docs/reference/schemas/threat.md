# Threat

The on-disk shape of one entry in `.loupe/threats.yaml`. Rendered from the Pydantic source so any field added in code shows up here on the next build — there is no hand-typed field table to drift.

## Threat

::: loupe_core.artifacts.threat.Threat

## ThreatsFile

::: loupe_core.artifacts.threat.ThreatsFile

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
      handler raises Exception directly without sanitisation.
    proposed_by: threatlens
```

## Cross-references

- Mitigation IDs in `mitigation_ids` must exist in [Mitigation](mitigation.md).
- Element IDs in `element_id` must exist in `knowledge.yaml`.
- `last_reviewed` and `review_due` are surfaced in the run record's `artifacts_changed` summary.
