# Mitigation

Sourced from `packages/loupe-core/loupe_core/artifacts/mitigation.py`. Each entry in `.loupe/mitigations.yaml` is a `Mitigation` record; the file root is `MitigationsFile`.

## Mitigation

| Field | Type | Required | Validation | Notes |
|---|---|---|---|---|
| `id` | `str` | yes | matches `^M-\d{3,}$` | Stable identifier; never reuse |
| `title` | `str` | yes | length 1–200 | Short label |
| `description` | `str` | yes | length ≥ 1 | What this mitigation does |
| `threats_addressed` | `list[str]` | no, default `[]` | each entry a Threat ID | Reverse-of `Threat.mitigation_ids` |
| `status` | `MitigationStatus` enum | yes | `proposed` / `planned` / `implemented` / `verified` / `retired` | Lifecycle state |
| `evidence` | `list[Evidence]` | no, default `[]` | see below | Where to look to confirm the mitigation exists |
| `verified_by` | `str \| null` | no, default `null` |   | Whoever verified the mitigation |
| `last_verified` | `date \| null` | no, default `null` |   | When the verification happened |

## Evidence

A pointer into the codebase, docs, or external system that backs the mitigation claim.

| Field | Type | Required | Validation | Notes |
|---|---|---|---|---|
| `kind` | `Literal` | yes | `code` / `doc` / `test` / `config` / `external` | What kind of artefact |
| `location` | `str` | yes | length ≥ 1 | Path, URL, or reference (e.g., `src/auth/login.py:42`) |
| `note` | `str \| null` | no, default `null` |   | Free-text annotation |

## MitigationsFile

The root of `.loupe/mitigations.yaml`:

| Field | Type | Default | Notes |
|---|---|---|---|
| `schema_version` | `int` | `1` | Bumps on a breaking schema change |
| `mitigations` | `list[Mitigation]` | `[]` | All mitigations for the project |

## Example

```yaml
schema_version: 1
mitigations:
  - id: M-005
    title: Sanitise exception messages before returning 500 responses
    description: |
      Wrap the framework's default error handler so internal exception
      messages do not leak in HTTP responses. Log the full traceback
      server-side; return a generic message + a request ID to the client.
    threats_addressed: [T-001]
    status: planned
    evidence:
      - kind: code
        location: src/api/middleware/error_handler.py
        note: New file added in the PR that closes T-001
      - kind: test
        location: tests/api/test_error_responses.py
        note: Assert no exception class names appear in 500 bodies
    verified_by: null
    last_verified: null
```

## Cross-references

- Every Threat ID in `threats_addressed` must exist in [Threat](threat.md)'s file.
- `evidence[].location` is treated as a hint, not a hard constraint; the validator does not check that the path exists.
- A mitigation with `status: verified` and no `verified_by` field is allowed but is a code smell; future `loupe verify` checks may warn on this.
