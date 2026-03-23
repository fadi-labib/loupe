# Mitigation

The on-disk shape of one entry in `.loupe/mitigations.yaml`. Rendered from the Pydantic source.

## Mitigation

::: loupe_core.artifacts.mitigation.Mitigation

## Evidence

::: loupe_core.artifacts.mitigation.Evidence

## MitigationsFile

::: loupe_core.artifacts.mitigation.MitigationsFile

## Example

```yaml
schema_version: 1
mitigations:
  - id: M-005
    title: Sanitise exception messages before returning 500 responses
    description: |
      Wrap the framework's default error handler so internal exception
      messages do not leak in HTTP responses. Log the traceback server
      side; return a generic message plus a request ID to the client.
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

- Threat IDs in `threats_addressed` are typed as `ThreatId` and validated at parse time against the `T-NNN` pattern. Whether the referenced threat actually exists in `threats.yaml` is checked separately at cross-reference time by `loupe verify` (one of the four Layer 3 checks).
- `evidence[].location` is treated as a hint; the validator does not check the path exists.
- A mitigation with `status: verified` and a null `verified_by` is allowed but is a code smell; future `loupe verify` checks may warn on this.
