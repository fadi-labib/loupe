# RunRecord

One file per Loupe invocation at `.loupe/runs/<timestamp>-<run_id>.json`. Canonical JSON (sorted keys, no whitespace) so `self_hash` is reproducible. Rendered from the Pydantic source.

## RunRecord

::: loupe_core.artifacts.run_record.RunRecord

## LensConsidered

::: loupe_core.artifacts.run_record.LensConsidered

## Hash chain construction

The `self_hash` is computed as:

```python
data = self.model_dump(mode="json", exclude={"self_hash"})
canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
self_hash = hashlib.sha256(canonical.encode()).hexdigest()
```

Two properties matter:

1. **Sorted keys, tight separators** make canonicalisation deterministic. Two clients computing the hash get the same result regardless of dict insertion order.
2. **Excluding `self_hash`** breaks the otherwise-circular reference. The field carries the hash of everything else.

`prev_run_hash` points at the previous record's `self_hash`. To break the chain, an attacker would have to recompute every record forward from the modified one, which `loupe verify` detects by comparing stored vs computed hashes record-by-record.

## Filename convention

```
.loupe/runs/{timestamp:%Y-%m-%dT%H-%M-%S-%fZ}-{run_id}.json
```

Microsecond precision means two runs in the same wall-clock second still sort chronologically by filename. Lexical sort matches chain order; no hash-chain traversal needed at load time.

## Example

```json
{
  "run_id": "run-a3f2b1c4",
  "timestamp": "2026-05-15T10:23:14.892173Z",
  "mode": "ci",
  "invoked_by": "loupe-action",
  "trigger": "github_pr",
  "base_sha": "0123456789abcdef0123456789abcdef01234567",
  "head_sha": "fedcba9876543210fedcba9876543210fedcba98",
  "diff_hash": "8f4a...",
  "context_md_hash": "c1d2...",
  "lenses_considered": [
    {"name": "threatlens", "score": 0.95, "reason": "code changes likely affect threat surface"}
  ],
  "lenses_run": ["threatlens"],
  "models_used": {"threatlens": "anthropic:claude-opus-4-7"},
  "total_tokens_in": 12450,
  "total_tokens_out": 832,
  "cost_usd_estimate": 0.07,
  "cache_hit_rate": 0.65,
  "artifacts_changed": [".loupe/threats.yaml"],
  "proposed_patches": [],
  "pending_decisions": [],
  "errors": [],
  "capability_degraded": [],
  "prev_run_hash": "aa11bb22...",
  "self_hash": "cc33dd44..."
}
```

`errors` carries structured lens crashes from `dispatch_plan`'s
error-isolation handler. `capability_degraded` (added in [D-23](../decisions.md#d-23))
carries preferred-but-unavailable capability records — one entry per
`(lens_name, capability)` pair where the lens's `prefers_capabilities`
declaration couldn't be satisfied and the lens ran with the matching
`RunContext` slot at `None`. Required-but-unavailable capabilities
never reach this list: they raise `RequiredCapabilityUnavailable`
at bootstrap and the CLI exits 64 before `dispatch_plan` runs. Both
fields are part of the canonical hash so a degraded run is
distinguishable from a clean one by `self_hash` alone.

## Validation

`load_run_records(runs_dir)` returns the chronologically-sorted list. `loupe verify` walks the chain and exits non-zero on the first record whose `prev_run_hash` does not match the previous record's `self_hash`. See [`verification.md`](../verification.md) for the audit recipe.
