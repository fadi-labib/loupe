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

## Artefact Merkle root construction

`artifact_hashes` maps each path written under `.loupe/` during this run to
its SHA-256 content hash (lowercase hex, 64 chars). `artifacts_merkle_root`
is the SHA-256 Merkle root over those leaves, computed in `save_run_record`
so callers cannot forget. The root is `null` when the run wrote no
artefacts and on legacy records that pre-date this field.

Construction details an external auditor needs to reproduce:

1. Sort `artifact_hashes` items by path (lexical, UTF-8). Paths are stored
   in POSIX form (`as_posix()`) so Windows and Linux auditors see identical
   keys.
2. Leaf hash: `SHA-256(b"\x00" + path_utf8 + b":" + sha256_hex_ascii)`.
3. Internal hash: `SHA-256(b"\x01" + left_bytes + right_bytes)` where each
   operand is the 32-byte binary form of the child hex digest.
4. On a level with an odd number of nodes, duplicate the last node before
   pairing.
5. The single remaining node is the root. Empty input collapses to the
   `null` sentinel rather than a fixed hash, so "no artefacts in this run"
   reads differently from "artefacts present, root computed".

The `b"\x00"` and `b"\x01"` domain separators prevent the second-preimage
attack where an attacker substitutes a leaf hash for an internal hash.
Reference implementation: `loupe_core.artifacts.merkle`.

`artifacts_merkle_root` is part of the record's canonical content, so
`self_hash` covers it. Tampering with the root after the fact breaks both
the chain check and the Merkle check. The two checks are independent and
both run by default in `loupe verify`.

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
