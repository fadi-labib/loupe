# RunRecord

Sourced from `packages/loupe-core/loupe_core/artifacts/run_record.py`. One file per Loupe invocation lives at `.loupe/runs/<timestamp>-<run_id>.json`. The format is canonical JSON (sorted keys, no whitespace) so the hash chain is reproducible.

## RunRecord

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | `str` | yes | e.g., `run-a3f2b1c4` |
| `timestamp` | `datetime` | yes | UTC ISO 8601, microsecond precision |
| `mode` | `Literal["ci", "interactive"]` | yes | Which frontend invoked Loupe |
| `invoked_by` | `str` | yes | Bot identity (CI) or user email (interactive) |
| `trigger` | `str` | yes | e.g., `github_pr`, `manual_ci`, `chat_session` |
| `base_sha` | `str \| null` | yes | Git commit SHA of the base (`null` for `loupe scan`) |
| `head_sha` | `str \| null` | yes | Git commit SHA of the head |
| `diff_hash` | `str` | yes | SHA-256 of the unified-diff text |
| `context_md_hash` | `str` | yes | SHA-256 of `context.md` at run time |
| `lenses_considered` | `list[LensConsidered]` | yes | Every enabled lens, with its relevance score |
| `lenses_run` | `list[str]` | yes | Subset of `lenses_considered` that ran |
| `models_used` | `dict[str, str]` | yes | Map of lens-name → model identifier |
| `total_tokens_in` | `int` | yes | Sum across all LLM calls this run |
| `total_tokens_out` | `int` | yes |   |
| `cost_usd_estimate` | `float` | yes | Calculated from token counts and the configured pricing table |
| `cache_hit_rate` | `float \| null` | yes | Prompt-cache hit rate when known; null when unmeasurable |
| `artifacts_changed` | `list[str]` | yes | Paths in `.loupe/` written this run |
| `proposed_patches` | `list[str]` | yes | Paths in `.loupe/.proposed/` created this run |
| `pending_decisions` | `list[str]` | yes | IDs of `decisions/*.md` awaiting human sign-off |
| `prev_run_hash` | `str \| null` | yes | SHA-256 of the previous run record; `null` for the first run |
| `self_hash` | `str` | yes | SHA-256 of this record's content, excluding the `self_hash` field |

## LensConsidered

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | `str` | yes | Lens name (`threatlens`, etc.) |
| `score` | `float` | yes | `is_relevant().score` |
| `reason` | `str` | yes | `is_relevant().reason` |

## Hash chain construction

The `self_hash` is computed as:

```python
data = self.model_dump(mode="json", exclude={"self_hash"})
canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
self_hash = hashlib.sha256(canonical.encode()).hexdigest()
```

Two properties matter:

1. **Sorted keys + tight separators** make the canonicalisation deterministic. Two clients computing the hash get the same result regardless of dict insertion order.
2. **Excluding `self_hash`** breaks the otherwise circular reference. The field carries the hash of everything else.

`prev_run_hash` points at the previous record's `self_hash`. To break the chain, an attacker would have to recompute every record from the modified one forward, which `loupe verify` detects by comparing the stored `prev_run_hash` with the actual previous record's `self_hash`.

## Filename

The save path is:

```
.loupe/runs/{timestamp.strftime("%Y-%m-%dT%H-%M-%S-%fZ")}-{run_id}.json
```

Microsecond precision in the timestamp means two runs in the same wall-clock second still sort chronologically by filename. Lexical filename sort matches chain order; no need for hash-chain traversal at load time.

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
  "prev_run_hash": "aa11bb22...",
  "self_hash": "cc33dd44..."
}
```

## Validation

`load_run_records(runs_dir)` returns the chronologically-sorted list. `loupe verify` walks the chain and exits non-zero on the first record whose `prev_run_hash` does not match the previous record's `self_hash`. See [`verification.md`](../verification.md#p-1-evidence-not-theatre) for the audit recipe.
