# Loupe benchmarks

Historical-CVE evaluation suites, per [D-19](../docs/reference/decisions.md#d-19)
and [evaluation.md](../docs/reference/evaluation.md). Methodology: pick a
real OSS project with published CVEs, check out the code exactly before
each fix, run Loupe against it as a diff, score what it found against
the published advisory. The CVE advisories are externally audited
ground truth — there's no risk of Loupe grading its own homework.

## What's here

- **`scoring/`** — shared, tier-agnostic scoring engine (manifest schema,
  per-scenario scoring, aggregate reporting, StrideGPT-comparison table
  rendering). Pure Python, no LLM calls, fully unit-tested under the
  normal free `pytest` gate.
- **`tier1-mongoose/`** — the Tier 1 (Cesanta Mongoose) scenario
  catalogue and orchestrator inputs. See its own README for specifics.
- **`run-tier1.py`** — Tier 1 orchestrator entrypoint.

Tier 2 (Eclipse Mosquitto, release evaluation) is documented in
evaluation.md but not yet built — see D-19's "Implementation timing"
note. The scoring engine is deliberately tier-agnostic (nothing in
`scoring/` references "mongoose" or "tier1") so Tier 2 can plug in later
without rearchitecting.

## Cost and determinism

These are **live-LLM runs with real API cost** — categorically different
from the rest of this repo's test suite, which sets `ANTHROPIC_API_KEY=""`
in CI specifically to stay free and deterministic via VCR cassettes
(`pytest-vcr`). Replaying a cassette here would only prove "the same
bytes come back as last time," not "Loupe still detects the
vulnerability" — which defeats the entire point of the benchmark.

Consequently:

- **Not** wired into `.github/workflows/tests.yml`'s required PR gate.
  There's no existing mechanism in this repo for a paid, non-deterministic
  check to block a merge — every required check today is free and
  deterministic (ruff, mypy, pytest-with-empty-keys, lychee, vale).
- **Is** runnable on demand (`uv run python benchmarks/run-tier1.py`)
  before pushing a change that touches the agent loop, prompt, or
  run-record shape — a recommended contributor habit, not an automated
  gate.
- **Is** runnable via a scheduled + `workflow_dispatch` GitHub Actions
  workflow (`.github/workflows/benchmark-tier1.yml`) for maintainer-
  controlled-cadence tracking, requiring `ANTHROPIC_API_KEY` as a
  repository secret.
- The **scoring math itself** (`scoring/`, pure Python) has normal,
  free, deterministic unit tests under `benchmarks/scoring/tests/`,
  collected by the regular `pytest` run via this repo's root
  `pyproject.toml` `testpaths`. Only the live orchestrator runs cost
  money — verifying the scorer's logic doesn't.

This is a deliberate reading of D-19's "runs per Loupe PR" language as
"a contributor habit + scheduled tracking job," not "a required
PR-blocking status check" — see the note added to D-19 in
[decisions.md](../docs/reference/decisions.md#d-19).

## Running

```bash
git submodule update --init benchmarks/tier1-mongoose/mongoose-fork
export ANTHROPIC_API_KEY=sk-ant-...
# Syft + Grype must be on PATH — ThreatLens declares both as
# requires_capabilities (D-23); see tier1-mongoose/README.md.

uv run python benchmarks/run-tier1.py                      # full suite
uv run python benchmarks/run-tier1.py --scenario CVE-2023-34188  # one scenario
```

Output: a markdown report to stdout and `tier1-mongoose/REPORT.md`,
plus per-scenario raw run artefacts under each scenario's
`actual-runs/` (gitignored — regenerated every run, not committed).
