---
tags:
  - how-to
  - troubleshooting
---

# Troubleshooting

The failure modes a fresh user hits most often, with the diagnostic command in each case. Run `loupe doctor` first; most of these reproduce in its output.

## Provider key not recognised

Symptom: `loupe doctor` reports `provider key (<name>): missing` or `loupe ci` writes a `lens_error` entry to the run record and exits 1.

Cause: the env var matching `models.default` in `.loupe/config.yaml` is not set in the shell that ran `loupe`. The default is Anthropic, so the env var is `ANTHROPIC_API_KEY`; if you switched to `openai:gpt-5` it's `OPENAI_API_KEY`, and so on.

Fix:

```bash
export ANTHROPIC_API_KEY="sk-ant-…"          # or the matching var for your provider
loupe doctor                                  # confirm it's seen
```

If `doctor` still reports missing after `export`, you're shelling out from a process that doesn't inherit the env (a `cron` job, a different terminal tab, `systemd` unit, etc.). Source from the same shell that runs `loupe`.

## Capability binary missing on `PATH`

Symptom: `loupe ci` finishes but a `runs/<id>.json` lens entry has `backend_error: backend 'syft' not found`. The lens that needed that capability is skipped but the run as a whole continues.

Cause: the bundled backends (Syft, Grype, gitleaks, TruffleHog, detect-secrets, Semgrep, CodeQL, Bandit, osv-scanner, cdxgen) are external binaries Loupe expects on `PATH`; `uv sync --all-packages` installs Loupe itself, not these tools.

Fix: install the binary the run wanted, or change the lens's `requires_capabilities` to a backend you do have. For Syft:

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
syft --version                                 # confirm
loupe doctor                                   # confirms via the "required capabilities" check
```

Backend-by-backend install instructions sit in each project's own README; the [`Capabilities` concept page](../concepts/capabilities.md) explains the abstraction.

## `.loupe/` directory not found

Symptom: `loupe ci` exits 64 with `error: .loupe/ not found in current directory`.

Cause: `loupe ci` reads `.loupe/config.yaml`, `.loupe/context.md`, and `.loupe/knowledge.yaml`. None of these exist until you run `loupe init`.

Fix:

```bash
cd /path/to/your/project                       # the project you want analysed, NOT the Loupe checkout
loupe init                                     # scaffolds .loupe/
$EDITOR .loupe/context.md                      # fill the six sections; see Quickstart for the shape
```

## `context.md` left with placeholder text

Symptom: ThreatLens produces low-quality or generic threats unrelated to your code.

Cause: `loupe init` scaffolds `context.md` with `TODO:` placeholders. If they survive into the run, the agent is anchoring on "TODO: describe your product" instead of your actual product. The anti-hallucination anchor only works if it's accurate.

Fix:

```bash
grep -n "^TODO" .loupe/context.md              # any hit means a section wasn't filled
$EDITOR .loupe/context.md
```

Two or three concrete sentences per section is enough. Names, frameworks, and versions help the agent more than adjectives.

## Empty diff produces no findings

Symptom: `loupe ci --diff-file empty.diff` exits 0 with zero findings, even on a repository you know has issues.

Cause: `loupe ci` is diff-shaped, not repo-shaped. It analyses the *change*, not the whole codebase. An empty diff has nothing to analyse.

Fix: for a one-shot full-repo analysis, use `loupe scan` instead:

```bash
loupe scan --paths src/                        # source-grounded, reads files
loupe scan --paths . --budget-usd 5.00         # hard cap on worst-case cost
```

`scan` walks the paths, reads source via the same Layer 1 boundary that protects writes, and produces threats the same way as `ci`. See [D-15](../reference/decisions.md#d-15) for the design trade-off and `scan`'s self-limits.

## `loupe verify` fails on the hash chain

Symptom: `loupe verify` exits non-zero with `hash chain broken at runs/<id>.json: prev_self_hash does not match prior run's self_hash`.

Cause: someone rewrote git history across a `runs/` commit (rebase, amend, force-push), or an editor wrote to a `runs/*.json` after Loupe sealed it. The hash chain is designed to detect exactly this; it's working as intended.

Fix:

```bash
git log --diff-filter=M .loupe/runs/           # who modified a sealed run record?
git log --follow .loupe/runs/<id>.json         # what happened to this one specifically?
```

If the rewrite was intentional (history cleanup before the repo opened), the only honest move is to delete the affected run records and let Loupe re-run on the next PR. Forging a continuation hash is detectable on replay; the chain's whole point is that you cannot.

## VCR cassette tests fail locally

Symptom: `uv run pytest packages/loupe-threatlens/` fails with `vcr.errors.CannotOverwriteExistingCassetteException` or `AssertionError: cassette appears to leak '<needle>'`.

Cause (overwrite error): you changed the ThreatLens prompt body. The VCR `match_on` includes the request body, so a prompt change is, correctly, a cassette mismatch. The cassette was recorded against the old prompt and replay no longer matches.

Cause (leak error): the cassette contains a string that looks like an API key or auth header. The `conftest.py` filter is supposed to strip these before recording; either the filter regressed or a needle the project tracks (`sk-ant-`, header names) landed in the cassette text.

Fix:

```bash
export ANTHROPIC_API_KEY="sk-ant-…"
mv packages/loupe-threatlens/tests/cassettes/<file>.yaml{,.stale}
uv run pytest packages/loupe-threatlens/tests/test_agent_run.py --record-mode=once
uv run pytest packages/loupe-threatlens/tests/test_cost_regression.py    # confirms tokens stay under budget
rm packages/loupe-threatlens/tests/cassettes/*.stale
```

Each re-record spends ~$0.05 against the live API. The cost-regression fixture catches prompt drift that blows the token budget.

## Cost-cap refusal: `loupe scan` exits 64 with "estimated cost exceeds budget"

Symptom: `loupe scan --paths . --budget-usd 1.00` refuses to run before any LLM call happens.

Cause: the `--budget-usd <N>` flag triggers a pre-flight worst-case estimate — `sum across planned lenses of per_run_max_tokens_in × input-price + per_run_max_tokens_out × output-price`. If the estimate exceeds the budget, the scan exits before spending anything. This is intentional (D-15); the conservative estimate means real-run cost is typically lower than the gate threshold, but the gate refuses to gamble.

Fix:

```bash
loupe scan --paths src/<narrower-scope>        # smaller scope means smaller estimate
loupe scan --paths . --budget-usd 5.00         # raise the cap if you accept the worst case
```

The exact estimate formula and per-mode defaults are in [D-10](../reference/decisions.md#d-10) and the `pricing.py` snippet block in [Pricing reference](../reference/pricing.md).

## Still stuck

If none of the above matches your failure mode, capture the smallest reproduction (a `runs/<id>.json` plus your `.loupe/config.yaml` is usually enough) and follow the steps in [`contributing.md`](../contributing.md#filing-issues-proposing-changes).
