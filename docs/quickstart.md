---
tags:
  - tutorial
  - getting-started
---

# Getting started

This walks through installing Loupe, scaffolding the `.loupe/` directory in your repository, running a first CI invocation, and reading the output. It assumes you have Python 3.13 and `uv` (or `pip`) available.

## Before you begin

> [!WARNING]
> **Pre-alpha.** The platform, capability registry, CLI, and GitHub Action all exist, and the ThreatLens agent is wired to a live LLM. APIs and schemas may move before the v0.1 tag.

`loupe ci` invokes a PydanticAI agent against the provider you select in `.loupe/config.yaml` under `models.default` (Anthropic by default). Set the matching provider key in your environment (`ANTHROPIC_API_KEY` for the default; `OPENAI_API_KEY`, `GOOGLE_API_KEY`, and so on for alternatives — the scaffolded `config.yaml` lists the supported forms). Without a key, `loupe ci` records a `lens_error` entry on the run record and exits 1.

Run `loupe doctor` to confirm your environment is ready before the first `loupe ci`: it checks the provider key, the capability binaries on `PATH`, and that `context.md` has been filled in.

If you are evaluating Loupe for production use, expect token costs on every PR run. If you are exploring the architecture, run the steps below.

## Install

> [!NOTE]
> PyPI publishing lands with the v0.1 tag; see [CHANGELOG.md](changelog.md) for the release-process outline. Until then, install from source.

From source (pre-alpha, today):

```bash
git clone https://github.com/fadi-labib/loupe.git
cd loupe
uv sync --all-packages
```

This installs the four workspace packages (`loupe-core`, `loupe-cli`, `loupe-threatlens`, `loupe-action`) in editable mode. The `--all-packages` flag is required because Loupe is a uv workspace; without it, `uv sync` resolves only the root package and the CLI imports fail at runtime. Invoke the CLI through `uv run loupe …`.

Once v0.1 is published, the install simplifies to:

```bash
pip install loupe-cli loupe-threatlens
```

The GitHub Action wrapper (`loupe-action`) is part of the same workspace; nothing extra to install for it.

## Use it from another project

Pre-PyPI, the CLI runs out of the workspace venv. To invoke it against a *different* project on disk (any directory that is not the Loupe checkout), use `uv run --project` with the absolute path to your Loupe checkout:

```bash
# From your own project's root, with $LOUPE pointing at the Loupe checkout
cd ~/projects/my-product
uv run --project ~/projects/loupe loupe init                                                 # scaffold .loupe/
uv run --project ~/projects/loupe loupe doctor                                               # preflight after scaffolding
uv run --project ~/projects/loupe loupe ci --diff-file /tmp/pr.diff --base-sha main --head-sha HEAD
```

`loupe doctor` runs after `init` so its `.loupe/ exists` check passes; doctor itself never writes and is safe to re-run at any time.

Every `loupe` subcommand works the same way. Once v0.1 publishes to PyPI the `uv run --project` prefix collapses to just `loupe …`.

## Scaffold the repo

Inside your project root:

```bash
loupe init
```

This creates `.loupe/` with the minimum files Loupe expects:

```
.loupe/
├── config.yaml          # operator settings (capabilities, lenses, CI gates)
├── context.md           # your product description (human-authored)
├── knowledge.yaml       # persistent knowledge graph (scaffolded empty)
├── runs/                # hash-chained run records
└── decisions/           # ADR-style risk acceptances
```

`config.yaml` ships with sensible defaults: ThreatLens enabled at relevance threshold 0.3, the `agent_writable_paths` allow-list pointing at the standard ThreatLens artefact locations, a `ci.fail_on` gate, and a commented-out `capabilities:` skeleton you can uncomment to wire Syft / Grype / Gitleaks / Semgrep into the run. See [Configure the capabilities](#configure-the-capabilities) below for details.

`knowledge.yaml` is scaffolded as an empty graph (`schema_version: 1`, empty asset/element/decision lists) with a leading banner comment. Lens runs that promote high-confidence Facts append to it across invocations; you can delete the file at any time to reset.

`context.md` is your responsibility. Open it in an editor and fill in the marked sections.

```bash
$EDITOR .loupe/context.md
```

It asks for six things: product description, critical assets, users and roles, deployment topology, threat actors of concern, and out-of-scope items. Two or three sentences per section is enough. This file is the anti-hallucination anchor for every agent run; keep it accurate as the project changes.

The agent cannot edit `context.md` directly. It can only propose patches into `.loupe/.proposed/` for you to review. Same for `decisions/*.md` and `config.yaml`.

## Run on a diff locally

Compute a diff and feed it to Loupe.

```bash
git diff main... > /tmp/pr.diff
loupe ci \
  --diff-file /tmp/pr.diff \
  --base-sha "$(git rev-parse main)" \
  --head-sha HEAD
```

What happens:

1. The CLI bootstraps a `RunContext` from the diff, `context.md`, and `knowledge.yaml`.
2. The coordinator asks each enabled lens `is_relevant(ctx)` and skips anything below threshold.
3. Capability backends (Syft for SBOM, Grype for CVE, etc., per `capabilities:` in `config.yaml`) run once before any lens dispatches. Typed results land on `ctx.sbom`, `ctx.cve_findings`, etc.
4. Selected lenses run in topological order. ThreatLens's PydanticAI agent is called with the diff, the SBOM, the CVE list, and `context.md` as a stable-prefix prompt, and proposes threats through `propose_threat` tool calls.
5. A run record gets written to `.loupe/runs/<id>.json` with a SHA-256 hash chain pointing at the previous run.

Output ends with the lens names that ran and the path of the new run record.

## Read the output

The run record is the canonical artefact. It captures inputs (diff hash, context hash), which lenses considered the diff and which ran, models used, tokens consumed, cost estimate, artefacts changed, and the hash chain pointer. An auditor can replay history by walking `.loupe/runs/*.json` in chronological order and verifying each `self_hash`.

```bash
loupe verify
```

The command runs the four Layer 3 checks: hash-chain integrity across `.loupe/runs/*.json`, artefact schema consistency for each `threats.yaml` / `mitigations.yaml`, threats-to-mitigations cross-reference integrity, and (when invoked with `--strict`) protected-path authorship. It exits non-zero on the first failure.

The threats themselves are in `.loupe/threats.yaml`. Each threat has a stable ID (`T-NNN`), a STRIDE category, severity, status, links to the diff lines that introduced it, and a list of mitigation IDs.

## Run interactively

```bash
loupe chat
```

Runs in two modes:

- **Default** — runs the same in-process `loupe ci` pipeline first (so the session reviews fresh proposals), then walks each staged `.loupe/.proposed/<...>.patch` through a `[y/N/edit/skip]` prompt.
- **`--review-only`** — skips the ci run; reviews whatever is already in `.proposed/`.

For each proposal: `y` applies the patch via `git apply` and moves the `.patch` from `.proposed/` to `.applied/`. `skip` moves it to `.skipped/`. `edit` opens the diff in `$EDITOR`; on save, the modified diff is dry-run-checked and you confirm a second time before it applies. `N` (default) leaves the proposal in `.proposed/` for the next session.

Precondition: `.loupe/.proposed/` must be clean against `HEAD` before chat starts — commit your staged proposals with `git add .loupe/.proposed/ && git commit` first. See [D-26](reference/decisions.md#d-26) for why chat is the one documented git-write exception, and [Proposals](concepts/proposals.md) for the full `.proposed/` → `.applied/` / `.skipped/` lifecycle.

## Wire up the GitHub Action

In `.github/workflows/loupe.yml`:

```yaml
on:
  pull_request:

jobs:
  loupe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: loupe-action@v1
        with:
          pr: ${{ github.event.pull_request.number }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The Action fetches the PR's base SHA, head SHA, and unified diff through the GitHub API (so it works with shallow clones), runs `loupe ci`, and posts a sticky comment on the PR with severity-grouped findings. The comment edits in place across pushes; you do not get a graveyard of stale Loupe comments on long-running branches.

Six outputs are exposed for downstream steps:

| Output | What it is |
|---|---|
| `findings_count` | Total threats reported by this run |
| `findings_critical` / `findings_high` / `findings_medium` / `findings_low` | Per-severity counts |
| `run_id` | Matches `.loupe/runs/<id>.json` |
| `run_hash` | Self-hash of the run record |
| `exit_code` | 0 clean, 1 gate failed, 64 usage error |

The step fails with exit code 1 when severities listed in `config.yaml`'s `ci.fail_on` appear. Set `fail_on: [critical, high]` to fail on those and treat everything else as informational. Set `fail_on: []` for report-only mode.

## Configure the capabilities

`config.yaml` is where you express the team's audit posture. Two examples.

Belt-and-braces secret detection:

```yaml
capabilities:
  secret_detect:
    mode: union
    backends: [trufflehog, gitleaks]
```

Consensus-based SAST to suppress false positives:

```yaml
capabilities:
  static_analysis:
    mode: consensus
    consensus_threshold: 2
    backends: [semgrep, codeql, bandit]
```

Discovery subcommands:

```bash
loupe lens list   # show every registered lens
loupe cap list    # show every registered capability + backend pair
```

For programmatic introspection, you can still use:

```bash
python -c 'from importlib.metadata import entry_points; print(list(entry_points(group="loupe.lenses")))'
```

## What to expect, what not to expect

Expect three to five threats on a typical small PR, a cost of around $0.07–$0.20 per PR on Claude Opus, and roughly 30 seconds of wall time per PR. Cost numbers are illustrative; actual usage depends on diff size and model choice.

If `ANTHROPIC_API_KEY` (or the matching key for your `models.default`) is not set, `loupe ci` writes a `lens_error` entry on the run record and exits 1 — see [When something goes wrong](#when-something-goes-wrong) for the audit trail format.

## When something goes wrong

`.loupe/runs/<latest>.json` records every failure mode. If a capability backend fails (Syft not installed, Grype database missing), the run record marks it as `backend_error` and the lens that requested the capability is skipped. If a lens's tool call hits the path boundary, the run record marks it as `enforcement_error` and the lens is aborted but the run as a whole continues.

For live plan tracing during a run, add `--verbose` to `loupe ci` — the flag emits `[verbose] Considering lens X: dispatching` and `[verbose] Lens X complete (<tokens>, $<cost>)` lines as each lens runs. See [`reference/cli.md`](reference/cli.md#loupe-ci) for the full flag list.

For specific failure modes (missing provider key, scanner binary not on `PATH`, hash-chain break, VCR cassette mismatch, cost-cap refusal), see [`how-to/troubleshooting.md`](how-to/troubleshooting.md). For anything else, [`contributing.md`](contributing.md) describes how to file an issue and how to reproduce locally.

## See it on a real codebase

If you'd rather drive the same flow against an actual third-party project than scaffold against your own, follow the [ThreatLens on Mongoose](tutorials/threatlens-on-mongoose.md) tutorial. It walks through `loupe init`, a real MQTT-parser fix diff, and `loupe scan` end-to-end with expected outputs at every step — useful for sanity-checking your environment before pointing Loupe at code you actually care about.

> [!NOTE]
> **Both `ci` and `scan` are source-grounded.** `loupe ci --diff-file <patch>` sends the diff bytes; `loupe scan --paths <file-or-dir>` walks the paths, expands directories by `CODE_EXTENSIONS`, and reads each file via the same Layer-1 boundary that protects writes (see [D-24](reference/decisions.md#d-24)). Files larger than the per-file cap truncate with a visible marker; `--max-chars-per-file` tightens or relaxes the default 50,000.
