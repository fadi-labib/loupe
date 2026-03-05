---
tags:
  - tutorial
  - getting-started
---

# Getting started

This walks through installing Loupe, scaffolding the `.loupe/` directory in your repository, running a first CI invocation, and reading the output. It assumes you have Python 3.13 and `uv` (or `pip`) available.

## Before you begin

> [!WARNING]
> **Pre-alpha.** The platform, capability registry, CLI, and GitHub Action all exist. The PydanticAI agent inside ThreatLens is scaffolded but not yet wired to a live LLM. `loupe ci` will currently run the full pipeline (parse diff, run capabilities, build run record) and emit a stub threats file, not real STRIDE analysis.

If you are evaluating Loupe for production use, wait for the agent wiring to land. If you are exploring the architecture, run the steps below.

## Install

> [!NOTE]
> PyPI publishing lands with the v0.1 tag; see [CHANGELOG.md](changelog.md) for the release-process outline. Until then, install from source.

From source (pre-alpha, today):

```bash
git clone https://github.com/fadilabib/loupe.git
cd loupe
uv sync --all-packages
```

This installs the four workspace packages (`loupe-core`, `loupe-cli`, `loupe-threatlens`, `loupe-action`) in editable mode. Invoke the CLI through `uv run loupe …`.

Once v0.1 is published, the install simplifies to:

```bash
pip install loupe-cli loupe-threatlens
```

The GitHub Action wrapper (`loupe-action`) is part of the same workspace; nothing extra to install for it.

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

`config.yaml` ships with sensible defaults: ThreatLens enabled at relevance threshold 0.3, the `agent_writable_paths` allow-list pointing at the standard ThreatLens artefact locations, and a `ci.fail_on` gate. The capability registry exists in the codebase (see `concepts/capabilities.md`) but the default `config.yaml` does not yet wire its backends into the CI flow; that wiring lands when the ThreatLens agent goes live against an LLM.

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

What happens today:

1. The CLI bootstraps a `RunContext` from the diff, `context.md`, and `knowledge.yaml`.
2. The coordinator asks each enabled lens `is_relevant(ctx)` and skips anything below threshold.
3. Selected lenses run in topological order. ThreatLens runs its scaffolded pipeline; the LLM step is stubbed.
4. A run record gets written to `.loupe/runs/<id>.json` with a SHA-256 hash chain pointing at the previous run.

What will happen once the agent wiring lands:

5. The capability bootstrap pass runs the configured SBOM and CVE backends once before any lens executes. Typed results land on `ctx.sbom` and `ctx.cve_findings` for every lens to read.
6. ThreatLens's PydanticAI agent gets called with the diff, the SBOM, the CVE list, and `context.md` as a stable-prefix prompt, then proposes threats through `propose_threat` tool calls.

Output ends with the lens names that ran and the path of the new run record.

## Read the output

The run record is the canonical artefact. It captures inputs (diff hash, context hash), which lenses considered the diff and which ran, models used, tokens consumed, cost estimate, artefacts changed, and the hash chain pointer. An auditor can replay history by walking `.loupe/runs/*.json` in chronological order and verifying each `self_hash`.

```bash
loupe verify
```

Today the command checks one thing: the hash-chain integrity across `.loupe/runs/*.json`. It exits non-zero on the first tamper signal. Authorship of protected paths, schema consistency of each artefact, and threats-to-mitigations cross-reference integrity are documented as Layer 3 checks but not yet implemented; they land in subsequent commits.

The threats themselves are in `.loupe/threats.yaml` once ThreatLens emits any. Each threat has a stable ID (`T-NNN`), a STRIDE category, severity, status, links to the diff lines that introduced it, and a list of mitigation IDs.

## Run interactively

```bash
loupe chat
```

> [!NOTE]
> **Not yet shipped.** The command currently prints a placeholder saying the conversational REPL is a v1.x feature.

The TTY guard is in place (the command refuses to run with stdin redirected) but the conversational pipeline that drives lenses with `[y/N/edit/skip]` confirmation prompts has not been wired. Tracked alongside the MCP server as part of the second-frontend work.

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

Discovery subcommands (`loupe lens list`, `loupe cap list`) are designed but not yet registered. For now, the source of truth for what is installed is the entry-points: `python -c 'from importlib.metadata import entry_points; print(list(entry_points(group=\"loupe.lenses\")))'` and the same for `loupe.capabilities`.

## What to expect, what not to expect

Until the agent wiring lands, you will see the pipeline run, the run records appear, and the GitHub Action comment post. The threat list will be empty or stubbed. That is expected.

When the agent wiring lands, expect three to five threats on a typical small PR, a cost of around $0.07–$0.20 per PR on Claude Opus, and roughly 30 seconds of wall time per PR. Cost numbers are illustrative; actual usage depends on diff size and model choice.

## When something goes wrong

`.loupe/runs/<latest>.json` records every failure mode. If a capability backend fails (Syft not installed, Grype database missing), the run record marks it as `backend_error` and the lens that requested the capability is skipped. If a lens's tool call hits the path boundary, the run record marks it as `enforcement_error` and the lens is aborted but the run as a whole continues.

Richer flags (`loupe ci --verbose` for plan tracing, `loupe verify --strict` for a wider set of consistency checks) are documented in the CLI design but not yet implemented. Today's `loupe ci` and `loupe verify` only carry the flags shown earlier in this page.

For anything beyond that, [`contributing.md`](contributing.md) describes how to file an issue and how to reproduce locally.
