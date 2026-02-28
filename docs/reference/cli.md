# CLI reference

Every command Loupe currently registers, with its flags, exit codes, and what it actually does. Sourced from `packages/loupe-cli/loupe_cli/__main__.py` and the per-command modules; treat that source as authoritative if this page drifts.

## Top-level invocation

```
loupe <command> [OPTIONS]
```

The five commands registered today: `init`, `ci`, `verify`, `chat`, `scan`. Two more are designed but not yet registered: `mcp` (Model Context Protocol server) and discovery subcommands (`lens list`, `cap list`).

## `loupe init`

Scaffold a `.loupe/` directory in the current working directory.

```
loupe init
```

No flags today.

Creates:

- `.loupe/config.yaml` — operator settings with sensible defaults (ThreatLens enabled at `minimum_relevance: 0.3`, `agent_writable_paths` for the standard ThreatLens artefacts, `ci.fail_on: [critical, high]`).
- `.loupe/context.md` — human-authored project description with TODO placeholders the user fills in.
- `.loupe/knowledge.yaml` — empty knowledge graph.
- `.loupe/runs/` — directory for hash-chained run records.
- `.loupe/decisions/` — directory for ADR-style human risk acceptances.

Exit codes: `0` on success. Errors (already exists, permission denied) propagate as Typer's default exit codes.

## `loupe ci`

Run Loupe in CI mode against a unified diff. The non-interactive entry point.

```
loupe ci [--pr <number>] [--diff <text> | --diff-file <path>]
         [--base-sha <sha>] [--head-sha <sha>]
         [--config <path>]
```

| Flag | Default | What it does |
|---|---|---|
| `--pr` | `None` | Pull request number, informational only; recorded in the run record |
| `--diff` | `""` | Unified diff text passed inline (used by tests; the action passes via `--diff-file`) |
| `--diff-file` | `None` | Path to a unified-diff file; mutually exclusive with `--diff` in practice |
| `--base-sha` | `None` | Base SHA of the diff; recorded for the audit trail |
| `--head-sha` | `None` | Head SHA of the diff; recorded for the audit trail |
| `--config` | `.loupe/config.yaml` | Path to the project's `LoupeConfig` file |

Behaviour:

1. Bootstraps a `RunContext` from the diff, `context.md`, and `knowledge.yaml`.
2. Asks each enabled lens `is_relevant(ctx)` and filters by `minimum_relevance`.
3. Runs surviving lenses in topological order against `requires_lenses`.
4. Writes the run record to `.loupe/runs/<id>.json` with the SHA-256 hash chain.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Clean run; no `ci.fail_on` severities triggered |
| 1 | Gate failure: at least one threat at a `ci.fail_on` severity was reported |
| 2 | Usage or environment error (e.g., `.loupe/` not found in cwd) |

`--verbose` for plan tracing is documented in the design but not yet implemented.

## `loupe verify`

Verify Loupe state integrity.

```
loupe verify
```

No flags today.

Today it checks one thing: hash-chain integrity across `.loupe/runs/*.json`. Each record's `self_hash` must match the SHA-256 of its content (excluding the `self_hash` field), and `prev_run_hash` must match the previous record's `self_hash`.

Exit codes: `0` if the chain validates; non-zero on the first tamper signal.

Future checks (documented in `verify_cmd.py` as planned, not yet implemented):

- Authorship of protected paths (`context.md`, `decisions/`, `config.yaml` must not be touched by an agent identity).
- Schema consistency: every artefact parses with its Pydantic model.
- Threats-to-mitigations cross-reference integrity.
- A `--strict` flag that runs additional checks beyond the default set.

## `loupe chat`

Interactive Loupe session.

```
loupe chat
```

No flags today.

Currently prints a placeholder message that the conversational REPL is a v1.x feature and exits. The TTY guard is in place: the command refuses to run with stdin redirected, so accidental unattended runs cannot happen.

Once implemented, the design is:

- Same pipeline as `loupe ci`, but every protected-path proposal pauses for a `[y/N/edit/skip]` confirmation with default-N.
- No `--auto-confirm` flag and no environment variable that lowers the bar.

Exit codes today: `0` on the placeholder exit; `2` if not a TTY.

## `loupe scan`

Full-repo scan, no diff required. Used for onboarding, periodic re-baseline, audit-prep runs.

```
loupe scan [--paths <path> ...] [--config <path>]
```

| Flag | Default | What it does |
|---|---|---|
| `--paths` | `[]` | Limit the scan to these paths (repeatable). Empty list means full repository |
| `--config` | `.loupe/config.yaml` | Path to the `LoupeConfig` file |

Behaviour:

- Sets `RunContext.scope` to `"full"` (no `--paths`) or `"scoped"` (with `--paths`). See D-15 in the decision log.
- When scope is not `"diff"`, the coordinator overrides each lens's relevance score and includes every enabled lens. Each lens's `is_relevant()` still gets called for the reason string but does not affect inclusion.
- Cost: full-repo runs are significantly more expensive than diff runs. The `--budget-usd <N>` flag described in D-15 is planned but not yet wired.

Exit codes: same scheme as `loupe ci`.

## Commands not yet registered

The following are part of the CLI design but not in `__main__.py`:

| Command | Status | Source of truth in the meantime |
|---|---|---|
| `loupe mcp` | MCP server, designed | Concept page; no implementation |
| `loupe lens list` | Discovery, designed | `python -c 'from importlib.metadata import entry_points; print(list(entry_points(group="loupe.lenses")))'` |
| `loupe cap list` | Discovery, designed | Same incantation with `loupe.capabilities` |
| `loupe ci --verbose` | Plan tracing, designed | None |
| `loupe verify --strict` | Wider verification set, designed | None |
| `loupe scan --budget-usd <N>` | Cost cap for full-repo runs, designed in D-15 | None |

## Environment variables

| Variable | Used by | Purpose |
|---|---|---|
| `THREATLENS_MODEL` | `loupe-threatlens` | LLM provider+model identifier; e.g., `anthropic:claude-opus-4-7`, `openai:gpt-5`, `google-gla:gemini-2.5-pro`, `ollama:llama-3.3-70b` |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GOOGLE_API_KEY` | The configured LLM provider | Auth for the LLM call. Never read by Loupe itself; only by PydanticAI's transport |
| `AI_GATEWAY_API_KEY` | The Vercel AI Gateway provider option | Optional |
| `INPUT_PR`, `INPUT_CONFIG`, `INPUT_COMMENT_MODE`, `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `GITHUB_WORKSPACE`, `GITHUB_OUTPUT`, `GITHUB_API_URL` | `loupe-action` entrypoint | See [`reference/data-handling.md`](data-handling.md) and `action.yml` |
