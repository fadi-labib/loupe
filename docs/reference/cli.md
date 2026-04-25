---
tags:
  - reference
  - cli
---

# CLI reference

Every command Loupe currently registers, with its flags, exit codes, and what it actually does. Sourced from `packages/loupe-cli/loupe_cli/__main__.py` and the per-command modules; treat that source as authoritative if this page drifts.

## Top-level invocation

```
loupe <command> [OPTIONS]
```

The six top-level commands today: `init`, `ci`, `verify`, `chat`, `scan`, `mcp`. Two command groups provide discovery: `loupe lens list` and `loupe cap list`.

> [!NOTE]
> A handful of flags remain designed but not yet implemented (`loupe ci --verbose`, `loupe scan --budget-usd <N>`). See [Flags not yet wired](#flags-not-yet-wired) at the bottom.

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
loupe verify [--strict]
```

Flags:

| Flag | Default | What it does |
|---|---|---|
| `--strict` | (off) | Run additional protected-path authorship checks (`context.md`, `decisions/*.md`, `config.yaml` must not have been last touched by an agent identity). |

Today's checks (all wired in `loupe_core/enforcement/verify.py`):

1. **Hash-chain integrity** across `.loupe/runs/*.json`. Each record's `self_hash` must match the SHA-256 of its content (excluding the `self_hash` field), and `prev_run_hash` must match the previous record's `self_hash`.
2. **Artefact schema consistency**: every `threats.yaml` / `mitigations.yaml` parses with its Pydantic model.
3. **Threats-to-mitigations cross-references**: every `mitigation_ids` entry on a threat resolves to a real mitigation, and every `threats_addressed` on a mitigation resolves to a real threat.
4. **Protected-path authorship** (strict mode): `context.md`, `decisions/*.md`, `config.yaml` must not have been last touched by an agent-identity author.

Exit codes: `0` if all checks pass; non-zero on the first failure.

Without `--strict`, the three default checks (hash chain, artefact schemas, threats↔mitigations cross-references) run. With `--strict`, the additional protected-path authorship check also runs.

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

## `loupe mcp`

Start a Model Context Protocol server over stdio so editors, IDEs, and other MCP clients can read Loupe state — and, when configured, propose new threats/mitigations through Layer-1-gated write tools.

```
loupe mcp [--loupe-dir <path>]
```

| Flag | Default | What it does |
|---|---|---|
| `--loupe-dir` | `.loupe` (cwd-relative) | Path to the project's `.loupe/` directory. The server resolves config, artefacts, and the agent's write boundary against this directory. |

Behaviour:

- Loads `<loupe-dir>/config.yaml` (when present) to read `agent_writable_paths`; that list becomes the `PathBoundary` for write tools.
- Registers **read tools** unconditionally: `list_threats`, `query_by_severity`, `latest_run`, plus a per-lens summary tool when a lens is installed.
- Registers **write tools** only when the boundary loaded cleanly: `threatlens_propose_threat`, `threatlens_propose_mitigation`. Every write goes through `PathBoundary` exactly as the in-CI agent does, so protected paths (`context.md`, `decisions/*.md`, `config.yaml`) are mechanically refused. See [D-22](decisions.md#d-22) for the rationale.
- Transport is JSON-RPC 2.0 over stdio (the standard MCP framing). HTTP+SSE is recorded in the roadmap; not yet wired.

Exit codes: `0` on a clean shutdown; `64` on a config error (`EX_USAGE` — for example, a malformed `agent_writable_paths` entry); `1` on an unhandled exception during the run loop. Errors are written to stderr; stdout is reserved for the protocol stream.

## `loupe lens list`

Print every lens discovered through the `loupe.lenses` entry-point group.

```
loupe lens list
```

No flags today. Output is a fixed-width table with one row per registered lens (`NAME`, `DOMAIN`, `REQUIRES`). The `REQUIRES` column flattens the lens's `requires_lenses` and `requires_capabilities` declarations, so an operator can confirm at a glance what tooling each lens expects.

Exit codes: `0` on a clean enumeration (including the empty case — a message points at the discovery troubleshooting steps); non-zero only on an environment error reading the entry-point metadata.

## `loupe cap list`

Print every capability backend discovered through the `loupe.capabilities` entry-point group, grouped by capability category.

```
loupe cap list
```

No flags today. Output is grouped by category (`sbom`, `cve`, `secret_detect`, `static_analysis`) with one indented line per backend (`NAME`, dotted import path). Backends whose underlying tool is missing from `PATH` still appear; only the runtime registry's `is_available()` filter hides them at run time.

Exit codes: same scheme as `loupe lens list`.

## Flags not yet wired

A small set of flags are part of the design but not yet implemented:

| Flag | Status | Source of truth in the meantime |
|---|---|---|
| `loupe ci --verbose` | Plan tracing, designed | None |
| `loupe scan --budget-usd <N>` | Cost cap for full-repo runs, designed in D-15 | None |

## Environment variables

### CLI env vars

| Variable | Used by | Purpose |
|---|---|---|
| `THREATLENS_MODEL` | `loupe-threatlens` | LLM provider+model identifier (see provider-specific examples below) |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GOOGLE_API_KEY` | The configured LLM provider | Auth for the LLM call. Never read by Loupe itself; only by PydanticAI's transport |
| `AI_GATEWAY_API_KEY` | The Vercel AI Gateway provider option | Optional |

### Action env vars

Set automatically by `action.yml` when invoked through the GitHub Action; you do not set these by hand.

| Variable | Purpose |
|---|---|
| `INPUT_PR`, `INPUT_CONFIG`, `INPUT_COMMENT_MODE` | Action inputs passed via `with:` in the workflow |
| `GITHUB_TOKEN` | API auth for PR fetch + sticky comment |
| `GITHUB_REPOSITORY`, `GITHUB_WORKSPACE`, `GITHUB_OUTPUT`, `GITHUB_API_URL` | Standard GitHub-Actions runner env vars |

See [`data-handling.md`](data-handling.md) for what is actually transmitted.

### Switching LLM providers

The `THREATLENS_MODEL` identifier follows PydanticAI's format: `<provider>:<model>`. Set the matching API key env var.

=== "Anthropic"

    ```bash
    export THREATLENS_MODEL='anthropic:claude-opus-4-7'
    export ANTHROPIC_API_KEY='sk-ant-...'
    ```

=== "OpenAI"

    ```bash
    export THREATLENS_MODEL='openai:gpt-5'
    export OPENAI_API_KEY='sk-...'
    ```

=== "Google"

    ```bash
    export THREATLENS_MODEL='google-gla:gemini-2.5-pro'
    export GOOGLE_API_KEY='...'
    ```

=== "Ollama (local)"

    ```bash
    export THREATLENS_MODEL='ollama:llama-3.3-70b'
    # No API key. The OLLAMA_HOST env var (default http://localhost:11434)
    # determines where the local Ollama server is listening.
    ```

=== "Vercel AI Gateway"

    ```bash
    # The Gateway speaks the OpenAI API shape, so PydanticAI can route to it
    # with the openai provider plus an alternate base URL.
    export THREATLENS_MODEL='openai:gpt-5'
    export AI_GATEWAY_API_KEY='...'
    export OPENAI_BASE_URL='https://gateway.ai.vercel.com/...'
    ```
