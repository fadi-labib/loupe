---
tags:
  - concept
  - proposals
  - layer-4
---

# Proposals

The mechanism by which the agent can suggest changes to files it is not allowed to write directly. Every change to a protected path (`context.md`, `decisions/*.md`, `config.yaml`, source code outside the agent-writable allow-list) lands as a staged diff for the human to accept, edit, or reject. There is no "write the file and ask forgiveness" path.

## The two write tools

The agent has exactly two ways to put bytes on disk:

| Tool | Writes to | Used for |
|---|---|---|
| `write_agent_artifact` | `.loupe/` paths in the operator's `agent_writable_paths` allow-list | Files the agent owns end-to-end: `threats.yaml`, `mitigations.yaml`, generated narrative `*.md` |
| `propose_patch` | `.loupe/.proposed/<encoded-target>/<run_id>.patch` | Everything else: `context.md`, `decisions/*.md`, `config.yaml`, source files |

`propose_patch` refuses to write to an agent-writable path (so the agent cannot trick its way out of the allow-list by routing through `.proposed/`) and refuses absolute paths, `..` traversal, and NUL bytes in the target. See `propose_patch` in `packages/loupe-core/loupe_core/tools.py:108-138` for the validator chain.

## Anatomy of one proposal

A proposal is a single `.patch` file written by `propose_patch`. Its on-disk path encodes the target file the diff applies to:

```
.loupe/.proposed/<encoded-target>/<run_id>.patch
```

The encoding replaces `/` with `_` and preserves the leading dot, so `.loupe/context.md` becomes `.loupe_context.md` (not `_loupe_context.md`). Each `<run_id>` directory may contain one or more `.patch` files if the same target was touched across multiple runs.

The `.patch` file itself is a small header followed by a standard unified diff:

```diff
# Proposed patch for .loupe/context.md
# Rationale: surface the new /api/refund endpoint added in PR 1234
# Run: 2026-05-20T14-32-01-abc123
---
--- a/.loupe/context.md
+++ b/.loupe/context.md
@@ -12,6 +12,10 @@
 ## Critical assets
 - Payment authorisation tokens
 - PII (name, email, address)
+
+## Recently changed surfaces
+- POST /api/refund (added in PR 1234, no current rate limit)
```

The header lines are comments; the unified diff after `---` is what `git apply` consumes.

## Three resting states

```mermaid
flowchart LR
    propose["propose_patch()"]
    proposed[".loupe/.proposed/<...>/.patch"]
    review["loupe chat<br/>[y/N/edit/skip]"]
    applied[".loupe/.applied/"]
    skipped[".loupe/.skipped/"]

    propose --> proposed
    proposed --> review
    review -->|y / edit + confirm| applied
    review -->|skip| skipped
    review -->|N (default)| proposed
```

`.proposed/` is the staging area. Each `.patch` file sits there until a human reviews it.

`.applied/` holds patches that were accepted and successfully applied. `loupe chat` runs `git apply <patch>` against the target file and `git mv` on the patch file itself; the diff is now in your working tree alongside the moved patch record. You decide when to commit.

`.skipped/` holds patches that were explicitly rejected. `loupe chat` `git mv`s the patch without applying it. The patch survives as audit-trail evidence that the agent suggested something and the human said no.

A patch that received no answer (the human pressed `N` or hit `Ctrl-C`) stays in `.proposed/` for the next session.

## How `loupe chat` walks them

`loupe chat` is a TTY-only REPL. On entry, it lists every `.patch` file under `.loupe/.proposed/` and prompts for each one:

```text
Proposal 1/3: .loupe/context.md
  Rationale: surface the new /api/refund endpoint added in PR 1234

  --- a/.loupe/context.md
  +++ b/.loupe/context.md
  @@ -12,6 +12,10 @@
   ## Critical assets
  …
  +## Recently changed surfaces
  +- POST /api/refund (added in PR 1234, no current rate limit)

Apply? [y/N/edit/skip]:
```

| Response | What happens |
|---|---|
| `y` | `git apply <patch>` against the target, then `git mv` the `.patch` from `.proposed/` to `.applied/` |
| `N` (default; also blank line) | Leave the patch in `.proposed/` for next session |
| `edit` | Open the patch in `$EDITOR`. On save, dry-run-validate with `git apply --check`. If it passes, prompt `Apply edited? [y/N]`; if no, return to top |
| `skip` | `git mv` the `.patch` from `.proposed/` to `.skipped/` without applying |

No `--auto-confirm`, no `--yes`, no env var that lowers the bar. The TTY guard at `chat_cmd.py:_stdin_is_tty()` refuses to run from a pipe or non-interactive shell, so `loupe chat <<< 'y\ny\ny\n'` does not work.

## Why a git-write exception

`loupe chat` is the one and only documented git-write exception in the runtime ([D-26](../reference/decisions.md#d-26)). Loupe-core is git-free; the CLI's other commands never invoke git. `chat` calls `git apply` and `git mv` because that is functionally equivalent to a human typing the same commands by hand at the same TTY they are reviewing the diff from.

The exception is scoped: chat only touches `.loupe/` paths and only when the user just answered `y` at the prompt for that specific patch. The agent never runs git; the platform never runs git in CI; only the human-driven chat REPL does.

The Action's auto-commit pipeline is a separate exception covered in [D-27](../reference/decisions.md#d-27) and constrained by Layer 2's PAT scope.

## Preconditions and gotchas

`loupe chat` requires `.loupe/.proposed/` to be clean against `HEAD` before it starts. If you ran `loupe ci` and have unstaged `.patch` files in `.proposed/`, commit them first:

```bash
git add .loupe/.proposed/ && git commit -m "stage loupe proposals from PR 1234"
loupe chat
```

The reason is that `git mv` (used to move accepted/rejected patches between dirs) cannot operate on untracked files. Committing the staged proposals also gives you a clear audit trail of which run produced which patch, separate from the answer the human gave.

## See also

- [`docs/reference/cli.md#loupe-chat`](../reference/cli.md#loupe-chat) — flag reference and exit codes
- [D-08](../reference/decisions.md#d-08) — the four-layer write boundary that makes `.proposed/` the right shape
- [D-26](../reference/decisions.md#d-26) — the `.loupe/`-only git-write exception
