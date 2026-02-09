# Loupe — Data Handling

> Every security or compliance team evaluating Loupe will ask: "what does this tool send out of my environment, and to whom?" This document answers that — directly, with the relevant code references, so you can verify rather than trust.

## TL;DR

- **Loupe is local-first.** All artefacts live in your repo as plain files. There is no Loupe-hosted backend, no telemetry, no cloud database. Git is your audit substrate.
- **Loupe makes outbound network calls to exactly one endpoint per run**: the LLM provider you configure (Anthropic, OpenAI, Google, etc.). It does not phone home to any "Loupe" service, because no such service exists.
- **What gets sent to the LLM**: the contents of `.loupe/context.md`, the unified diff (in diff mode) or selected file paths/excerpts (in full-repo mode), the SBOM delta summary, a filtered slice of the persistent knowledge graph, and the lens's task instructions.
- **What does NOT get sent**: API keys, environment variables, file contents that aren't in the diff (unless a tool explicitly reads them), credentials, secrets, anything outside `.loupe/` and the diff.
- **Run records** (`.loupe/runs/*.json`) store **hashes** of inputs, not verbatim prompts. The audit trail is reproducible from in-repo state, not from stored transcripts.

---

## Outbound network calls

Loupe makes exactly one kind of outbound call: HTTPS to the LLM provider configured by `THREATLENS_MODEL` (or per-lens overrides in `config.yaml`).

| Endpoint | When | What's sent |
|---|---|---|
| `https://api.anthropic.com/v1/messages` (or equivalent for other providers) | Each lens LLM call during a run | The assembled prompt (system + user messages); tool schemas; conversation history within the run |
| `https://gateway.ai.vercel.com/...` (if configured) | Same, routed via Vercel AI Gateway | Same content; the gateway is a transparent proxy |
| `https://api.osv.dev/...`, `https://nvd.nist.gov/...` (via osv-scanner/grype subprocess) | Once per run, only when SBOM delta exists | The list of package + version pairs; **not** code |
| **No other endpoints** | — | — |

There is **no** Loupe-hosted analytics, telemetry, usage reporting, or "phone home." If you want to verify this, the entire network surface lives in:

- `loupe_core/agent.py` (LLM calls, via PydanticAI)
- `loupe_core/sbom.py` (Syft / Grype / osv-scanner subprocess; these are open-source tools you can audit independently)
- `loupe_core/vcs/github.py` (only when CI mode pushes a proposal branch; uses your GitHub App token; only `git` and `gh` subprocesses)

You can verify this with `grep -r "httpx\|requests\|urllib\|aiohttp" packages/` — only PydanticAI's transport layer should appear.

---

## What goes into an LLM prompt

The prompt is structured into a **stable prefix** (cache-friendly, paid once per run) and a **variable suffix** (per-lens task).

### Stable prefix (sent to the LLM with every lens call in a run)

| Content | Source | Why |
|---|---|---|
| Common system framing | `loupe_core/prompts/` | Loupe's general agent persona |
| `.loupe/context.md` content | Your human-authored project description | Anti-hallucination anchor |
| Diff summary (in diff mode) | `git diff` output | What changed |
| SBOM delta summary | Syft output diffed | What dependencies changed |
| Selected slice of `knowledge.yaml` | The knowledge graph entries relevant to this diff | Cross-run continuity |
| Lens-specific framing | The lens's `prompts/system.md` | E.g., ThreatLens's STRIDE framing |

### Variable suffix (per-lens, not cached)

| Content | Source |
|---|---|
| The lens's task for this invocation | Coordinator's planning output |
| Prior findings from earlier lenses in this run | `RunContext.findings` (only those relevant to this lens) |

### What is NOT in the prompt

- **File contents that aren't in the diff.** The agent only sees code that appears in the unified diff. To read other files, it must explicitly call a tool that returns the contents — which (a) is logged, (b) is bounded by tool implementation, (c) does not exist in v1 (no `Read` tool; ThreatLens's tools take typed input, not arbitrary file paths).
- **API keys.** Authentication is via the `Authorization` header, which never appears in any prompt or artefact.
- **Environment variables** other than the ones the agent's tool implementations explicitly read (currently: only `THREATLENS_MODEL` and provider API key env vars).
- **CI/CD secrets.** Same as env vars — never marshalled into prompts.
- **Anything in `.git/`** (commit messages, signing keys, hooks).
- **Anything outside the repo** (the home directory, system files, etc.).

---

## API key handling

| Where API keys come from | How |
|---|---|
| Local CLI usage | Standard provider env vars: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`, `AI_GATEWAY_API_KEY`. Loupe reads them via `os.environ` at agent startup. |
| CI usage | The workflow exposes them via GitHub Actions secrets: `env: ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}`. They never appear in workflow logs (GitHub auto-redacts secret values). |
| Tests | Tests **never** require API keys. Integration tests use VCR cassettes; the cassettes themselves are scrubbed of `Authorization` headers before commit (see "VCR cassette hygiene" below). |

API keys are:

- **Never** written to any artefact in `.loupe/`.
- **Never** logged in `runs/*.json` (the model identifier is logged, e.g., `anthropic/claude-opus-4-7`, but not the key).
- **Never** echoed by the CLI, even in verbose modes.
- **Never** stored in the prompt cache (the cache key is the prompt content, not the auth header).

If you suspect an API key has leaked, `git log --all -p | grep -i 'sk-'` (or similar) will find it. Loupe's own code is auditable in this regard.

---

## What's logged in run records

Each `runs/*.json` captures:

| Field | What | Privacy implication |
|---|---|---|
| `run_id` | UUID per invocation | Identifier; no PII |
| `timestamp` | UTC ISO 8601 | Time of run |
| `mode` | `ci` or `interactive` | — |
| `invoked_by` | Bot identity (CI) or user email (interactive) | Could be PII if interactive |
| `base_sha`, `head_sha` | Git commit SHAs | Public if your repo is public |
| `diff_hash` | SHA-256 of the diff text | Cannot reconstruct the diff from the hash |
| `context_md_hash` | SHA-256 of `context.md` at run time | Cannot reconstruct content from hash |
| `lenses_considered` | List of `(name, score, reason)` | Lens names and scores |
| `lenses_run` | Lens names | — |
| `models_used` | Provider/model strings | E.g., `anthropic/claude-opus-4-7` |
| `total_tokens_in`, `total_tokens_out` | Token counts | Cost / usage metric |
| `cost_usd_estimate` | Estimated USD cost | — |
| `artifacts_changed` | List of paths in `.loupe/` | — |
| `prev_run_hash`, `self_hash` | SHA-256 chain | Tamper-evidence |

What is deliberately NOT stored:

- **Verbatim prompts.** Their content is reproducible from in-repo state (the diff at `head_sha`, `context.md` at that time, the knowledge graph snapshot) — so the audit trail is replayable without storing transcripts.
- **Verbatim LLM responses.** Same reasoning.
- **API keys.** See above.
- **PII not already in your repo.** If your `context.md` mentions a person, it's in your repo; Loupe doesn't add new PII.

---

## Local data flow

```
Your repo (local working tree)
    │
    │  loupe ci / loupe scan / loupe chat
    │
    ▼
.loupe/  (in-repo, version-controlled)
    ├── context.md            ← human-authored, never auto-edited
    ├── threat-model.md       ← agent-written (Layer 1)
    ├── threats.yaml          ← agent-written
    ├── mitigations.yaml      ← agent-written
    ├── sbom.cdx.json         ← Syft-generated
    ├── vex.json              ← agent-written (with human approval for not_affected)
    ├── decisions/            ← human-authored, agent can only draft into .proposed/
    ├── runs/                 ← audit trail (hash-chained)
    ├── knowledge.yaml        ← cross-run state
    └── config.yaml           ← human-managed

The agent makes outbound calls only to:
    https://api.<provider>.com  (LLM)
    https://api.osv.dev          (vulnerability data; package names only)
```

`.loupe/` is intended to be committed to your repo. If you don't want some artefacts in version control, you can `.gitignore` them — but doing so weakens the audit story (no Git history for those artefacts).

---

## CI data flow

In CI, the same local flow runs inside a GitHub Actions runner with these additions:

- **GitHub App token** (a fine-grained PAT with `contents: write` scoped to `loupe/proposal-*` branches only) is the only credential with repo write access. It cannot push to `main`.
- The runner is ephemeral; nothing Loupe writes persists outside the proposal branch and the run record committed there.
- The `gh` CLI subprocess opens a PR using the GitHub App's identity, posts a comment on the original PR, and exits.

There is no Loupe-managed CI state. Everything Loupe needs to know between runs lives in your repo's `.loupe/`.

---

## MCP server data flow

When you run `loupe mcp`, the server:

- Listens on **stdio** by default (local clients like Claude Code attach via subprocess). No network port opened.
- Optionally listens on **HTTP+SSE** (`loupe mcp --serve --host …`) for remote clients. Requires authentication (token mode); refuses anonymous access on HTTP.
- Exposes the same tools and workflows as the CLI/CI. Every read goes through the same path-boundary; every write goes through the same `write_agent_artifact` or `propose_patch`. Layer 1 is enforced identically over MCP.
- Does not log MCP traffic anywhere by default. If you want a transcript, redirect stderr.

What an external MCP client (Claude Code, Cursor, ChatGPT desktop) sees:

- Tool/workflow schemas (the published `inputSchema` and `outputSchema`).
- Tool/workflow return values (Pydantic-validated structured data).
- Read access to `.loupe/` artefacts via `loupe.tools.query_artifact`.

It does NOT see:

- Loupe's own prompts to its internal LLM.
- API keys.
- Code outside `.loupe/` that isn't returned by a tool call.

---

## VCR cassette hygiene

Loupe's tests use `pytest-vcr` to record HTTP fixtures for the LLM calls, then replay them in CI. To prevent secrets in cassettes:

- A `filter_headers` filter in `conftest.py` strips `Authorization`, `x-api-key`, and any custom auth headers before the cassette is written to disk.
- Before committing a new cassette, run `grep -i 'sk-\|bearer\|api_key' tests/.../cassettes/` and `grep -i 'sk-\|bearer\|api_key' packages/.../tests/cassettes/` to verify.
- CI fails the build if any cassette contains an `Authorization` header (planned: `loupe verify` check; not yet implemented in v1).

---

## Data retention

- **Run records** are kept indefinitely in your Git history. To purge them, you'd have to rewrite Git history — which by design is what the hash chain detects.
- **Knowledge graph** is overwritten on every run (with promotion rules — see [`DESIGN-DECISIONS.md` D-07](DESIGN-DECISIONS.md#d-07--shared-state-within-run-runcontext-blackboard--persistent-knowledge-graph)). Older versions live in Git history.
- **Artefacts** are overwritten on every run that affects them. Older versions live in Git history.
- **Proposal branches** persist until you delete them. They're not auto-cleaned.

Practically: your Git retention policy is Loupe's retention policy.

---

## What if I need to redact something later

Two scenarios:

1. **Sensitive info leaked into `context.md` or another artefact.**
   - Edit the file, commit. The current state is correct.
   - For Git history: use `git filter-repo` (or BFG). Loupe's `verify` chain will break — you'll need to re-establish the chain (planned: `loupe re-baseline` command; not in v1).

2. **An LLM call contained sensitive content you didn't want sent.**
   - The call has already happened. You can't unsend it.
   - You should rotate the API key (you've already authenticated the call).
   - File an issue with the provider if their data-retention policy is relevant.
   - **Prevention**: make sure your `context.md` and your diffs don't contain things you wouldn't send to the configured LLM provider. The same hygiene as using any LLM API.

---

## In short

If you're trying to build a threat model for Loupe itself — and you should — the attack surface is:

- One outbound HTTPS connection per LLM call to a provider you configured
- One outbound HTTPS connection to OSV/NVD per SBOM scan, with package names only
- File reads/writes within your repo (constrained by Layer 1 path boundary)
- Subprocess invocations: `git`, `gh`, `syft`, `grype` or `osv-scanner`

That's the whole list. There is no Loupe service, no Loupe telemetry, no Loupe analytics. The platform's design assumes a paranoid security/compliance team is going to read this document before adopting it — and we'd rather you do.
