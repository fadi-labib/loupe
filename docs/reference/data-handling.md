# Data handling

Every security or compliance team evaluating Loupe will ask what it sends out of their environment and to whom. This document answers that with code references so you can verify rather than trust.

## TL;DR

Loupe is local-first. All artefacts live in your repo as plain files. There is no Loupe-hosted backend, no telemetry, no cloud database; git is the audit substrate.

Outbound network calls go to four kinds of endpoints during a typical run, and only when the corresponding code path is exercised:

1. The LLM provider you configure (Anthropic, OpenAI, Google, others through PydanticAI).
2. Vulnerability data sources reached by the SBOM and CVE backends (OSV, NVD), through the subprocesses those backends shell out to.
3. The GitHub API when running through the GitHub Action, to fetch PR metadata and diff and to post the sticky comment.
4. Nothing else. There is no Loupe-managed service, no usage reporting, no phone-home.

Run records under `.loupe/runs/` store hashes of inputs, not verbatim prompts. The audit trail is replayable from in-repo state.

## The full outbound surface

| Endpoint | When | What's sent | Code |
|---|---|---|---|
| LLM provider HTTPS API | Each LLM call during a lens run | The assembled prompt (system + user); tool schemas; per-call context | `packages/loupe-threatlens/loupe_threatlens/agent.py` (PydanticAI Agent) |
| `api.github.com/repos/.../pulls/<n>` | Once per Action invocation | Auth header; nothing in the request body | `packages/loupe-action/loupe_action/pr_fetcher.py` |
| `api.github.com/repos/.../pulls/<n>` (Accept: diff) | Once per Action invocation | Auth header | same |
| `api.github.com/repos/.../issues/<n>/comments` | List, then POST or PATCH | The sticky-comment Markdown body | `packages/loupe-action/loupe_action/comment_poster.py` |
| OSV / NVD / vendor CVE feeds | Once per CVE-capability invocation | The list of package + version pairs from the SBOM. Not code. | The CVE backend's subprocess (e.g., `grype`) |
| SBOM sources (registries, package indexes) | Once per SBOM-capability invocation | Module names; sometimes module hashes for verification | The SBOM backend's subprocess (e.g., `syft`) |

You can spot-check the platform's own HTTP usage with:

```bash
grep -rnE 'httpx|requests|urllib|aiohttp' packages/ \
  --include='*.py' | grep -v tests/
```

The matches you should see: PydanticAI's transport for LLM calls, `httpx.AsyncClient` for the GitHub Action's API client (limited to `api.github.com` paths), and nothing else.

## What goes into an LLM prompt

The prompt is structured as a stable prefix (paid once per run, cached on subsequent lens calls) and a variable suffix (per-lens task).

Stable prefix:

| Content | Source |
|---|---|
| Common system framing | `loupe-threatlens/loupe_threatlens/prompts/system.md` |
| `.loupe/context.md` content | Your human-authored project description |
| Diff summary (in diff mode) | The unified diff |
| SBOM delta summary | Capability-registry output, once the registry is wired |
| Relevant slice of `knowledge.yaml` | Cross-run continuity |
| Lens-specific framing | The lens's `prompts/system.md` |

Variable suffix:

| Content | Source |
|---|---|
| The lens's task for this invocation | Coordinator output |
| Prior findings from earlier lenses in the same run | `RunContext.findings`, namespaced per lens |

What is not in the prompt:

- File contents outside the diff. The agent only sees code that appears in the unified diff. To read other files it would have to call a tool that returns the contents, and no such tool exists in v1.
- API keys. Authentication is via the `Authorization` header, which never appears in any prompt or artefact.
- Environment variables other than the model identifier (`THREATLENS_MODEL`) and provider API-key vars, neither of which is marshalled into prompts.
- CI/CD secrets. Same as env vars.
- Anything in `.git/`. Anything outside the repo.

## API-key handling

| Where keys come from | How |
|---|---|
| Local CLI | Provider env vars: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`, `AI_GATEWAY_API_KEY`. Read from `os.environ` at agent startup. |
| GitHub Action | `env: ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}`. GitHub redacts secret values in workflow logs. The Action's own `GITHUB_TOKEN` is the API auth for the four GitHub API calls described above. |
| Tests | Never require keys. VCR cassettes record responses once with a key and replay without one. Cassettes are scrubbed of `Authorization` and `x-api-key` headers via `filter_headers` in `conftest.py`. |

API keys are never written to any artefact in `.loupe/`, never logged in `runs/*.json` (the model identifier is logged, the key is not), never echoed by the CLI even in verbose modes, and never stored in the prompt cache (cache keys are content hashes, not auth headers).

## What's logged in run records

Each `.loupe/runs/*.json` captures:

| Field | What it is |
|---|---|
| `run_id` | UUID per invocation |
| `timestamp` | UTC ISO 8601 |
| `mode` | `ci` or `interactive` |
| `invoked_by` | Bot identity (CI) or user email (interactive) |
| `base_sha`, `head_sha` | Git commit SHAs |
| `diff_hash` | SHA-256 of the diff text |
| `context_md_hash` | SHA-256 of `context.md` at run time |
| `lenses_considered` | Triples of `(name, score, reason)` |
| `lenses_run` | Lens names that actually executed |
| `models_used` | Provider/model identifier strings |
| `total_tokens_in`, `total_tokens_out` | Cost and usage metrics |
| `cost_usd_estimate` | Estimated dollar cost |
| `artifacts_changed` | List of paths in `.loupe/` written this run |
| `prev_run_hash`, `self_hash` | SHA-256 chain |

What is deliberately not stored:

- Verbatim prompts. Their content is reproducible from in-repo state (diff at `head_sha`, `context.md` at that time, knowledge-graph snapshot) so the audit trail is replayable without storing transcripts.
- Verbatim LLM responses. Same reasoning.
- API keys.
- PII not already in your repo. If `context.md` mentions a person, it is in your repo; Loupe does not add new PII.

## Local data flow

```
Your repo (local working tree)
        │
        │  loupe ci / loupe scan (loupe chat and loupe mcp not yet shipped)
        │
        ▼
.loupe/  (in-repo, version-controlled)
    ├── context.md            ← human-authored, never auto-edited
    ├── threat-model.md       ← agent-written (Layer 1)
    ├── threats.yaml          ← agent-written
    ├── mitigations.yaml      ← agent-written
    ├── sbom.cdx.json         ← SBOM backend output (Syft today)
    ├── vex.json              ← agent-written (human approval for not_affected)
    ├── decisions/            ← human-authored, agent can only draft to .proposed/
    ├── runs/                 ← hash-chained audit trail
    ├── knowledge.yaml        ← cross-run state
    └── config.yaml           ← human-managed

The agent makes outbound calls only to:
    https://api.<provider>.com  (LLM)
    https://api.github.com      (only when running through the GitHub Action)
    SBOM/CVE backend endpoints  (package names only, no code)
```

`.loupe/` is intended to be committed. You can gitignore individual files, but doing so weakens the audit story because you lose the git history for those files.

## CI data flow

The GitHub Action runs the same `loupe ci` pipeline inside an ephemeral runner. The differences from local:

- The GitHub Action's GitHub token (whatever scope the workflow grants it) authenticates the four `api.github.com` calls described above. The token is what GitHub Actions provides via `${{ secrets.GITHUB_TOKEN }}`.
- The runner is ephemeral; nothing Loupe writes persists outside the proposal branch and the run record committed there.
- Once branch-namespace enforcement (Layer 2 in the principles) is implemented, the token will be a fine-grained PAT scoped to `loupe/proposal-*` branches only. Today the Action uses the standard `GITHUB_TOKEN` and the branch restriction is a documented Layer 2 commitment, not yet enforced.

There is no Loupe-managed CI state. Everything Loupe needs between runs lives in your repo's `.loupe/`.

## MCP server data flow (designed, not implemented)

When `loupe mcp` is implemented, the design is:

- Listens on stdio by default (local clients like Claude Code attach via subprocess). No network port opened.
- Optionally listens on HTTP+SSE for remote clients, requiring authentication; refuses anonymous access.
- Exposes the same tools as the CLI. Every read goes through the path boundary; every write goes through `write_agent_artifact` or `propose_patch`. Layer 1 enforcement applies identically.

The MCP command is not yet registered; this section is a forward-looking commitment, not a current capability.

## VCR-cassette hygiene

Loupe's tests use `pytest-vcr` to record HTTP fixtures for LLM calls and replay them in CI without keys.

`filter_headers` in `conftest.py` strips `Authorization`, `x-api-key`, `anthropic-version`, and a few other auth-adjacent headers before any cassette is written to disk. Before committing a new cassette, run `grep -i 'sk-\|bearer\|api_key'` over the cassette to verify nothing slipped through.

A `loupe verify` check that fails the build if a cassette contains an `Authorization` header is documented as a planned check; not yet implemented.

## Data retention

Run records persist indefinitely in git history. Purging them requires rewriting history, which by design is what the hash chain detects.

The knowledge graph is overwritten each run (with promotion rules; see [`decisions.md` D-07](decisions.md#d-07)). Older versions live in git history.

Artefacts are overwritten each run that affects them. Older versions live in git history.

Proposal branches persist until you delete them; not auto-cleaned.

Your git retention policy is Loupe's retention policy.

## What to do if something sensitive leaks

If sensitive info ended up in `context.md` or another artefact: edit the file and commit. The current state is correct. For git history, use `git filter-repo` or BFG; the hash chain will break and a future `loupe re-baseline` command (planned, not in v1) will re-establish it.

If an LLM call contained sensitive content you did not want sent: rotate the API key (the call has already happened). File an issue with the provider if their data-retention policy is relevant. The prevention is the same hygiene as any LLM API: do not put things in `context.md` or your diffs that you would not send.

## In short

If you are threat-modelling Loupe itself, the outbound attack surface is:

- HTTPS to your configured LLM provider, one connection per lens call.
- HTTPS to `api.github.com`, four calls per Action invocation (PR metadata, diff, list comments, post or edit comment).
- HTTPS to OSV/NVD/vendor feeds via the SBOM and CVE backend subprocesses, package names only.
- File reads and writes within your repo, constrained by the Layer 1 path boundary.
- Subprocesses: `git`, `syft`, `grype` (or alternatives configured in `capabilities`).

That is the whole list. No Loupe service, no Loupe telemetry, no Loupe analytics.
