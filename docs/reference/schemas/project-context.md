# ProjectContext

Sourced from `packages/loupe-core/loupe_core/artifacts/context.py`. `ProjectContext` is the parsed representation of `.loupe/context.md`; it is the most under-rated artefact in the system, because it is what stops the LLM from hallucinating about your product.

## ProjectContext

| Field | Type | Required | Notes |
|---|---|---|---|
| `product_description` | `str` | yes | Two-to-three sentences describing what the product does |
| `assets` | `list[str]` | yes | Critical assets (data, keys, tokens, signing keys). One item per bullet |
| `users` | `list[str]` | yes | User types and what each can do |
| `deployment` | `str` | yes | Where the product runs, trust boundaries, exposed network surfaces |
| `threat_actors` | `list[str]` | yes | Who you worry about (insider, supply chain, opportunistic, targeted) |
| `out_of_scope` | `list[str]` | yes | Threat models you explicitly do not address (physical, upstream CDN, etc.) |

All six fields are required. `from_markdown(path)` raises `ContextMdError` if any required section is missing or empty after parsing.

## On-disk format

`.loupe/context.md` is human-authored Markdown with YAML frontmatter. The expected shape:

```markdown
---
schema_version: 1
last_human_edit: 2026-05-15
maintained_by: your-team@example.com
---

# Product Context

## Product description

Two or three sentences describing what the product does and who it is for.

## Critical assets

- Asset one (e.g., user PII)
- Asset two (e.g., API keys for upstream payment processor)

## Users and roles

- Customer: places orders, views own data
- Admin: full backend access, no UI access

## Deployment

Where the product runs. Container on AWS Fargate, behind an ALB, with an
RDS Postgres backend. The trust boundary is the ALB.

## Threat actors of concern

- Compromised customer accounts (credential stuffing, session hijacking)
- Supply-chain compromise via PyPI or npm
- Insider misuse with legitimate admin credentials

## Out of scope

- Physical attacks on the AWS data centre
- DoS from upstream CDN providers themselves
```

Frontmatter fields are parsed but not exposed on the Pydantic model today; they exist for downstream tooling (e.g., to compute time since last review).

## Section headers are exact

The parser uses `_REQUIRED_SECTIONS`:

```
Product description
Critical assets
Users and roles
Deployment
Threat actors of concern
Out of scope
```

Header text must match exactly (case-sensitive, `##` level). The parser does not normalise; a typo like "User and roles" raises `ContextMdError`.

## Bullets vs prose

`product_description` and `deployment` are parsed as free prose (the section's content, stripped). The other four are parsed as bullet lists: each `-` line becomes one entry in the list. A missing bullet marker means that entry is lost.

## How the agent reads it

`RunContext.bootstrap()` calls `ProjectContext.from_markdown()` once per run and stores the result on `ctx.project`. Every lens reads from there; no lens re-parses the file. The agent's stable-prefix prompt includes the parsed fields verbatim, which is what makes `context.md` the anti-hallucination anchor.

## Why the agent cannot edit it

`context.md` is not in `agent_writable_paths`. The agent can only `propose_patch` against it, which writes a draft to `.loupe/.proposed/context.md` for human review. This is by design: a project description that the agent can rewrite is one that drifts with the agent's mood; a human-authored one is the source of truth.
