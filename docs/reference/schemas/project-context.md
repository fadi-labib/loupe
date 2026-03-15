# ProjectContext

The parsed representation of `.loupe/context.md`. Rendered from the Pydantic source.

Each list field (`assets`, `users`, `threat_actors`, `out_of_scope`) holds `BulletItem` values. A bullet like `- Customer: places orders` parses into `BulletItem(label="Customer", note="places orders")`; a bullet without a colon has `note=None`. `str(item)` re-renders the bullet for prompt assembly.

The YAML frontmatter at the top of the file is parsed into a `ProjectContextFrontmatter` model (`schema_version`, `last_human_edit`, `maintained_by`); all three fields are optional with safe defaults. If the file has no frontmatter, the model parses as defaults.

## ProjectContext

::: loupe_core.artifacts.context.ProjectContext

## ProjectContextFrontmatter

::: loupe_core.artifacts.context.ProjectContextFrontmatter

## BulletItem

::: loupe_core.artifacts.context.BulletItem

## ContextMdError

::: loupe_core.artifacts.context.ContextMdError

## On-disk format

`.loupe/context.md` is human-authored Markdown with YAML frontmatter:

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

## Section headers are exact

The parser uses these six required section titles. Header text must match exactly (case-sensitive, `##` level). A typo like "User and roles" raises `ContextMdError`:

```
Product description
Critical assets
Users and roles
Deployment
Threat actors of concern
Out of scope
```

## Bullets vs prose

`product_description` and `deployment` are parsed as free prose (the section's content, stripped). The other four are parsed as bullet lists: each `-` line becomes one entry. A missing bullet marker means that entry is lost.

## Why the agent cannot edit it

`context.md` is not in `agent_writable_paths`. The agent can only `propose_patch` against it, which writes a draft to `.loupe/.proposed/context.md` for human review. This is by design: a project description the agent can rewrite is one that drifts with the agent's mood; a human-authored one is the source of truth.
