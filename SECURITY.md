# Security policy

Loupe is a **development product**, not a production-supported one. There is no SLA, no paid support, and no security@ address. Treat anything you build on top of Loupe accordingly: don't rely on it for production threat detection or compliance evidence without your own review.

## Reporting a vulnerability

Open a regular [GitHub issue](https://github.com/fadilabib/loupe/issues/new) describing what you found. There is no private disclosure channel because the project is pre-alpha and the threat model assumes the source is fully public.

When opening the issue, please include:

- A short title naming the component (e.g., `path-boundary`, `run-record`, `loupe-action`).
- Steps to reproduce. A failing test case is the gold standard.
- The branch and commit SHA you tested against.
- Why you think this is a security concern (impact, attacker model). Loupe's [principles](docs/principles.md) describe the threat model we hold ourselves to; framing the report against those is useful but not required.

If the issue feels too sensitive to file in public, mark it as a draft, name only the component, and ask for a contact — the maintainer will respond on the public thread.

## Scope

In scope:

- The four workspace packages (`loupe-core`, `loupe-cli`, `loupe-threatlens`, `loupe-action`).
- The artefact schemas and the hash chain (`runs/*.json`).
- The Layer 1 path boundary (`PathBoundary`) and its enforcement code paths.
- The capability protocols and bundled backends.

Out of scope:

- Third-party LLM providers' responses. Loupe is provider-agnostic; vulnerabilities in a specific provider's API belong to that provider.
- Third-party scanner backends (Syft, Grype, gitleaks, etc.). Report to those projects directly.
- The hosting GitHub Action runner itself. Report to GitHub.
- Cosmetic issues in docs or output formatting that have no security impact.

## What "security concern" means for Loupe specifically

Bugs we'd treat as security-relevant:

- The agent writes a file outside `agent_writable_paths` without the path appearing under `.loupe/.proposed/`. ([Principle: Enforcement is structural](docs/principles.md))
- The hash chain validates with `loupe verify` even though a run record has been tampered with. ([Principle: Evidence, not theatre](docs/principles.md))
- A capability backend executes arbitrary code from a malicious diff or SBOM input.
- An agent tool that should require human confirmation completes without it.
- A secret (API key, token) appears in a run record or any committed artefact.

Bugs we'd treat as ordinary defects:

- A lens crashes on a malformed diff (file a normal bug).
- A backend timeout that doesn't propagate cleanly (file a normal bug).

## What you can expect

- An acknowledgement on the issue within roughly a week.
- A fix or a "won't fix with reasons" comment within a reasonable window. Pre-alpha means timelines are loose.
- No bounty programme. Apache 2.0 licence; same expectations as any other OSS project of this stage.
