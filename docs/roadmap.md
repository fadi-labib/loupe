---
tags:
  - meta
  - planning
---

# Roadmap

A snapshot of where Loupe is heading. This page is editable and expected to drift; the [decisions log](reference/decisions.md) is the durable record of *why* each item is shaped the way it is.

## Now <span class="section-label">Shipped</span>

The platform, capability registry with ten bundled backends, CLI (including `loupe mcp`, `loupe chat`, `loupe lens list`, `loupe cap list`), GitHub Action, and ThreatLens are in place. The PydanticAI agent inside ThreatLens is wired to a live LLM and exercised in CI through a VCR cassette; the cost-regression fixture replays it without keys. `loupe chat` lands the Layer 4 interactive UX gate ([y/N/edit/skip] default-N on every staged `.proposed/` patch, edit-the-diff via `$EDITOR`, `.proposed/` → `.applied/` / `.skipped/` lifecycle via `git mv`). `loupe mcp` now also supports an opt-in, token-gated HTTP+SSE remote transport alongside the stdio default ([D-28](reference/decisions.md#d-28)).

## Capability layer phased plan

Tracked under [D-18](reference/decisions.md#d-18). Each phase produced working, shippable software on its own.

| Phase | Scope | Status |
|---|---|---|
| v1.x-A | Capability protocols + registry skeleton (Protocol definitions, `CapabilityRegistry` with entry-point discovery, `RunContext` typed slots, coordinator dependency check) | Shipped |
| v1.x-B | SBOM capability + Syft and cdxgen backends | Shipped |
| v1.x-C | CVE capability + Grype and osv-scanner backends | Shipped |
| v1.x-D | Secret-detection capability + gitleaks, TruffleHog, and detect-secrets backends | Shipped |
| v1.x-E | Static-analysis capability + Semgrep, CodeQL, and Bandit backends | Shipped |
| v1.x-F | Composition modes `union` / `consensus` / `pipeline` (the `single` and `fallback` modes shipped in v1.x-A; the richer modes shipped alongside the second backend per capability) | Shipped |

## Frontends still in flight

- `loupe chat` (Shipped) — TTY-required interactive REPL with `[y/N/edit/skip]` confirmation prompts on every staged `.loupe/.proposed/` patch (Layer 4 enforcement). Default-N; no `--auto-confirm`. See [D-26](reference/decisions.md#d-26) for the `.loupe/` git-write exception that chat operates under.
- `loupe mcp` (Shipped) — Model Context Protocol server, 11 tools today: 6 core read (`list_threats`, `get_threat`, `list_mitigations`, `get_mitigation`, `list_elements`, `latest_run`), 3 ThreatLens read (`threatlens_query_by_stride`, `threatlens_query_by_severity`, `threatlens_summary`), 2 ThreatLens write (`threatlens_propose_threat`, `threatlens_propose_mitigation`, both gated by Layer 1). Two transports: `stdio` (default, local, unauthenticated) and `sse` (opt-in, remote, requires a static bearer token). See [D-09](reference/decisions.md#d-09), [D-21](reference/decisions.md#d-21), [D-22](reference/decisions.md#d-22), and [D-28](reference/decisions.md#d-28).
- GitLab / Gitea / Bitbucket adapters (Designed) — the GitHub Action exists; other VCS hosts are scoped for follow-ups.

## Lenses beyond ThreatLens <span class="section-label">Anticipated</span>

Anticipated, not committed:

- **SafetyLens** — functional-safety hazard analysis (ISO 26262, IEC 61508, IEC 62304).
- **PrivacyLens** — data-protection review (GDPR DPIA, LINDDUN).
- **AIRiskLens** — AI/ML risk (NIST AI RMF, EU AI Act high-risk requirements; potentially MAESTRO methodology).

Each lands as its own pip package; no fork of the platform. The plugin contract gets refined when SafetyLens lands ([D-04](reference/decisions.md#d-04), [principle §10](principles.md#principle-10)).

## Benchmarks ([D-19](reference/decisions.md#d-19))

- **Tier 1 — Cesanta Mongoose** <span class="section-label">Shipped</span>. Fast smoke test, 9 independently-verified historical-CVE scenarios, `benchmarks/tier1-mongoose/`. Run via `uv run python benchmarks/run-tier1.py` (a recommended contributor habit, not a PR-blocking gate — it's live-LLM and costs real money) or the scheduled `benchmark-tier1` GitHub Actions workflow. See [`benchmarks/README.md`](https://github.com/fadi-labib/loupe/blob/main/benchmarks/README.md) for the cost/determinism split between this and the free `pytest` gate.
- **Tier 2 — Eclipse Mosquitto.** Release evaluation, ~15 scenarios, under 30 minutes per Loupe release. Still deferred — the scoring engine in `benchmarks/scoring/` was built tier-agnostic so this can plug in without rearchitecting when it lands.

## Deferred until a trigger <span class="section-label">Backlog</span>

Recorded in [decisions.md "Open decisions"](reference/decisions.md#open-decisions):

- PyPI namespace check before publishing (fallbacks: `loupekit`, `loupe-platform`).
- First canonical demo project for end-to-end smoke testing.
- Sigstore / GPG commit signing and off-repo retention store ([D-14](reference/decisions.md#d-14)).
- C2PA-style cryptographic provenance for AI outputs.
- Knowledge-graph promotion thresholds beyond the initial "≥1 human decision OR ≥2 runs."

## How to use this page

For *what was decided and why*, read [decisions.md](reference/decisions.md). For *what is committed and when*, this page is the entry point. For *what shipped in a given release*, see [CHANGELOG.md](changelog.md).
