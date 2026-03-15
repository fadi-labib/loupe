---
tags:
  - meta
  - planning
---

# Roadmap

A snapshot of where Loupe is heading. This page is editable and expected to drift; the [decisions log](reference/decisions.md) is the durable record of *why* each item is shaped the way it is.

## Now <span class="section-label">Shipped</span>

The platform, capability registry, CLI, GitHub Action, and ThreatLens scaffolding are in place. The PydanticAI agent inside ThreatLens is not yet wired to a live LLM; that is the immediate next milestone.

## Next: agent wiring <span class="section-label">In progress</span>

ThreatLens against a live LLM, with VCR cassettes for CI. The infrastructure to receive that wiring has landed (MCP server, RunRecord cost fields populated from real agent runs, cost-regression test fixture); what remains is the agent's prompt + tool wiring against the live model and the first end-to-end VCR cassette. Once the agent itself goes live, the threat list is no longer stubbed.

## Capability layer phased plan

Tracked under [D-18](reference/decisions.md#d-18). Each phase produces working, shippable software on its own.

| Phase | Scope | Approx. effort |
|---|---|---|
| v1.x-A | Capability protocols + registry skeleton (six Protocol definitions, `CapabilityRegistry` with entry-point discovery, `CapabilityRegistry` on `RunContext`, coordinator dependency check, unit tests with fake backends) | ~1 week |
| v1.x-B | SBOM capability + Syft backend (refactor `loupe_core/sbom.py` into `SbomCapability` Protocol; `SyftBackend` as a backend package; existing `generate_sbom()` becomes a thin compat facade for one minor version, then removed) | ~3 days |
| v1.x-C | CVE capability + Grype / osv-scanner backends | ~3 days |
| v1.x-D | Secret-detection capability + gitleaks / TruffleHog backends | ~3 days |
| v1.x-E | Static-analysis capability + Semgrep backend | ~3 days |
| v1.x-F | Composition modes `union` / `consensus` / `pipeline` (the `single` and `fallback` modes ship in v1.x-A; richer modes come once there are ≥2 backends per capability to compose) | ~1 week |

Total estimated v1.x effort: roughly four to five weeks spread across releases.

## Frontends still in flight

- `loupe chat` (Designed) — interactive REPL with `[y/N/edit/skip]` confirmation prompts on protected paths. The TTY guard is in place; the conversational pipeline is not.
- `loupe mcp` (Shipped) — Model Context Protocol server. Listed here as a reminder that the HTTP+SSE remote transport is still designed-not-wired; stdio works today. See [D-09](reference/decisions.md#d-09) and [D-21](reference/decisions.md#d-21).
- GitLab / Gitea / Bitbucket adapters (Designed) — the GitHub Action exists; other VCS hosts are scoped for follow-ups.

## Lenses beyond ThreatLens <span class="section-label">Anticipated</span>

Anticipated, not committed:

- **SafetyLens** — functional-safety hazard analysis (ISO 26262, IEC 61508, IEC 62304).
- **PrivacyLens** — data-protection review (GDPR DPIA, LINDDUN).
- **AIRiskLens** — AI/ML risk (NIST AI RMF, EU AI Act high-risk requirements; potentially MAESTRO methodology).

Each lands as its own pip package; no fork of the platform. The plugin contract gets refined when SafetyLens lands ([D-04](reference/decisions.md#d-04), [principle §10](principles.md#principle-10)).

## Benchmarks ([D-19](reference/decisions.md#d-19))

Methodology recorded; scaffolding deferred to Phase 10:

- **Tier 1 — Cesanta Mongoose.** Fast smoke test, ~10 scenarios, under 5 minutes per Loupe PR.
- **Tier 2 — Eclipse Mosquitto.** Release evaluation, ~15 scenarios, under 30 minutes per Loupe release.

## Deferred until a trigger <span class="section-label">Backlog</span>

Recorded in [decisions.md "Open decisions"](reference/decisions.md#open-decisions):

- PyPI namespace check before publishing (fallbacks: `loupekit`, `loupe-platform`).
- First canonical demo project for end-to-end smoke testing.
- Sigstore / GPG commit signing and off-repo retention store ([D-14](reference/decisions.md#d-14)).
- C2PA-style cryptographic provenance for AI outputs.
- Knowledge-graph promotion thresholds beyond the initial "≥1 human decision OR ≥2 runs."

## How to use this page

For *what was decided and why*, read [decisions.md](reference/decisions.md). For *what is committed and when*, this page is the entry point. For *what shipped in a given release*, see [CHANGELOG.md](changelog.md).
