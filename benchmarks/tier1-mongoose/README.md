# Tier 1: Cesanta Mongoose (fast smoke test)

Per [D-19](../../docs/reference/decisions.md#d-19): fast feedback for
development, not a breadth claim. A passing Tier 1 result means "no
obvious regressions in the agent loop" — the corpus is too narrow
(parser/protocol-heavy, weak on Spoofing/Repudiation/Elevation because
Mongoose is a single embedded networking library with little surface
for those categories) to support a "Loupe is good" claim. That's Tier
2's job, when it lands.

## Prerequisites

Same as [the Mongoose tutorial](../../docs/tutorials/threatlens-on-mongoose.md):

- `ANTHROPIC_API_KEY` (or another provider key matching the model in
  `config-template.yaml`) exported.
- Syft + Grype on `PATH` — ThreatLens declares both as
  `requires_capabilities` (D-23); the orchestrator's config wires them,
  so a scenario run exits 64 without them installed.
- The `mongoose-fork` submodule initialized:
  `git submodule update --init benchmarks/tier1-mongoose/mongoose-fork`
  (a full, non-shallow clone — scenario commits span Mongoose's whole
  history, and the project is small enough that shallow-depth tuning
  isn't worth the fragility).

## Scenarios

9 scenarios today (target was "~10" per D-19; 9 real, independently-
verified findings beat padding to a round number with a weak or
unverifiable one — see evaluation.md's own "honest limits" framing).

| Scenario | File | STRIDE | Severity |
|---|---|---|---|
| `MONGOOSE-MQTT-VARINT-CAST` | `src/mqtt.c` | T | medium |
| `CVE-2018-18764` | `src/mg_mqtt.c` | I | medium |
| `CVE-2022-25299` | `src/http.c` | T | high |
| `CVE-2023-34188` | `src/http.c` | D | high |
| `CVE-2025-51495` | `src/ws.c` | D | high |
| `CVE-2025-65502` | `src/tls_openssl.c` | D | medium |
| `CVE-2026-5244` | `src/tls_builtin.c` | T | high |
| `CVE-2026-5245` | `src/dns.c` | D | medium |
| `CVE-2026-5246` | `src/tls_builtin.c` | S | medium |

`CVE-2026-5244` and `CVE-2026-5246` come from the same upstream commit
(a squashed "patch" commit bundling unrelated DNS/HTTP/JSON/TLS
changes) — each scenario's `manifest.yaml` sets `diff_scope_paths` to
isolate just its own file from that commit, so neither scenario's diff
is polluted by the other's fix. Because both end up with the literal
same scoped diff, the orchestrator de-duplicates by diff content hash
within one run and only pays for the LLM call once.

No Spoofing/Repudiation/Elevation scenarios were forced in — Mongoose's
real CVE history doesn't supply good examples for those categories
(`CVE-2026-5246`'s mTLS bypass is the one genuine Spoofing example that
turned up; it wasn't manufactured to fill a quota).

## Adding a new scenario

Follow [evaluation.md § How to add a new scenario](../../docs/reference/evaluation.md#how-to-add-a-new-scenario).
Every commit SHA in a scenario's `manifest.yaml` must be independently
verified against the real `cesanta/mongoose` history (`gh api
repos/cesanta/mongoose/commits/<sha>`, or the GitHub UI) before it
lands — don't trust a search result or a memory of a CVE without
confirming the actual commit, parent, and diff content. A scenario
whose SHA can't be verified should not be added, full stop.

## Cost note

The default model in `config-template.yaml` is a cheap/fast one
(`anthropic:claude-haiku-4-5`), not the Opus-tier model used elsewhere
in this repo's docs and tutorials — the $0.10/scenario median-cost
acceptance threshold (evaluation.md) isn't reachable at Opus pricing.
Override `models.default` there if you want to compare a different
model's detection quality; that's a `config-template.yaml` edit, not an
orchestrator flag, since it's a property of every scenario run.
