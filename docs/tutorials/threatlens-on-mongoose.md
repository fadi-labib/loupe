---
tags:
  - tutorial
  - threatlens
  - end-to-end
---

# End-to-end ThreatLens on Cesanta Mongoose

A complete walkthrough from `git clone` of a real third-party project to a
verified `.loupe/` artefact pack with hash-chained run records. Use this when
you want to *see* Loupe doing genuine work — the tutorial uses [Cesanta
Mongoose](https://github.com/cesanta/mongoose), an embedded networking library
in C, exactly the Tier-1 benchmark candidate identified in
[D-19](../reference/decisions.md#d-19) and
[evaluation.md](../reference/evaluation.md#tier-1-cesanta-mongoose-fast-smoke-test).

By the end you will have run:

- `loupe doctor` (preflight)
- `loupe init` (scaffold)
- `loupe ci` against a real fix commit diff (the agent reads the diff +
  `context.md` and proposes STRIDE-categorised threats)
- `loupe scan` against a single source file (whole-file analysis, scan-mode)
- `loupe verify --strict` (hash-chain integrity + protected-path authorship)

The whole walkthrough costs roughly **$1–$3** in Anthropic API charges at
Claude Opus 4.7 prices, and takes **5–10 minutes** of wall time. Pick a
cheaper model in `models.default` if you want to dry-run.

## What you need

| Requirement | Why |
|---|---|
| Python 3.13 + `uv` | Loupe's runtime — see [Quickstart § Install](../quickstart.md#install) |
| A Loupe checkout you've run `uv sync --all-packages` against | Pre-PyPI, the CLI lives in the workspace venv |
| `ANTHROPIC_API_KEY` exported (or another provider key matching `models.default`) | ThreatLens calls a real LLM |
| `git` | We clone Mongoose and check out a real fix commit |
| Syft + Grype on PATH (installed in Step 4.5) | ThreatLens declares both as `requires_capabilities`; `loupe ci` exits 64 until they're wired ([D-23](../reference/decisions.md#d-23)) |

> [!NOTE]
> Loupe is pre-alpha (pre-PyPI), so the CLI runs out of the workspace checkout.
> The cleanest way to invoke it from *another* project's directory is
> `uv run --project /path/to/loupe loupe <cmd>`. Replace `/path/to/loupe`
> with your local checkout's absolute path throughout the rest of this
> tutorial. Once `loupe-cli` ships on PyPI the prefix collapses to just
> `loupe …`.

## 1. Clone Mongoose and pick a target commit

```bash
mkdir -p /tmp/loupe-validation && cd /tmp/loupe-validation
git clone --depth=200 https://github.com/cesanta/mongoose.git
cd mongoose
```

We use `--depth=200` to keep the clone small. Mongoose's recent history
contains several real protocol-parser fixes. A useful Tier-1-style target is
the MQTT-cast fix:

```bash
git log --oneline -50 --grep mqtt
# Look for "Fix casting issue in MQTT parsing" — sha may differ on your
# pull because the upstream branch updates. Replace <SHA> below with the
# commit you find.
SHA=$(git log -1 --format=%H --grep='Fix casting issue in MQTT parsing')
echo "$SHA"
```

This commit introduces a `decode_varint(... uint32_t *value)` signature
where the caller passes `(uint32_t *) &m->props_size` and `m->props_size`
is a `size_t`. On a 64-bit host that's a partial-write strict-aliasing bug —
exactly the kind of protocol-state defect Loupe is meant to catch.

Generate the diff Loupe will analyse:

```bash
git show "$SHA" > /tmp/loupe-validation/mqtt-cast-fix.diff
wc -l /tmp/loupe-validation/mqtt-cast-fix.diff   # roughly 150-200 lines
```

## 2. Run preflight diagnostics

Before scaffolding anything, confirm the environment is ready:

```bash
uv run --project /path/to/loupe loupe doctor
```

Expected output (pre-init):

```
[✗] .loupe/ directory: .loupe not found — run `loupe init` first

0 ok · 0 warn · 1 fail
```

The `.loupe/` directory doesn't exist yet, so doctor surfaces that and stops.
This is the expected failure — fix it in the next step.

## 3. Scaffold `.loupe/`

```bash
uv run --project /path/to/loupe loupe init
```

You should see:

```
Initialised /tmp/loupe-validation/mongoose/.loupe.
Edit .loupe/context.md to describe your product, then run `loupe ci` or `loupe chat`.
```

Inspect what landed:

```bash
ls .loupe/
# config.yaml  context.md  decisions/  knowledge.yaml  runs/
```

`config.yaml` ships with ThreatLens enabled, the per-run budget set to
$2.50, the standard `agent_writable_paths` allow-list, and a *commented-out*
`capabilities:` skeleton — intentional, so ThreatLens runs without SBOM/CVE
backends on first try. See
[Configure the capabilities](../quickstart.md#configure-the-capabilities)
if you want to wire Syft/Grype.

## 4. Author `context.md` — the anti-hallucination anchor

This is the single most load-bearing artefact for ThreatLens output quality.
The agent reads it on every run; weak content here produces generic STRIDE
templates instead of code-grounded threats. Open it in your editor and fill
in all six sections:

```bash
$EDITOR .loupe/context.md
```

A realistic Mongoose `context.md` looks like this (abridged — write it in
your own words, the agent reads everything):

```markdown
## Product description
Mongoose is an embedded networking library written in portable C. It
provides HTTP/1.1, HTTP/2, WebSocket, MQTT, CoAP, DNS, and TLS in a
single-source-file build, targeted at firmware engineers running on
resource-constrained devices.

## Critical assets
- TLS private keys and certificates loaded by the embedding application
- Device credentials persisted through Mongoose-facing HTTP/MQTT endpoints
- Network message buffers (inbound parser state) — corruption is exploitable
- Listening sockets and connection state machines

## Users and roles
- firmware-developer: links Mongoose into device firmware; owns cert-loading
- end-user: interacts with the device through Mongoose-served HTTP/MQTT
- ota-update-service: external system publishing firmware via MQTT/HTTPS
- attacker-on-network: untrusted peer on the LAN with port reachability

## Deployment
Mongoose ships as source; deployments are heterogeneous. (Resource-
constrained MCU running RTOS, Linux/POSIX edge gateway, standalone Linux
binary.) Trust boundary is the network socket.

## Threat actors of concern
- Remote unauthenticated LAN attacker (parser-corruption → RCE/DoS)
- Authenticated MQTT publisher abusing topic ACL gaps
- Supply-chain: tampered mongoose.c amalgamation in a downstream build

## Out of scope
- Physical-tampering / side-channel attacks against silicon
- The linked TLS library's threat model (BearSSL / mbedTLS / OpenSSL)
- Bugs introduced by an embedding application's misuse of the C API
```

Save the file. Now re-run doctor:

```bash
uv run --project /path/to/loupe loupe doctor
```

Expected (with `capabilities:` still commented out):

```
[✓] .loupe/ directory: .loupe
[✓] config.yaml parse: schema_version=1
[✓] context.md: all sections filled
[✓] provider key (anthropic): ANTHROPIC_API_KEY is set
[✗] capabilities[sbom]: lens 'threatlens' requires 'sbom' but no backends are wired in config.yaml. Uncomment the `capabilities:` block in `.loupe/config.yaml` and install the backend; `loupe ci` exits 64 otherwise.
[✗] capabilities[cve]: lens 'threatlens' requires 'cve' but no backends are wired in config.yaml. Uncomment the `capabilities:` block in `.loupe/config.yaml` and install the backend; `loupe ci` exits 64 otherwise.

4 ok · 0 warn · 2 fail
```

Doctor flags both `sbom` and `cve` because ThreatLens declares them as
required ([D-23](../reference/decisions.md#d-23)). Wire them in the next
step, then doctor turns green and `loupe ci` will work.

## 4.5. Wire the SBOM + CVE capability backends

ThreatLens needs an SBOM and CVE provider before it runs. Install Syft
(SBOM generator) and Grype (CVE matcher):

```bash
# macOS via Homebrew
brew install anchore/syft/syft anchore/grype/grype

# Linux (one-line installers from the Anchore releases)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
  | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
  | sh -s -- -b /usr/local/bin

# Verify both are on PATH
syft version
grype version
```

Then uncomment the `capabilities:` block in `.loupe/config.yaml` so both
backends are wired:

```yaml
capabilities:
  sbom:
    mode: single
    backends: [syft]
  cve:
    mode: single
    backends: [grype]
```

Re-run doctor to confirm the wall is down:

```bash
uv run --project /path/to/loupe loupe doctor
```

Expected:

```
[✓] .loupe/ directory: .loupe
[✓] config.yaml parse: schema_version=1
[✓] context.md: all sections filled
[✓] provider key (anthropic): ANTHROPIC_API_KEY is set
[✓] required capabilities: 2 required cap(s) wired across enabled lenses
[✓] backend cve.grype: grype on PATH
[✓] backend sbom.syft: syft on PATH

7 ok · 0 warn · 0 fail
```

> [!NOTE]
> **Why required, not optional.** ThreatLens declares `sbom` and `cve`
> as `requires_capabilities`, not `prefers_capabilities`, per
> [D-23](../reference/decisions.md#d-23). The choice favours audit-trail
> integrity over onboarding ergonomics: every threat ever produced by
> ThreatLens carries a real Grype CVE cross-reference rather than a
> training-data-recalled CWE. The one-time cost of wiring Syft + Grype
> buys evidence-grade output from the first run forward.

## 5. Run `loupe ci` against the MQTT-cast diff

```bash
uv run --project /path/to/loupe loupe ci \
  --diff-file /tmp/loupe-validation/mqtt-cast-fix.diff \
  --base-sha "$(git rev-parse "$SHA"^)" \
  --head-sha "$SHA"
```

Wall-time roughly 30–60 seconds. The CLI will print a pydantic-ai warning
about `temperature` being ignored on Opus 4.7 (cosmetic, harmless — F-08
tracks the fix), then run Syft and Grype against the Mongoose checkout
(the SBOM + CVE results land on `ctx.sbom` / `ctx.cve_findings` before
ThreatLens reads them), and finally:

```
Loupe CI complete. Run: run-7414f333.
Lenses run: ['threatlens']
Warning: 1 threat(s) at warn_on severities (medium):
  - T-003: medium
Gate failure: 2 threat(s) at fail_on severities (critical, high):
  - T-001: critical
  - T-002: high
```

Exit code is 1: the `ci.fail_on: [critical, high]` gate fired on the two
real bugs ThreatLens spotted. That's the product working as designed.

Read what was proposed:

```bash
head -40 .loupe/threats.yaml
```

You should see four entries (`T-001..T-004`) referencing real symbols —
`mg_mqtt_parse`, `decode_varint`, `mg_mqtt_next_prop` — with CWE
cross-references and rationales that tie back to the assets and threat
actors you authored in `context.md`. Total cost was around **$0.94** for
roughly 33k input tokens; the run record under `.loupe/runs/*.json`
captures the exact numbers.

## 6. Verify hash chain and cross-references

```bash
uv run --project /path/to/loupe loupe verify
```

Expected:

```
loupe verify: OK
```

Strict mode adds protected-path authorship checks (per
[verification.md](../reference/verification.md)):

```bash
uv run --project /path/to/loupe loupe verify --strict
```

Expected:

```
loupe verify: OK (strict)
```

## 7. Run `loupe scan` over a single source file

`loupe ci` is the PR-shaped, diff-mode entry point. `loupe scan` is the
[D-15](../reference/decisions.md#d-15) whole-file (or whole-repo) entry
point — bypasses the per-lens relevance threshold, used for onboarding and
re-baselining. Scope it tight on the first run so the cost stays predictable:

> [!WARNING]
> **Scan-mode is being fixed (F-09).** Until the fix in
> [D-24](../reference/decisions.md#d-24) lands, `loupe scan --paths <file>`
> does **not** send the file's bytes to the LLM. The agent receives the
> system prompt, your `context.md`, and a `"No diff provided"` placeholder
> — nothing else. The threats it produces are reasoned from `context.md`
> and the model's pre-existing knowledge of public projects (here:
> Mongoose), not from a fresh reading of the source you pointed at.
>
> This is useful for context-grounded brainstorming but is **not a code
> audit** in the current build. For analysis that requires the model to
> actually see code, use `loupe ci --diff-file <patch>` (Section 5 above).
> Track the fix at `docs/plans/2026-05-16-mongoose-validation-gaplog.md`
> §F-09. Re-run this section after that fix ships to get a real
> source-grounded scan and a comparable cost number.

```bash
uv run --project /path/to/loupe loupe scan --paths src/mqtt.c
```

> [!IMPORTANT]
> `loupe scan` takes paths through the **`--paths` flag**, repeatable
> per file — *not* as positional arguments. (`loupe scan src/mqtt.c`
> currently errors with `Got unexpected extra arguments`. Tracked as
> F-05 in the validation gap log.)

Wall-time roughly 1–2 minutes; cost roughly **$1.10** for a single file at
Opus 4.7 prices. The output ends with:

```
Loupe scan complete. Run: run-ba9c630c (scope=scoped).
Lenses run: ['threatlens']
```

Inspect the run record telemetry to confirm the scan accounted for tokens
and cost correctly:

```bash
python3 -c "
import json
from pathlib import Path
runs = sorted(Path('.loupe/runs').glob('*.json'))
data = json.loads(runs[-1].read_text())
for key in ('run_id','trigger','total_tokens_in','total_tokens_out','cost_usd_estimate','models_used'):
    print(f'{key}={data[key]}')
print(f'artifacts_changed_count={len(data[\"artifacts_changed\"])}')
"
```

Expected (numbers will vary with the model's output):

```
run_id=run-ba9c630c
trigger=manual_scan_scoped
total_tokens_in=28788
total_tokens_out=9049
cost_usd_estimate=1.110495
models_used={'threatlens': 'anthropic:claude-opus-4-7'}
artifacts_changed_count=16
```

`artifacts_changed_count` matches the number of `threat:` entries in
`threats.yaml`. Run `loupe verify --strict` again — it should still pass.

## What you've validated

If every command above produced the expected output:

1. The CLI surface (`doctor`, `init`, `ci`, `scan`, `verify`) works
   end-to-end from a project root that is *not* the Loupe checkout.
2. ThreatLens makes a real Anthropic API call and, **in `loupe ci`**,
   emits threats that reference real source symbols, real CWEs, and
   real assets from `context.md`. Scan-mode currently produces
   threats grounded in `context.md` plus training-data recall, not
   in the bytes of the files you scoped — see the warning at
   Section 7 and D-24.
3. The `ci.fail_on` gate fires on the correct severities.
4. The run record's per-lens telemetry (token counts, cost estimate,
   model id, artefacts changed) survives the round-trip through both
   `loupe ci` and `loupe scan`.
5. `loupe verify --strict` confirms the hash chain and protected-path
   authorship hold under the produced run sequence.

> [!NOTE]
> **Capability context.** This walkthrough runs ThreatLens after wiring
> Syft (SBOM) and Grype (CVE) in Step 4.5, so `ctx.sbom` and
> `ctx.cve_findings` are populated before the lens reads them. The CWE
> references in the threats above are anchored to the real Grype scan
> against Mongoose's dependency graph rather than training-data recall.
> Skip Step 4.5 and `loupe ci` will exit 64 ([D-23](../reference/decisions.md#d-23)) — the wall is deliberate.

## Where to go next

- Wire SBOM + CVE capability backends to give ThreatLens more context.
  See [concepts/capabilities.md](../concepts/capabilities.md) and uncomment
  the `capabilities:` block in `.loupe/config.yaml`.
- Wire the [GitHub Action](../quickstart.md#wire-up-the-github-action) so
  every PR gets the same treatment.
- Run [`loupe mcp`](../how-to/run-mcp-server.md) and expose Loupe's read
  tools to your editor / agent host.
- For the Mosquitto Tier 2 release-evaluation flow,
  [evaluation.md](../reference/evaluation.md#tier-2-eclipse-mosquitto-release-evaluation)
  has the methodology; the `benchmarks/` scaffold lands in Phase 10.
