# Evaluation Benchmarking Loupe Against Historical CVEs

> **Status:** Methodology recorded; benchmark scaffolding deferred to Phase 10. This document defines the evaluation contract so contributors know what "Loupe is good enough" means in measurable terms, and so the benchmark can be implemented against a stable specification.

---

## Why evaluation matters

Loupe makes two distinguishing claims:

1. **"Evidence-grade"** outputs are auditor-credible (see [PRINCIPLES.md §1](PRINCIPLES.md#1-produce-evidence-not-theatre)).
2. **"Better-shaped than existing tools"** the platform value justifies the build over using StrideGPT + a CI wrapper (see [COMPARISON.md](COMPARISON.md) and [D-16](DECISIONS.md#d-16--relationship-with-stridegpt-learn--attribute-dont-fork)).

Both claims are testable. **Without evaluation, they're marketing.** With evaluation, they become measurable properties an external party can verify by re-running the suite.

This document specifies the evaluation: what we test against, how we score, what we compare to, and what we honestly expect to find.

---

## The methodology: historical CVEs as ground truth

The core idea is borrowed from recent LLM-security research (2024–2025 ACM/IEEE papers using the same pattern):

1. Pick a real OSS project with a rich history of published CVEs.
2. For each CVE, identify the commit that fixed it.
3. Check out the parent commit the codebase exactly *before* the fix landed. This is the vulnerable version.
4. Run Loupe against that version (synthesised as a diff against an earlier clean commit, or as a `loupe scan`).
5. Score what Loupe produced against the published CVE advisory.

The crucial property: the CVE advisories are **externally audited**. NVD, the project maintainers, and security researchers have collectively agreed these are real vulnerabilities with specific root causes. There's no risk of Loupe grading its own homework the ground truth is independently established.

---

## The benchmark projects: two-tier (D-19)

Recorded as **[D-19](DECISIONS.md#d-19--benchmark-projects-two-tier-cesanta-mongoose--eclipse-mosquitto)**. The two-tier choice:

### Tier 1 Cesanta Mongoose (fast smoke test)

- **What it is:** Embedded networking library (HTTP / WebSocket / MQTT / CoAP / DNS, single C file).
- **Size:** ~15k LOC core.
- **CVE history:** ~12 since 2019, mostly parser / protocol-state / TLS handling.
- **Licence:** dual GPL-2 / commercial. For evaluation (fork → scan → record, no redistribution) the GPL terms don't bite. Loupe's scoring code stays Apache 2.0.
- **When run:** Every Loupe PR.
- **Target wall time:** under 5 minutes.
- **Target scenarios:** ~10.
- **Role:** "Does the agent still work correctly?" Catches regressions in agent reasoning + tool surface + run-record writing. Doesn't claim breadth.

### Tier 2 Eclipse Mosquitto (release evaluation)

- **What it is:** MQTT broker (service). C core + C++ plugins.
- **Size:** ~70k LOC.
- **CVE history:** ~15 since 2015, all in NVD with detailed advisories.
- **Licence:** EPL-2.0 (clean / permissive).
- **When run:** Every Loupe release (and nightly on the main branch).
- **Target wall time:** under 30 minutes.
- **Target scenarios:** ~15.
- **Role:** "Does Loupe meet v1.0 acceptance thresholds against a representative corpus?" This is the suite whose numbers go in the public release report.

### Why two tiers (and not just one of either)

- A single big suite (Mosquitto-only) gates iteration. If it takes 30 minutes to validate a prompt tweak, contributors stop running it locally and quality regresses.
- A single small suite (Mongoose-only) biases toward memory-safety CVEs exactly the category where Loupe is honestly weakest. Reporting on Mongoose-only would understate Loupe's value.
- Two tiers separates the concerns: fast feedback for development, rigorous coverage for release. Same scoring engine, same scenario-manifest schema, same StrideGPT-comparison protocol ([D-16](DECISIONS.md#d-16--relationship-with-stridegpt-learn--attribute-dont-fork)) only the catalogues differ.

### What each tier deliberately is NOT

- **Tier 1 is not a public-facing quality claim.** A passing Tier 1 result does not mean "Loupe is good." It means "no obvious regressions in the agent loop." The Tier 1 corpus is too narrow for breadth claims.
- **Tier 2 is not a per-commit gate.** It's too expensive to run on every PR; running it for every commit would either burn budget or get skipped. Tier 2 runs at release-branch checkpoints or on a nightly schedule.

---

## Suite structure

```
benchmarks/
├── tier1-mongoose/
│   ├── mongoose-fork/               # git submodule (Cesanta cesanta/mongoose)
│   ├── scenarios/                   # ~10 CVE scenarios
│   │   ├── CVE-YYYY-XXXX/
│   │   │   ├── manifest.yaml        # metadata (schema below)
│   │   │   ├── pre-fix-commit.sha
│   │   │   ├── advisory.md
│   │   │   ├── expected-threats.yaml
│   │   │   └── actual-runs/         # per-model run outputs
│   │   └── …
│   └── README.md                    # tier-1-specific notes
│
├── tier2-mosquitto/
│   ├── mosquitto-fork/              # git submodule (eclipse/mosquitto)
│   ├── scenarios/                   # ~15 CVE scenarios
│   │   ├── CVE-2017-7650/
│   │   │   ├── manifest.yaml
│   │   │   ├── pre-fix-commit.sha
│   │   │   ├── advisory.md
│   │   │   ├── expected-threats.yaml
│   │   │   └── actual-runs/
│   │   ├── CVE-2018-12550/
│   │   └── …
│   └── README.md
│
├── scoring/                         # SHARED across tiers
│   ├── score_run.py                 # one scenario → score.json
│   ├── aggregate.py                 # all scenarios → report
│   └── compare_baseline.py          # Loupe vs. StrideGPT comparison
│
├── run-tier1.py                     # orchestrator: PR-gate suite
├── run-tier2.py                     # orchestrator: release suite
└── run-all.py                       # both tiers (CI: nightly only)
```

The scoring code is shared. New tiers in future (e.g., a v1.x SafetyLens benchmark against an automotive codebase) plug into the same scorer without duplicating logic.

### Scenario manifest schema

```yaml
# benchmarks/scenarios/CVE-2017-7650/manifest.yaml
cve_id: CVE-2017-7650
published: 2017-04-11
severity_cvss_v3: 9.8
severity_label: critical                    # mapped from CVSS to our 4-level scale
stride_category: E                          # Spoofing/Tampering/Repudiation/InfoDisclosure/DoS/Elevation
pre_fix_commit: a1b2c3d4...                 # upstream sha to check out
fix_commit: 5e6f7a8b...                     # upstream sha that fixed it
expected_affected_paths:                    # paths Loupe should flag activity around
  - src/security_default.c
expected_element_id: E-???                  # what element in the threat model maps here
description_summary: >
  Pattern-based ACL bypass: clients with publish permission on topic '+'
  could publish to topics matched by other clients' ACLs.
```

### Expected-threats schema

```yaml
# benchmarks/scenarios/CVE-2017-7650/expected-threats.yaml
# Human-curated. Reviewed by a security engineer who has read the
# advisory + the fix commit. Represents what Loupe SHOULD have found.
expected_threats:
  - title_keywords: [ACL, bypass, wildcard, pattern]   # any one match counts
    stride_category: E
    severity_min: high
    severity_max: critical
    must_reference_paths:
      - src/security_default.c
  # If the CVE could legitimately surface as multiple threats, list each.
```

---

## Scoring metrics

### Per-scenario (one CVE)

| Metric | Definition | Why it matters |
|---|---|---|
| **detected** | Did Loupe propose *any* threat at the affected element? | Coarse "did the tool see it at all" check |
| **category_correct** | Did the STRIDE category match the expected? | Catches "Loupe found *a* problem but mis-classified it" |
| **severity_in_range** | Was the proposed severity within [expected_min, expected_max]? | Severity calibration relative to context.md |
| **specific_match** | Does the rationale reference root cause keywords from the advisory? | Distinguishes "lucky hit at the right file" from real understanding |
| **cost_usd** | Token cost for the run | Economic efficiency |
| **latency_s** | Wall-clock seconds | Operational viability |
| **false_positives** | Other threats Loupe proposed beyond the expected CVE | Noise level (some FPs may be real un-CVE'd issues) |

### Aggregate (whole suite)

| Metric | Definition |
|---|---|
| **detection rate** | scenarios where `detected == True` / total scenarios |
| **classification accuracy** | scenarios where `category_correct == True` / detected scenarios |
| **specific-match rate** | scenarios where `specific_match == True` / detected scenarios |
| **average severity error** | mean absolute distance from expected severity, in levels |
| **median cost per scenario** | typical $ to evaluate one CVE |
| **comparison vs. StrideGPT** | same metrics computed against StrideGPT's output for the same scenarios (per [D-16](DECISIONS.md#d-16--relationship-with-stridegpt-learn--attribute-dont-fork)) |

### Acceptance thresholds (for v1.0)

These are commitments, not aspirations failure to hit them is a real bug. The two tiers have different bars because the corpora exercise different STRIDE breadth.

**Tier 1 (Mongoose, PR gate):**

| Metric | Threshold | Rationale |
|---|---|---|
| Detection rate | ≥ 50% | Tier 1's corpus is parser/protocol-heavy; Loupe will reasonably miss many memory-safety bugs without a `StaticAnalysisCapability` backend (D-18) |
| Median cost per scenario | ≤ $0.10 | Must be cheap enough that "run the smoke test before pushing" is routine |
| Total suite wall time | ≤ 5 minutes | Has to fit in a developer's PR feedback loop |

**Tier 2 (Mosquitto, release evaluation):**

| Metric | Threshold | Rationale |
|---|---|---|
| Detection rate | ≥ 70% | Broader corpus → reasonable to claim two-thirds caught is a real signal |
| Classification accuracy | ≥ 80% on detected | Mis-categorising means the rest of the workflow misroutes |
| Specific-match rate | ≥ 50% on detected | Loupe should *understand* half of what it catches, not just pattern-match |
| Severity calibration | within ±1 level on average | Severity drives auditor attention; gross miscalibration is misleading |
| Median cost per scenario | ≤ $0.50 | Routine evaluation must be affordable |
| Total suite wall time | ≤ 30 minutes | Has to be runnable nightly without dominating the CI bill |

If Loupe misses any Tier 2 threshold, that's a v1.0 release blocker. Better to ship an honest 60% detection rate than 85% claims that don't hold up.

A Tier 1 miss is a regression worth investigating but doesn't gate release it gates a PR's merge until either fixed, the scenario is re-curated, or the threshold is explicitly lowered with a commit message explaining why.

---

## Comparison with StrideGPT (D-16 in action)

Per [D-16](DECISIONS.md#d-16--relationship-with-stridegpt-learn--attribute-dont-fork), StrideGPT is our quality benchmark. For each scenario we run *both* tools and tabulate:

| Scenario | Loupe found | StrideGPT found | Winner |
|---|---|---|---|
| CVE-2017-7650 | Yes (E, high) | Yes (Elevation, high) | tie |
| CVE-2018-12550 | Yes (S, critical) | Yes (Spoofing, high) | Loupe (severity) |
| CVE-2021-34431 | No | Yes (DoS, medium) | StrideGPT |
| CVE-2023-3592 | Yes (D, medium) | No | Loupe |
| ... |

We do not need to win every scenario. We need to:
1. **Lose acceptably few** (≤ 20% of cases) i.e., not be a quality regression vs. the simpler tool.
2. **Win on workflow** even when output quality is tied, Loupe's continuous + persistent + CRA-shaped artefact value is the platform argument.

Losing on a scenario is a *prompt-iteration signal*. Per D-16, we study StrideGPT's prompts for that scenario and refine ours.

---

## Honest limits

What we expect the evaluation to show stating this upfront so the results aren't a surprise:

### Where Loupe will do well

- **Authentication / ACL / authorisation bugs** (CVE-2017-7650, CVE-2018-12550) these are protocol/business-logic threats LLMs reason about well, especially when `context.md` lists the assets at stake.
- **Architectural-level threats** bugs that span multiple files or involve interaction between subsystems. LLMs hold context an analyser doesn't.
- **Rationale quality** Loupe's rationale field tends to be more informative than what a one-shot tool produces, because the agent reads `context.md` first.

### Where Loupe will do less well

- **Pure memory-safety bugs** (most of libpng-style CVEs, some Mosquitto crash bugs) buffer overruns, use-after-frees, NULL deref. Static analysers (CodeQL, Coverity, Semgrep with the right rules) outperform LLM reasoning here.
- **Bugs in code Loupe didn't read** if the vulnerable code is in a file the agent didn't see (because the diff was elsewhere, or the prompt-cache filter dropped it), we miss it. This is a *known* failure mode of all LLM tools.
- **Subtle race conditions** multi-threaded reasoning is hard for LLMs. We'll have a few of these in the Mosquitto CVE list and they'll mostly be missed.

The fix for the memory-safety gap is **[D-18 capability backends](DECISIONS.md#d-18--capability-abstraction-tool-agnostic-functional-building-blocks)** the `StaticAnalysisCapability` lets a future ThreatLens query Semgrep / CodeQL findings and *incorporate* them into reasoning. The eval suite is the artefact that proves this matters: scenarios Loupe fails on solo, plus a Semgrep backend, should pass.

### What "false positives" really means

If Loupe proposes a threat at a place that wasn't a CVE, that's a false positive *for this evaluation*. It may still be a real threat that just hasn't been filed yet, or a defence-in-depth concern, or a latent bug not yet exploited.

The scoring engine counts FPs, but the EVALUATION.md result reporting must distinguish:

- **Hard FP** proposed threat at code that has no realistic exploit path (the human reviewer agrees)
- **Soft FP** proposed threat the maintainers chose not to file a CVE for but agree is legitimate
- **Latent finding** proposed threat that's actually a real bug not yet disclosed

Without this distinction, "high FP rate" sounds bad when in fact some of those FPs are the tool earning its keep.

---

## How to add a new scenario

When a fresh Mosquitto CVE is published:

1. Identify the fix commit (usually linked from the advisory).
2. Identify the pre-fix commit (parent of the fix commit).
3. Create `scenarios/CVE-YYYY-NNNN/` with:
   - `manifest.yaml` fill in the schema above
   - `pre-fix-commit.sha` text file with the SHA
   - `advisory.md` copy of the public advisory text (with a link to the source)
   - `expected-threats.yaml` human-curated; reviewed by someone who's read both the advisory *and* the fix diff
4. PR the new scenario directory. Re-run `run-all.py`. Update the aggregate report.

The scenarios become a permanent regression test: a Loupe change that newly fails a previously-passing scenario is a regression, not progress.

---

## How to run (once Phase 10 lands the scaffolding)

```bash
# Initial setup clones both upstream projects as submodules
git clone <loupe-repo>
cd loupe
git submodule update --init benchmarks/tier1-mongoose/mongoose-fork
git submodule update --init benchmarks/tier2-mosquitto/mosquitto-fork

export ANTHROPIC_API_KEY=sk-ant-...

# Tier 1 PR gate (5 min, ~$1 total)
uv run python benchmarks/run-tier1.py

# Tier 2 release evaluation (30 min, ~$8 total)
uv run python benchmarks/run-tier2.py

# Both (nightly job)
uv run python benchmarks/run-all.py

# Single scenario (fastest iteration when tuning prompts)
uv run python benchmarks/run-tier2.py --scenario CVE-2017-7650

# Compare against StrideGPT baseline (records both runs side by side)
uv run python benchmarks/run-tier2.py --compare stridegpt

# Aggregate report from the most recent runs
uv run python benchmarks/scoring/aggregate.py > REPORT.md
```

The aggregate output is intentionally a markdown table easy to paste into a release-note section, a blog post, or a regulator briefing. Tier 2 reports are the public-facing artefact; Tier 1 reports are mostly for internal-PR signalling.

---

## Why this evaluation is itself an artefact

The scenarios directory + scoring code + aggregate report are a publishable benchmark suite. Other STRIDE-tool authors can run their tools against the same scenarios and tabulate results in the same shape. That gives the industry a shared rubric not just "we tested it on our own examples and it works." Loupe's evaluation framework is meant to be *useful to people who don't use Loupe*.

Specifically:

- A future SafetyLens evaluation needs a similar suite tied to ISO 26262 violations.
- A future PrivacyLens evaluation needs LINDDUN-categorised scenarios.
- The scoring shape (per-scenario booleans + aggregate rollups + comparison vs. baseline) generalises beyond security threat modelling.

In that sense the EVALUATION.md is part of the contribution Loupe makes, separate from the agent itself.

---

## Cross-references

- [D-19](DECISIONS.md#d-19--benchmark-project-choice-eclipse-mosquitto) the decision record
- [D-16](DECISIONS.md#d-16--relationship-with-stridegpt-learn--attribute-dont-fork) StrideGPT as a quality benchmark
- [D-18](DECISIONS.md#d-18--capability-abstraction-tool-agnostic-functional-building-blocks) Capability backends (Semgrep / CodeQL) close the memory-safety gap
- [PRINCIPLES.md §1](PRINCIPLES.md#1-produce-evidence-not-theatre) why "verifiable by an external party" is non-negotiable
