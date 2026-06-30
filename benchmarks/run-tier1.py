#!/usr/bin/env python3
"""Tier 1 (Mongoose) benchmark orchestrator.

Live-LLM, real cost — not part of the free `pytest packages/` CI gate
(see benchmarks/README.md). Run on demand before pushing changes to the
agent loop, prompt, or run-record shape, or via the scheduled
`benchmark-tier1` GitHub Actions workflow.

For each scenario under `tier1-mongoose/scenarios/`: checks out the
scenario's pre-fix commit in the `mongoose-fork` submodule, generates a
diff against the fix commit, runs the real `loupe ci` CLI against it
(as a subprocess — exercising the actual entrypoint, not loupe-core
internals directly), scores the result against the scenario's
`expected-threats.yaml`, and rolls everything up into an aggregate
report checked against Tier 1's acceptance thresholds.

Usage:
    uv run python benchmarks/run-tier1.py
    uv run python benchmarks/run-tier1.py --scenario CVE-2023-34188
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

BENCH_ROOT = Path(__file__).resolve().parent
LOUPE_REPO_ROOT = BENCH_ROOT.parent
TIER1_ROOT = BENCH_ROOT / "tier1-mongoose"
MONGOOSE_FORK = TIER1_ROOT / "mongoose-fork"
SCENARIOS_ROOT = TIER1_ROOT / "scenarios"

sys.path.insert(0, str(BENCH_ROOT))

from scoring.aggregate import aggregate, render_markdown  # noqa: E402
from scoring.manifest import ScenarioManifest  # noqa: E402
from scoring.score_run import ScenarioScore, score_scenario_dir  # noqa: E402

# Reset between scenarios so one scenario's findings/run-history don't
# leak into the next — each scenario should score against a clean
# .loupe/ state. context.md and config.yaml are NOT reset; they're the
# fixed scaffold shared across all scenarios.
_PER_SCENARIO_RESET_PATHS = (
    "threats.yaml",
    "mitigations.yaml",
    "knowledge.yaml",
    "runs",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario", default=None, help="Run only this scenario id (a scenarios/<id>/ dirname)."
    )
    args = parser.parse_args()

    _ensure_submodule_initialized()
    _ensure_loupe_scaffold()

    scenario_dirs = sorted(d for d in SCENARIOS_ROOT.iterdir() if d.is_dir())
    if args.scenario:
        scenario_dirs = [d for d in scenario_dirs if d.name == args.scenario]
        if not scenario_dirs:
            print(f"error: no scenario named {args.scenario!r} under {SCENARIOS_ROOT}")
            return 2

    scores: list[ScenarioScore] = []
    diff_cache: dict[str, tuple[Path, Path, float]] = {}
    for scenario_dir in scenario_dirs:
        score = _run_scenario(scenario_dir, diff_cache)
        scores.append(score)
        print(
            f"{scenario_dir.name}: detected={score.detected} "
            f"category_correct={score.category_correct} cost=${score.cost_usd:.4f} "
            f"latency={score.latency_s:.1f}s"
        )

    report = aggregate(scores)
    markdown = render_markdown(report, scores)
    print()
    print(markdown)
    (TIER1_ROOT / "REPORT.md").write_text(markdown)

    return 0 if report.thresholds_met else 1


def _ensure_submodule_initialized() -> None:
    if not (MONGOOSE_FORK / ".git").exists():
        print(f"error: {MONGOOSE_FORK} is not initialized.")
        print("Run: git submodule update --init benchmarks/tier1-mongoose/mongoose-fork")
        sys.exit(2)


def _ensure_loupe_scaffold() -> None:
    loupe_dir = MONGOOSE_FORK / ".loupe"
    if not loupe_dir.exists():
        _run_loupe_cli(["init"])
    (loupe_dir / "context.md").write_text((TIER1_ROOT / "context-template.md").read_text())
    (loupe_dir / "config.yaml").write_text((TIER1_ROOT / "config-template.yaml").read_text())


def _reset_per_scenario_state() -> None:
    loupe_dir = MONGOOSE_FORK / ".loupe"
    for name in _PER_SCENARIO_RESET_PATHS:
        target = loupe_dir / name
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()
    (loupe_dir / "runs").mkdir(exist_ok=True)


def _run_scenario(
    scenario_dir: Path, diff_cache: dict[str, tuple[Path, Path, float]]
) -> ScenarioScore:
    manifest = ScenarioManifest.load(scenario_dir / "manifest.yaml")
    diff_text = _generate_diff(manifest)
    diff_hash = hashlib.sha256(diff_text.encode()).hexdigest()

    if diff_hash in diff_cache:
        # Another scenario (e.g. a squashed upstream commit covering
        # multiple CVEs) already ran this exact diff through loupe ci —
        # reuse its output instead of paying for the same LLM call twice.
        threats_path, run_record_path, latency_s = diff_cache[diff_hash]
    else:
        threats_path, run_record_path, latency_s = _invoke_loupe_ci(manifest, diff_text)
        diff_cache[diff_hash] = (threats_path, run_record_path, latency_s)

    score = score_scenario_dir(
        scenario_dir,
        threats_path=threats_path,
        run_record_path=run_record_path,
        latency_s=latency_s,
    )
    _archive_run(scenario_dir, threats_path, run_record_path, score)
    return score


def _generate_diff(manifest: ScenarioManifest) -> str:
    subprocess.run(
        ["git", "checkout", "--quiet", "--detach", manifest.pre_fix_commit],
        cwd=MONGOOSE_FORK,
        check=True,
    )
    if manifest.diff_scope_paths:
        cmd = [
            "git",
            "diff",
            manifest.pre_fix_commit,
            manifest.fix_commit,
            "--",
            *manifest.diff_scope_paths,
        ]
    else:
        cmd = ["git", "show", manifest.fix_commit]
    result = subprocess.run(cmd, cwd=MONGOOSE_FORK, check=True, capture_output=True, text=True)
    return result.stdout


def _invoke_loupe_ci(manifest: ScenarioManifest, diff_text: str) -> tuple[Path, Path, float]:
    _reset_per_scenario_state()
    diff_path = MONGOOSE_FORK / ".loupe" / "_scenario.diff"
    diff_path.write_text(diff_text)

    start = time.monotonic()
    result = subprocess.run(
        [
            "uv",
            "run",
            "--project",
            str(LOUPE_REPO_ROOT),
            "loupe",
            "ci",
            "--diff-file",
            str(diff_path),
            "--base-sha",
            manifest.pre_fix_commit,
            "--head-sha",
            manifest.fix_commit,
        ],
        cwd=MONGOOSE_FORK,
        capture_output=True,
        text=True,
    )
    latency_s = time.monotonic() - start
    diff_path.unlink()

    # Exit 0 (no fail_on trigger) and exit 1 (gate fired — the EXPECTED
    # outcome for a real vulnerability scenario) both mean the run
    # completed; only other codes (64 = usage/config error, anything
    # else = a real crash) indicate the orchestrator itself is broken.
    if result.returncode not in (0, 1):
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise RuntimeError(
            f"loupe ci exited {result.returncode} (expected 0 or 1) for "
            f"{manifest.cve_id} — orchestration problem, not a scoring miss."
        )

    threats_path = MONGOOSE_FORK / ".loupe" / "threats.yaml"
    run_records = sorted((MONGOOSE_FORK / ".loupe" / "runs").glob("*.json"))
    if not run_records:
        raise RuntimeError(f"loupe ci produced no run record for {manifest.cve_id}")
    return threats_path, run_records[-1], latency_s


def _run_loupe_cli(args: list[str]) -> None:
    subprocess.run(
        ["uv", "run", "--project", str(LOUPE_REPO_ROOT), "loupe", *args],
        cwd=MONGOOSE_FORK,
        check=True,
    )


def _archive_run(
    scenario_dir: Path, threats_path: Path, run_record_path: Path, score: ScenarioScore
) -> None:
    actual_runs = scenario_dir / "actual-runs"
    actual_runs.mkdir(exist_ok=True)
    stamp = run_record_path.stem
    if threats_path.exists():
        shutil.copy(threats_path, actual_runs / f"{stamp}-threats.yaml")
    shutil.copy(run_record_path, actual_runs / f"{stamp}-run.json")
    (actual_runs / f"{stamp}-score.json").write_text(
        json.dumps(score.model_dump(), indent=2) + "\n"
    )


if __name__ == "__main__":
    raise SystemExit(main())
