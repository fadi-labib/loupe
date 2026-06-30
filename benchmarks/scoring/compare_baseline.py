"""Render the Loupe-vs-StrideGPT comparison table from D-16 / evaluation.md.

Per D-16, StrideGPT is a separate Streamlit app studied for its prompts,
not integrated live — there's no programmatic "run StrideGPT" call.
Recording a baseline is a manual, one-time-per-scenario task: run
StrideGPT's UI against the scenario's pre-fix file plus a StrideGPT-
shaped product description, then transcribe its output into
`stridegpt-baseline.yaml` next to the scenario's `expected-threats.yaml`.

This module only renders the comparison table once baselines exist —
it does not invoke StrideGPT. Scenarios without a recorded baseline
show "not yet recorded" rather than blocking the report.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel
from ruamel.yaml import YAML

from scoring.score_run import ScenarioScore

_yaml = YAML(typ="safe")


class StrideGptBaseline(BaseModel):
    """One scenario's manually-recorded StrideGPT output."""

    found: bool
    stride_category: str | None = None
    severity: str | None = None

    @classmethod
    def load(cls, path: Path) -> StrideGptBaseline:
        with path.open("r") as f:
            return cls.model_validate(_yaml.load(f))


def render_comparison_table(
    scores: list[ScenarioScore], baselines: dict[str, StrideGptBaseline]
) -> str:
    lines = [
        "| Scenario | Loupe found | StrideGPT found | Winner |",
        "|---|---|---|---|",
    ]
    for score in scores:
        baseline = baselines.get(score.scenario_id)
        loupe_found = _describe_loupe(score)
        if baseline is None:
            stridegpt_found = "not yet recorded"
            winner = "n/a"
        else:
            stridegpt_found = _describe_baseline(baseline)
            winner = _pick_winner(score, baseline)
        lines.append(f"| {score.scenario_id} | {loupe_found} | {stridegpt_found} | {winner} |")
    return "\n".join(lines) + "\n"


def load_baselines(scenarios_dir: Path) -> dict[str, StrideGptBaseline]:
    """Load every `stridegpt-baseline.yaml` present under `scenarios_dir`.

    Scenarios with no baseline file yet are simply absent from the
    returned mapping — `render_comparison_table` reports those as
    "not yet recorded".
    """
    baselines: dict[str, StrideGptBaseline] = {}
    for scenario_dir in sorted(scenarios_dir.iterdir()):
        baseline_path = scenario_dir / "stridegpt-baseline.yaml"
        if baseline_path.exists():
            baselines[scenario_dir.name] = StrideGptBaseline.load(baseline_path)
    return baselines


def _describe_loupe(score: ScenarioScore) -> str:
    return "Yes" if score.detected else "No"


def _describe_baseline(baseline: StrideGptBaseline) -> str:
    if not baseline.found:
        return "No"
    return f"Yes ({baseline.stride_category}, {baseline.severity})"


def _pick_winner(score: ScenarioScore, baseline: StrideGptBaseline) -> str:
    if score.detected and not baseline.found:
        return "Loupe"
    if baseline.found and not score.detected:
        return "StrideGPT"
    if score.detected and baseline.found:
        return "tie"
    return "neither"
