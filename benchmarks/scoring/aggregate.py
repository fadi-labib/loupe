"""Roll up per-scenario `ScenarioScore`s into the suite-level report.

Tier 1 acceptance thresholds, per `docs/reference/evaluation.md` §
Acceptance thresholds: detection rate >= 50%, median cost per scenario
<= $0.10. These are Tier-1-specific — Tier 2 (when it lands) has its
own, stricter thresholds and would pass its own values into
`check_thresholds`.
"""

from __future__ import annotations

from statistics import median

from pydantic import BaseModel

from scoring.score_run import ScenarioScore

TIER1_MIN_DETECTION_RATE = 0.50
TIER1_MAX_MEDIAN_COST_USD = 0.10


class AggregateReport(BaseModel):
    scenario_count: int
    detection_rate: float
    classification_accuracy: float
    specific_match_rate: float
    median_cost_usd: float
    total_false_positives: int
    total_latency_s: float
    thresholds_met: bool
    threshold_failures: list[str]


def aggregate(
    scores: list[ScenarioScore],
    *,
    min_detection_rate: float = TIER1_MIN_DETECTION_RATE,
    max_median_cost_usd: float = TIER1_MAX_MEDIAN_COST_USD,
) -> AggregateReport:
    if not scores:
        raise ValueError("aggregate() requires at least one ScenarioScore")

    detected = [s for s in scores if s.detected]
    detection_rate = len(detected) / len(scores)
    classification_accuracy = (
        sum(1 for s in detected if s.category_correct) / len(detected) if detected else 0.0
    )
    specific_match_rate = (
        sum(1 for s in detected if s.specific_match) / len(detected) if detected else 0.0
    )
    median_cost = median(s.cost_usd for s in scores)

    failures = []
    if detection_rate < min_detection_rate:
        failures.append(f"detection rate {detection_rate:.0%} < required {min_detection_rate:.0%}")
    if median_cost > max_median_cost_usd:
        failures.append(f"median cost ${median_cost:.4f} > required <= ${max_median_cost_usd:.2f}")

    return AggregateReport(
        scenario_count=len(scores),
        detection_rate=detection_rate,
        classification_accuracy=classification_accuracy,
        specific_match_rate=specific_match_rate,
        median_cost_usd=median_cost,
        total_false_positives=sum(s.false_positives for s in scores),
        total_latency_s=sum(s.latency_s for s in scores),
        thresholds_met=not failures,
        threshold_failures=failures,
    )


def render_markdown(report: AggregateReport, scores: list[ScenarioScore]) -> str:
    """Render the aggregate report as a markdown table — pasteable into a
    PR comment, release note, or CI step summary."""
    lines = [
        "## Tier 1 (Mongoose) benchmark report",
        "",
        f"- Scenarios: {report.scenario_count}",
        f"- Detection rate: {report.detection_rate:.0%}"
        f" (threshold: >= {TIER1_MIN_DETECTION_RATE:.0%})",
        f"- Classification accuracy (of detected): {report.classification_accuracy:.0%}",
        f"- Specific-match rate (of detected): {report.specific_match_rate:.0%}",
        f"- Median cost/scenario: ${report.median_cost_usd:.4f}"
        f" (threshold: <= ${TIER1_MAX_MEDIAN_COST_USD:.2f})",
        f"- Total false positives: {report.total_false_positives}",
        f"- Total wall time: {report.total_latency_s:.1f}s",
        f"- Thresholds met: {'yes' if report.thresholds_met else 'NO'}",
    ]
    if report.threshold_failures:
        lines.append("")
        lines.append("Failures:")
        lines.extend(f"- {failure}" for failure in report.threshold_failures)
    lines += [
        "",
        "| Scenario | Detected | Category correct | Severity in range "
        "| Specific match | Cost | FPs |",
        "|---|---|---|---|---|---|---|",
    ]
    for s in scores:
        lines.append(
            f"| {s.scenario_id} | {_yn(s.detected)} | {_yn(s.category_correct)} | "
            f"{_yn(s.severity_in_range)} | {_yn(s.specific_match)} | ${s.cost_usd:.4f} | "
            f"{s.false_positives} |"
        )
    return "\n".join(lines) + "\n"


def _yn(value: bool) -> str:
    return "yes" if value else "no"
