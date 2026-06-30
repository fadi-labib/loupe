"""Score one benchmark scenario's actual Loupe output against its
`expected-threats.yaml`.

Pure scoring logic lives in `score_scenario()` — no I/O, no LLM calls,
fully deterministic and unit-testable. `score_scenario_dir()` is the
thin I/O wrapper the orchestrator calls: it reads the scenario's
`expected-threats.yaml`, the threats Loupe actually produced
(`.loupe/threats.yaml`), and the run record Loupe wrote, then delegates
to `score_scenario()`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel

from scoring.manifest import ExpectedThreat, ExpectedThreatsFile, SeverityLabel


class ThreatLike(Protocol):
    """The subset of `loupe_core.artifacts.threat.Threat` scoring reads.

    A Protocol rather than importing the real `Threat` model so this
    package stays independent of `loupe-core`'s import graph — the
    orchestrator hands over already-loaded threat objects (or plain
    dicts read from JSON) that satisfy this shape.
    """

    title: str
    description: str
    rationale: str
    stride_category: str
    severity: str


class ScenarioScore(BaseModel):
    """Per-scenario scoring result — one row of the aggregate report."""

    scenario_id: str
    detected: bool
    category_correct: bool
    severity_in_range: bool
    specific_match: bool
    cost_usd: float
    latency_s: float
    false_positives: int


def _text_of(threat: ThreatLike) -> str:
    return f"{threat.title}\n{threat.description}\n{threat.rationale}".lower()


def _keyword_match(threat: ThreatLike, expected: ExpectedThreat) -> bool:
    text = _text_of(threat)
    return any(keyword.lower() in text for keyword in expected.title_keywords)


def _path_match(threat: ThreatLike, expected: ExpectedThreat) -> bool:
    if not expected.must_reference_paths:
        return True
    text = _text_of(threat)
    return any(path.lower() in text for path in expected.must_reference_paths)


def score_scenario(
    scenario_id: str,
    expected: ExpectedThreatsFile,
    produced_threats: list[ThreatLike],
    *,
    cost_usd: float,
    latency_s: float,
) -> ScenarioScore:
    """Score `produced_threats` against `expected.expected_threats`.

    "Detected" requires a keyword match in the threat's title,
    description, or rationale text. "Specific match" additionally
    requires the matched threat to reference at least one of the
    expected entry's `must_reference_paths` (when any are declared) —
    distinguishing a real, code-grounded finding from a generic STRIDE
    template hit on the right topic. Threats that match no expected
    entry at all count as false positives.
    """
    matched_threat_indices: set[int] = set()
    detected = False
    category_correct = False
    severity_in_range = False
    specific_match = False

    for expected_threat in expected.expected_threats:
        candidates = [
            (i, t) for i, t in enumerate(produced_threats) if _keyword_match(t, expected_threat)
        ]
        if not candidates:
            continue
        detected = True
        matched_threat_indices.update(i for i, _ in candidates)

        category_matches = [
            (i, t) for i, t in candidates if t.stride_category == expected_threat.stride_category
        ]
        if category_matches:
            category_correct = True
            severity_in_range = severity_in_range or any(
                expected_threat.severity_in_range(_severity(t)) for _, t in category_matches
            )

        if any(_path_match(t, expected_threat) for _, t in candidates):
            specific_match = True

    false_positives = sum(
        1 for i in range(len(produced_threats)) if i not in matched_threat_indices
    )

    return ScenarioScore(
        scenario_id=scenario_id,
        detected=detected,
        category_correct=category_correct,
        severity_in_range=severity_in_range,
        specific_match=specific_match,
        cost_usd=cost_usd,
        latency_s=latency_s,
        false_positives=false_positives,
    )


def _severity(threat: ThreatLike) -> SeverityLabel:
    severity = threat.severity
    if severity not in ("low", "medium", "high", "critical"):
        raise ValueError(f"Unrecognised severity {severity!r} on threat {threat.title!r}")
    return severity  # type: ignore[return-value]


def score_scenario_dir(
    scenario_dir: Path,
    *,
    threats_path: Path,
    run_record_path: Path,
    latency_s: float,
) -> ScenarioScore:
    """I/O wrapper: load files, then call `score_scenario`.

    `threats_path` / `run_record_path` point at the orchestrator's
    fresh-per-scenario `.loupe/threats.yaml` and the run record it just
    wrote — not at anything under `scenario_dir/actual-runs/` (the
    orchestrator copies those files there itself, after scoring).
    """
    expected = ExpectedThreatsFile.load(scenario_dir / "expected-threats.yaml")
    produced = _load_produced_threats(threats_path)
    run_record = json.loads(run_record_path.read_text())
    return score_scenario(
        scenario_dir.name,
        expected,
        produced,
        cost_usd=run_record["cost_usd_estimate"],
        latency_s=latency_s,
    )


def _load_produced_threats(threats_path: Path) -> list[ThreatLike]:
    if not threats_path.exists():
        return []
    from ruamel.yaml import YAML

    with threats_path.open("r") as f:
        data: dict[str, Any] = YAML(typ="safe").load(f) or {}
    return [_ThreatRecord(**t) for t in data.get("threats", [])]


class _ThreatRecord:
    """Minimal `ThreatLike` built from a raw `threats.yaml` entry dict."""

    def __init__(self, **fields: Any) -> None:
        self.title: str = fields["title"]
        self.description: str = fields["description"]
        self.rationale: str = fields["rationale"]
        self.stride_category: str = fields["stride_category"]
        self.severity: str = fields["severity"]
