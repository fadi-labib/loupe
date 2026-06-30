"""Deterministic unit tests for the scoring engine.

No LLM calls, no network, no fixtures beyond plain Python objects — this
is the free, CI-gated half of the benchmark suite (see
benchmarks/README.md § Cost and determinism for the split between this
and the live, paid orchestrator runs).
"""

from __future__ import annotations

from scoring.manifest import ExpectedThreat, ExpectedThreatsFile
from scoring.score_run import score_scenario


class _FakeThreat:
    def __init__(
        self,
        *,
        title: str = "",
        description: str = "",
        rationale: str = "",
        stride_category: str = "T",
        severity: str = "medium",
    ) -> None:
        self.title = title
        self.description = description
        self.rationale = rationale
        self.stride_category = stride_category
        self.severity = severity


def _expected(
    *,
    title_keywords: list[str],
    stride_category: str = "T",
    severity_min: str = "medium",
    severity_max: str = "critical",
    must_reference_paths: list[str] | None = None,
) -> ExpectedThreatsFile:
    return ExpectedThreatsFile(
        expected_threats=[
            ExpectedThreat(
                title_keywords=title_keywords,
                stride_category=stride_category,  # type: ignore[arg-type]
                severity_min=severity_min,  # type: ignore[arg-type]
                severity_max=severity_max,  # type: ignore[arg-type]
                must_reference_paths=must_reference_paths or [],
            )
        ]
    )


def test_no_produced_threats_is_undetected():
    expected = _expected(title_keywords=["overflow"])
    score = score_scenario("S1", expected, [], cost_usd=0.01, latency_s=1.0)
    assert score.detected is False
    assert score.category_correct is False
    assert score.false_positives == 0


def test_keyword_match_in_rationale_detects():
    expected = _expected(title_keywords=["decode_varint", "mqtt"])
    produced = [_FakeThreat(rationale="The decode_varint cast truncates props_size.")]
    score = score_scenario("S1", expected, produced, cost_usd=0.02, latency_s=1.0)
    assert score.detected is True
    assert score.false_positives == 0


def test_category_mismatch_is_detected_but_not_category_correct():
    expected = _expected(title_keywords=["overflow"], stride_category="D")
    produced = [_FakeThreat(title="buffer overflow", stride_category="T")]
    score = score_scenario("S1", expected, produced, cost_usd=0.02, latency_s=1.0)
    assert score.detected is True
    assert score.category_correct is False
    assert score.severity_in_range is False


def test_severity_out_of_range_is_not_in_range():
    expected = _expected(
        title_keywords=["overflow"],
        stride_category="D",
        severity_min="high",
        severity_max="critical",
    )
    produced = [_FakeThreat(title="overflow", stride_category="D", severity="low")]
    score = score_scenario("S1", expected, produced, cost_usd=0.02, latency_s=1.0)
    assert score.category_correct is True
    assert score.severity_in_range is False


def test_severity_in_range_when_matched_and_within_bounds():
    expected = _expected(
        title_keywords=["overflow"],
        stride_category="D",
        severity_min="medium",
        severity_max="critical",
    )
    produced = [_FakeThreat(title="overflow", stride_category="D", severity="high")]
    score = score_scenario("S1", expected, produced, cost_usd=0.02, latency_s=1.0)
    assert score.severity_in_range is True


def test_specific_match_requires_path_reference():
    expected = _expected(title_keywords=["overflow"], must_reference_paths=["src/mqtt.c"])
    generic = [_FakeThreat(title="overflow", description="some generic overflow")]
    score = score_scenario("S1", expected, generic, cost_usd=0.02, latency_s=1.0)
    assert score.detected is True
    assert score.specific_match is False

    grounded = [_FakeThreat(title="overflow", description="overflow in src/mqtt.c parser")]
    score2 = score_scenario("S1", expected, grounded, cost_usd=0.02, latency_s=1.0)
    assert score2.specific_match is True


def test_specific_match_true_by_default_with_no_required_paths():
    expected = _expected(title_keywords=["overflow"])
    produced = [_FakeThreat(title="overflow")]
    score = score_scenario("S1", expected, produced, cost_usd=0.02, latency_s=1.0)
    assert score.specific_match is True


def test_unmatched_threats_count_as_false_positives():
    expected = _expected(title_keywords=["overflow"])
    produced = [
        _FakeThreat(title="buffer overflow in parser"),
        _FakeThreat(title="unrelated SSRF concern in totally different code"),
    ]
    score = score_scenario("S1", expected, produced, cost_usd=0.02, latency_s=1.0)
    assert score.detected is True
    assert score.false_positives == 1


def test_cost_and_latency_pass_through_unchanged():
    expected = _expected(title_keywords=["overflow"])
    score = score_scenario("S1", expected, [], cost_usd=0.0734, latency_s=12.5)
    assert score.cost_usd == 0.0734
    assert score.latency_s == 12.5
