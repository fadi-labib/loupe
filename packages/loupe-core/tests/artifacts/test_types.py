from loupe_core.artifacts.types import (
    Severity,
    StrideCategory,
    ThreatStatus,
)


def test_severity_values():
    assert {s.value for s in Severity} == {"low", "medium", "high", "critical"}


def test_threat_status_values():
    assert "proposed" in {s.value for s in ThreatStatus}
    assert "mitigated" in {s.value for s in ThreatStatus}


def test_stride_category_values():
    assert {c.value for c in StrideCategory} == {"S", "T", "R", "I", "D", "E"}


def test_severity_ordering():
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
