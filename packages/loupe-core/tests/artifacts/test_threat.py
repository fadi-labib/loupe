from datetime import date
import pytest
from pydantic import ValidationError
from loupe_core.artifacts.threat import Threat, ThreatsFile
from loupe_core.artifacts.types import Severity, ThreatStatus, StrideCategory


def _valid_threat_kwargs():
    return dict(
        id="T-001",
        element_id="E-001",
        stride_category=StrideCategory.SPOOFING,
        title="Spoof internal caller",
        description="An attacker that compromises an internal service could call this API.",
        severity=Severity.HIGH,
        status=ThreatStatus.PROPOSED,
        mitigation_ids=[],
        introduced_in_pr=None,
        last_reviewed=date(2026, 5, 13),
        review_due=None,
        rationale="High severity due to PAN access.",
        proposed_by="threatlens/anthropic/claude-opus-4-7",
    )


def test_threat_minimal_valid():
    t = Threat(**_valid_threat_kwargs())
    assert t.id == "T-001"
    assert t.severity == Severity.HIGH


def test_threat_id_format():
    with pytest.raises(ValidationError):
        Threat(**{**_valid_threat_kwargs(), "id": "INVALID"})


def test_threats_file_serializes_yaml(tmp_path):
    f = ThreatsFile(threats=[Threat(**_valid_threat_kwargs())])
    path = tmp_path / "threats.yaml"
    f.save(path)
    text = path.read_text()
    assert "T-001" in text
    assert "severity: high" in text


def test_threats_file_loads_yaml(tmp_path):
    f = ThreatsFile(threats=[Threat(**_valid_threat_kwargs())])
    path = tmp_path / "threats.yaml"
    f.save(path)
    loaded = ThreatsFile.load(path)
    assert len(loaded.threats) == 1
    assert loaded.threats[0].id == "T-001"
