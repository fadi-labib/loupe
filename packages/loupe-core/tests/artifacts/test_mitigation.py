from datetime import date

import pytest
from loupe_core.artifacts.mitigation import Evidence, Mitigation, MitigationsFile
from loupe_core.artifacts.types import MitigationStatus
from pydantic import ValidationError


def _ev():
    return Evidence(kind="code", location="src/auth.py:42-58", note=None)


def test_mitigation_minimal_valid():
    m = Mitigation(
        id="M-001",
        title="mTLS at internal ALB",
        description="Internal ALB rejects requests without a valid client cert.",
        threats_addressed=["T-001"],
        status=MitigationStatus.VERIFIED,
        evidence=[_ev()],
        verified_by="alice@example.com",
        last_verified=date(2026, 5, 13),
    )
    assert m.id == "M-001"


def test_evidence_kind_constrained():
    with pytest.raises(ValidationError):
        Evidence(kind="invalid", location="x")


def test_mitigations_file_yaml_roundtrip(tmp_path):
    f = MitigationsFile(mitigations=[
        Mitigation(
            id="M-001",
            title="t",
            description="d",
            threats_addressed=["T-001"],
            status=MitigationStatus.PLANNED,
            evidence=[],
            verified_by=None,
            last_verified=None,
        )
    ])
    p = tmp_path / "mitigations.yaml"
    f.save(p)
    loaded = MitigationsFile.load(p)
    assert loaded.mitigations[0].id == "M-001"
