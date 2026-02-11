from datetime import datetime

import pytest
from loupe_core.artifacts.threat import ThreatsFile
from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.run_context import RunContext
from loupe_threatlens.tools import ProposeThreatInput, propose_threat_impl


def _ctx() -> RunContext:
    return RunContext(
        run_id="r", mode="ci", started_at=datetime(2026, 5, 14),
        user_intent="", diff=None, sbom_delta=None,
        project=None, plan=[], knowledge=None,
    )


def _input(**overrides):
    base = dict(
        element_id="E-001",
        stride_category="S",
        title="Spoof",
        description="Caller spoofing",
        severity="high",
        rationale="High due to PAN",
        cwe_refs=[],
        mitigation_ids=[],
    )
    base.update(overrides)
    return ProposeThreatInput(**base)


def test_propose_threat_adds_to_threats_yaml(tmp_path):
    loupe_dir = tmp_path / ".loupe"
    loupe_dir.mkdir()
    boundary = PathBoundary(writable_globs=[str(loupe_dir / "threats.yaml")])
    ctx = _ctx()

    result = propose_threat_impl(
        ctx, boundary, loupe_dir,
        _input(),
        model_id="anthropic:claude-opus-4-7",
    )

    assert result.threat_id == "T-001"
    assert result.status == "written"

    loaded = ThreatsFile.load(loupe_dir / "threats.yaml")
    assert len(loaded.threats) == 1
    assert loaded.threats[0].title == "Spoof"
    assert loaded.threats[0].proposed_by == "threatlens/anthropic:claude-opus-4-7"


def test_propose_threat_assigns_sequential_ids(tmp_path):
    loupe_dir = tmp_path / ".loupe"
    loupe_dir.mkdir()
    boundary = PathBoundary(writable_globs=[str(loupe_dir / "threats.yaml")])
    ctx = _ctx()

    r1 = propose_threat_impl(ctx, boundary, loupe_dir, _input(), model_id="m")
    r2 = propose_threat_impl(ctx, boundary, loupe_dir, _input(), model_id="m")
    r3 = propose_threat_impl(ctx, boundary, loupe_dir, _input(), model_id="m")

    assert r1.threat_id == "T-001"
    assert r2.threat_id == "T-002"
    assert r3.threat_id == "T-003"

    loaded = ThreatsFile.load(loupe_dir / "threats.yaml")
    assert {t.id for t in loaded.threats} == {"T-001", "T-002", "T-003"}


def test_propose_threat_records_finding_in_runcontext(tmp_path):
    loupe_dir = tmp_path / ".loupe"
    loupe_dir.mkdir()
    boundary = PathBoundary(writable_globs=[str(loupe_dir / "threats.yaml")])
    ctx = _ctx()

    propose_threat_impl(ctx, boundary, loupe_dir, _input(), model_id="m")

    finding = ctx.lookup("threatlens", "threat:T-001")
    assert finding is not None
    assert finding["title"] == "Spoof"


def test_propose_threat_id_continues_after_existing_threats(tmp_path):
    """If threats.yaml already has T-001 and T-002, next ID should be T-003."""
    loupe_dir = tmp_path / ".loupe"
    loupe_dir.mkdir()
    boundary = PathBoundary(writable_globs=[str(loupe_dir / "threats.yaml")])
    ctx = _ctx()

    # Seed two threats
    propose_threat_impl(ctx, boundary, loupe_dir, _input(), model_id="m")
    propose_threat_impl(ctx, boundary, loupe_dir, _input(), model_id="m")

    # Fresh ctx, fresh load: existing file is read, IDs continue
    fresh_ctx = _ctx()
    r3 = propose_threat_impl(fresh_ctx, boundary, loupe_dir, _input(), model_id="m")
    assert r3.threat_id == "T-003"


def test_propose_threat_with_invalid_severity_rejected(tmp_path):
    """Pydantic should reject inputs with a bad severity literal."""
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        _input(severity="catastrophic")
