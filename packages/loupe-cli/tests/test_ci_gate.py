"""Tests for the `ci.fail_on` gate logic in loupe ci.

Verifies the small, deterministic exit-code function — no LLM, no
network, no agent invocation. The end-to-end gate behavior (lens runs,
proposes threats, ci returns 1) is the integration concern of
`test_ci_real.py`; this file pins the function-level contract.
"""

from datetime import datetime

from loupe_cli.ci_cmd import _gate_exit_code
from loupe_core.config import CIConfig, LoupeConfig
from loupe_core.run_context import RunContext


def _ctx(threats: list[dict]) -> RunContext:
    """RunContext with the given Threat-shaped dicts in findings."""
    ctx = RunContext(
        run_id="r-gate",
        mode="ci",
        started_at=datetime(2026, 5, 15),
        user_intent="",
        diff=None,
        sbom_delta=None,
        project=None,
        plan=[],
        knowledge=None,
    )
    for t in threats:
        ctx.record_finding("threatlens", f"threat:{t['id']}", t)
    return ctx


def _cfg(fail_on: list[str]) -> LoupeConfig:
    return LoupeConfig(ci=CIConfig(fail_on=fail_on))


def test_empty_fail_on_returns_zero_regardless_of_findings():
    """Report-only mode: fail_on=[] means we never exit non-zero."""
    ctx = _ctx([{"id": "T-001", "severity": "critical"}])
    assert _gate_exit_code(ctx, _cfg(fail_on=[])) == 0


def test_no_threats_returns_zero():
    """No findings means no gate trigger."""
    assert _gate_exit_code(_ctx([]), _cfg(fail_on=["critical", "high"])) == 0


def test_critical_threat_with_critical_in_fail_on_exits_one():
    ctx = _ctx([{"id": "T-001", "severity": "critical"}])
    assert _gate_exit_code(ctx, _cfg(fail_on=["critical"])) == 1


def test_only_low_threat_with_critical_high_in_fail_on_returns_zero():
    """Severity 'low' below the gate → exit 0."""
    ctx = _ctx([{"id": "T-001", "severity": "low"}])
    assert _gate_exit_code(ctx, _cfg(fail_on=["critical", "high"])) == 0


def test_multiple_threats_one_triggers_exits_one():
    ctx = _ctx(
        [
            {"id": "T-001", "severity": "low"},
            {"id": "T-002", "severity": "medium"},
            {"id": "T-003", "severity": "high"},
        ]
    )
    assert _gate_exit_code(ctx, _cfg(fail_on=["high"])) == 1


def test_multiple_fail_on_severities():
    """Gate fires on any threat whose severity matches any listed level."""
    ctx = _ctx(
        [
            {"id": "T-001", "severity": "medium"},
        ]
    )
    assert _gate_exit_code(ctx, _cfg(fail_on=["medium", "high", "critical"])) == 1


def test_non_threat_findings_ignored():
    """ctx.findings can hold non-threat keys; the gate must only inspect 'threat:*'."""
    ctx = RunContext(
        run_id="r",
        mode="ci",
        started_at=datetime(2026, 5, 15),
        user_intent="",
        diff=None,
        sbom_delta=None,
        project=None,
        plan=[],
        knowledge=None,
    )
    ctx.record_finding("threatlens", "metric:total_calls", {"value": 3, "severity": "critical"})
    assert _gate_exit_code(ctx, _cfg(fail_on=["critical"])) == 0


def _cfg_with_warn(*, fail_on: list[str], warn_on: list[str]) -> LoupeConfig:
    return LoupeConfig(ci=CIConfig(fail_on=fail_on, warn_on=warn_on))


def test_warn_only_threat_returns_zero():
    """Severity in warn_on but not in fail_on → exit 0 with a warning surfaced."""
    ctx = _ctx([{"id": "T-001", "severity": "medium"}])
    cfg = _cfg_with_warn(fail_on=["critical", "high"], warn_on=["medium"])
    assert _gate_exit_code(ctx, cfg) == 0


def test_warn_and_fail_threats_exits_one():
    """Mix of warn and fail severities: warnings print, exit code follows fail_on."""
    ctx = _ctx(
        [
            {"id": "T-001", "severity": "medium"},
            {"id": "T-002", "severity": "critical"},
        ]
    )
    cfg = _cfg_with_warn(fail_on=["critical"], warn_on=["medium"])
    assert _gate_exit_code(ctx, cfg) == 1


def test_severity_in_both_lists_takes_fail_precedence():
    """If a severity appears in both fail_on and warn_on, fail wins (no double-count)."""
    ctx = _ctx([{"id": "T-001", "severity": "high"}])
    cfg = _cfg_with_warn(fail_on=["high"], warn_on=["high"])
    assert _gate_exit_code(ctx, cfg) == 1


def test_empty_fail_and_warn_returns_zero_silently():
    """Pure report-only mode: no gate output, no exit-code change."""
    ctx = _ctx([{"id": "T-001", "severity": "critical"}])
    cfg = _cfg_with_warn(fail_on=[], warn_on=[])
    assert _gate_exit_code(ctx, cfg) == 0


def test_warn_only_config_returns_zero_even_at_critical():
    """A pure warn_on=[critical] config should never exit non-zero — warn doesn't gate."""
    ctx = _ctx([{"id": "T-001", "severity": "critical"}])
    cfg = _cfg_with_warn(fail_on=[], warn_on=["critical"])
    assert _gate_exit_code(ctx, cfg) == 0
