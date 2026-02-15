from __future__ import annotations

from datetime import UTC, date, datetime

from loupe_action.formatter import (
    COMMENT_SENTINEL,
    format_pr_comment,
)
from loupe_core.artifacts.run_record import LensConsidered, RunRecord
from loupe_core.artifacts.threat import Threat
from loupe_core.artifacts.types import Severity, StrideCategory, ThreatStatus


def _threat(
    id: str,
    sev: Severity,
    title: str = "Some threat",
    category: StrideCategory = StrideCategory.SPOOFING,
) -> Threat:
    return Threat(
        id=id,
        element_id="E-001",
        stride_category=category,
        title=title,
        description="A test threat",
        severity=sev,
        status=ThreatStatus.PROPOSED,
        mitigation_ids=[],
        cwe_refs=[],
        attack_pattern_refs=[],
        last_reviewed=date(2026, 5, 15),
        rationale="test rationale",
        proposed_by="threatlens",
    )


def _run_record(run_id: str = "run-abc123", lenses_run: list[str] | None = None) -> RunRecord:
    return RunRecord(
        run_id=run_id,
        timestamp=datetime.now(UTC),
        mode="ci",
        invoked_by="loupe-action",
        trigger="github_pr",
        base_sha="a" * 40,
        head_sha="b" * 40,
        diff_hash="d" * 64,
        context_md_hash="c" * 64,
        lenses_considered=[
            LensConsidered(name="threatlens", score=0.9, reason="code changes")
        ],
        lenses_run=lenses_run or ["threatlens"],
        models_used={"threatlens": "anthropic:claude-opus-4-7"},
        total_tokens_in=12000,
        total_tokens_out=800,
        cost_usd_estimate=0.07,
        cache_hit_rate=0.65,
        artifacts_changed=[".loupe/threats.yaml"],
        proposed_patches=[],
        pending_decisions=[],
        prev_run_hash=None,
        self_hash="hashhash",
    )


def test_comment_starts_with_machine_readable_sentinel():
    # The sentinel is what makes the sticky-comment poster idempotent —
    # it's the marker the poster greps for to find a prior Loupe comment.
    body = format_pr_comment(record=_run_record(), threats=[])
    assert body.startswith(COMMENT_SENTINEL)


def test_comment_includes_run_id():
    body = format_pr_comment(record=_run_record(run_id="run-xyz789"), threats=[])
    assert "run-xyz789" in body


def test_comment_groups_threats_by_severity_descending():
    threats = [
        _threat("T-001", Severity.LOW, "Low one"),
        _threat("T-002", Severity.CRITICAL, "Critical one"),
        _threat("T-003", Severity.MEDIUM, "Medium one"),
        _threat("T-004", Severity.HIGH, "High one"),
    ]
    body = format_pr_comment(record=_run_record(), threats=threats)
    # Critical must appear before High, which must appear before Medium, etc.
    pos_crit = body.find("Critical one")
    pos_high = body.find("High one")
    pos_med = body.find("Medium one")
    pos_low = body.find("Low one")
    assert -1 < pos_crit < pos_high < pos_med < pos_low


def test_clean_run_shows_explicit_no_findings_block():
    body = format_pr_comment(record=_run_record(), threats=[])
    assert "No threats" in body or "no findings" in body.lower()


def test_comment_includes_lenses_run_summary():
    body = format_pr_comment(
        record=_run_record(lenses_run=["threatlens", "autocyber"]), threats=[]
    )
    assert "threatlens" in body
    assert "autocyber" in body


def test_comment_includes_cost_estimate_when_present():
    body = format_pr_comment(record=_run_record(), threats=[])
    assert "0.07" in body or "$0.07" in body


def test_comment_includes_run_hash_footer_for_audit_trail():
    body = format_pr_comment(record=_run_record(), threats=[])
    # The hash chain is the tamper-evidence story — a reviewer should be
    # able to find the run's hash in the comment and cross-reference
    # the run-records file.
    assert "hashhash" in body


def test_comment_lists_proposed_patches_when_present():
    record = _run_record()
    record.proposed_patches = [".proposed/context.md.patch"]
    body = format_pr_comment(record=record, threats=[])
    assert ".proposed/context.md.patch" in body


def test_severity_counts_in_summary_line():
    threats = [
        _threat("T-001", Severity.CRITICAL),
        _threat("T-002", Severity.HIGH),
        _threat("T-003", Severity.HIGH),
        _threat("T-004", Severity.MEDIUM),
    ]
    body = format_pr_comment(record=_run_record(), threats=threats)
    # Summary should call out the counts so a reviewer eyeballing the PR
    # can triage without expanding the details section.
    assert "1 critical" in body.lower()
    assert "2 high" in body.lower()
    assert "1 medium" in body.lower()
