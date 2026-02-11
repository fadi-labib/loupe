from datetime import datetime

from loupe_core.run_context import CodeDiff, Fact, RunContext


def _new_ctx() -> RunContext:
    return RunContext(
        run_id="run-1",
        mode="ci",
        started_at=datetime(2026, 5, 13, 14, 32),
        user_intent="analyze diff",
        diff=CodeDiff(
            base_sha="a", head_sha="b", changed_paths=["src/x.py"],
            added_lines=10, removed_lines=2, raw_unified="",
        ),
        sbom_delta=None,
        project=None,
        plan=[],
        knowledge=None,
    )


def test_record_and_lookup_finding():
    ctx = _new_ctx()
    ctx.record_finding("threatlens", "threat:T-001", {"severity": "high"})
    assert ctx.lookup("threatlens", "threat:T-001")["severity"] == "high"
    assert ctx.lookup("threatlens", "missing") is None
    assert ctx.lookup("threatlens", "missing", default="x") == "x"


def test_findings_are_namespaced():
    ctx = _new_ctx()
    ctx.record_finding("threatlens", "k", 1)
    ctx.record_finding("safetylens", "k", 2)
    assert ctx.lookup("threatlens", "k") == 1
    assert ctx.lookup("safetylens", "k") == 2


def test_post_fact_appends():
    ctx = _new_ctx()
    f = Fact(
        id="F-001", posted_by="threatlens",
        subject="asset:payment_service", predicate="handles_pii", value=True,
        confidence="high", rationale="contains PAN",
        timestamp=datetime(2026, 5, 13, 14, 32),
    )
    ctx.post_fact(f)
    assert len(ctx.facts) == 1
    assert ctx.facts[0].predicate == "handles_pii"
