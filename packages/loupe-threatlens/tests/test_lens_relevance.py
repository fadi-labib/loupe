from datetime import datetime

from loupe_core.run_context import CodeDiff, RunContext
from loupe_threatlens.lens import ThreatLens


def _ctx(paths: list[str]) -> RunContext:
    return RunContext(
        run_id="r", mode="ci", started_at=datetime(2026, 5, 13),
        user_intent="",
        diff=CodeDiff(
            base_sha="a", head_sha="b", changed_paths=paths,
            added_lines=1, removed_lines=0, raw_unified="",
        ),
        sbom_delta=None, project=None, plan=[], knowledge=None,
    )


def test_high_relevance_on_code_changes():
    lens = ThreatLens()
    score = lens.is_relevant(_ctx(["src/api.py", "lib/utils.py"]))
    assert score.score >= 0.9


def test_medium_relevance_on_deps_only():
    lens = ThreatLens()
    score = lens.is_relevant(_ctx(["requirements.txt"]))
    assert 0.6 <= score.score <= 0.85


def test_low_relevance_on_docs_only():
    lens = ThreatLens()
    score = lens.is_relevant(_ctx(["docs/README.md", "docs/guide.md"]))
    assert score.score < 0.3


def test_ci_workflow_changes_are_medium_relevance():
    lens = ThreatLens()
    score = lens.is_relevant(_ctx([".github/workflows/deploy.yml"]))
    assert 0.5 <= score.score <= 0.7


def test_no_diff_returns_low_relevance():
    """In diff mode without a diff, relevance is low (full-repo scan goes via D-15)."""
    lens = ThreatLens()
    ctx = RunContext(
        run_id="r", mode="ci", started_at=datetime(2026, 5, 13),
        user_intent="", diff=None, sbom_delta=None, project=None, plan=[], knowledge=None,
    )
    score = lens.is_relevant(ctx)
    assert score.score < 0.3
