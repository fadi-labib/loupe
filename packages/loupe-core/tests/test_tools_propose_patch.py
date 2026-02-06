import pytest
from pathlib import Path
from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.tools import propose_patch, BoundaryViolation


def test_stages_proposal_in_proposed_dir(tmp_path):
    loupe_dir = tmp_path / ".loupe"
    pb = PathBoundary(writable_globs=[str(loupe_dir / "agent-owned.yaml")])
    out = propose_patch(
        boundary=pb,
        loupe_dir=loupe_dir,
        target_path="context.md",
        unified_diff="--- a/context.md\n+++ b/context.md\n@@ -1 +1 @@\n-old\n+new\n",
        rationale="Add refund flow",
        run_id="run-1",
    )
    assert "/.proposed/" in out
    assert Path(out).exists()
    body = Path(out).read_text()
    assert "Add refund flow" in body
    assert "+new" in body


def test_rejects_agent_writable_target(tmp_path):
    loupe_dir = tmp_path / ".loupe"
    pb = PathBoundary(writable_globs=[str(loupe_dir / "agent-owned.yaml")])
    with pytest.raises(BoundaryViolation):
        propose_patch(
            boundary=pb,
            loupe_dir=loupe_dir,
            target_path=str(loupe_dir / "agent-owned.yaml"),
            unified_diff="",
            rationale="",
            run_id="run-1",
        )
