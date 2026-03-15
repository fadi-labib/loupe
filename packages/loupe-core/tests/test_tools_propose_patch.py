from pathlib import Path

import pytest
from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.tools import BoundaryViolation, propose_patch


def test_propose_patch_rejects_dotdot_escape(tmp_path):
    """`target_path=".."` would resolve outside `.proposed/` if not blocked."""
    loupe_dir = tmp_path / ".loupe"
    pb = PathBoundary(writable_globs=[])
    with pytest.raises(ValueError, match="path traversal"):
        propose_patch(
            boundary=pb,
            loupe_dir=loupe_dir,
            target_path="..",
            unified_diff="",
            rationale="",
            run_id="run-1",
        )


def test_propose_patch_rejects_nested_dotdot(tmp_path):
    loupe_dir = tmp_path / ".loupe"
    pb = PathBoundary(writable_globs=[])
    with pytest.raises(ValueError, match="path traversal"):
        propose_patch(
            boundary=pb,
            loupe_dir=loupe_dir,
            target_path="foo/../../etc/passwd",
            unified_diff="",
            rationale="",
            run_id="run-1",
        )


def test_propose_patch_rejects_absolute_path(tmp_path):
    loupe_dir = tmp_path / ".loupe"
    pb = PathBoundary(writable_globs=[])
    with pytest.raises(ValueError, match="absolute"):
        propose_patch(
            boundary=pb,
            loupe_dir=loupe_dir,
            target_path="/etc/passwd",
            unified_diff="",
            rationale="",
            run_id="run-1",
        )


def test_propose_patch_rejects_nul_byte(tmp_path):
    loupe_dir = tmp_path / ".loupe"
    pb = PathBoundary(writable_globs=[])
    with pytest.raises(ValueError, match="NUL"):
        propose_patch(
            boundary=pb,
            loupe_dir=loupe_dir,
            target_path="foo\x00bar",
            unified_diff="",
            rationale="",
            run_id="run-1",
        )


def test_propose_patch_rejects_empty_target(tmp_path):
    loupe_dir = tmp_path / ".loupe"
    pb = PathBoundary(writable_globs=[])
    with pytest.raises(ValueError, match="empty"):
        propose_patch(
            boundary=pb,
            loupe_dir=loupe_dir,
            target_path="",
            unified_diff="",
            rationale="",
            run_id="run-1",
        )


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
    pb = PathBoundary(writable_globs=["agent-owned.yaml"])
    with pytest.raises(BoundaryViolation):
        propose_patch(
            boundary=pb,
            loupe_dir=loupe_dir,
            target_path="agent-owned.yaml",
            unified_diff="",
            rationale="",
            run_id="run-1",
        )
