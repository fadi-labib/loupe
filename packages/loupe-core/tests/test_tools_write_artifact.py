import os

import pytest
from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.tools import BoundaryViolation, write_agent_artifact


def test_writes_allowed_path(tmp_path):
    pb = PathBoundary(writable_globs=[str(tmp_path / "ok.txt")])
    out = write_agent_artifact(pb, tmp_path / "ok.txt", "hello")
    assert out == str(tmp_path / "ok.txt")
    assert (tmp_path / "ok.txt").read_text() == "hello"


def test_rejects_disallowed_path(tmp_path):
    pb = PathBoundary(writable_globs=[str(tmp_path / "ok.txt")])
    with pytest.raises(BoundaryViolation):
        write_agent_artifact(pb, tmp_path / "human.md", "x")


def test_rejects_symlink_at_target(tmp_path):
    """A pre-planted symlink at the target must not redirect the write.

    Without O_NOFOLLOW, ``Path.write_text`` would follow the symlink and
    overwrite the target outside the boundary — a Layer 1 TOCTOU breach.
    """
    outside = tmp_path / "secrets.txt"
    outside.write_text("INITIAL")
    target = tmp_path / "threats.yaml"
    os.symlink(outside, target)

    pb = PathBoundary(writable_globs=[str(target)])
    with pytest.raises(BoundaryViolation, match="symlink"):
        write_agent_artifact(pb, target, "MALICIOUS")
    assert outside.read_text() == "INITIAL", "symlink was followed — Layer 1 breached"


def test_rejects_symlinked_parent(tmp_path):
    """A symlinked parent directory must also be rejected (full chain check)."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "secrets.txt").write_text("INITIAL")
    parent_link = tmp_path / "linked"
    os.symlink(outside_dir, parent_link)
    target = parent_link / "secrets.txt"

    pb = PathBoundary(writable_globs=[str(target)])
    with pytest.raises(BoundaryViolation, match="symlink"):
        write_agent_artifact(pb, target, "MALICIOUS")
    assert (outside_dir / "secrets.txt").read_text() == "INITIAL"
