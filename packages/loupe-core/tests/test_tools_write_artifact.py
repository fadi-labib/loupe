
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
