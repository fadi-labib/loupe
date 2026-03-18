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


def test_write_agent_artifact_rejects_symlinked_parent_dir(tmp_path):
    """Layer 1 must not follow a symlink even at a parent-directory component.

    Scenario: attacker pre-plants a real directory at .loupe/subdir, the loop
    check sees it as a real dir, then between the check and the open the
    attacker swaps it for a symlink pointing outside .loupe/. The O_NOFOLLOW
    flag on the final open does not protect parent components — only dir_fd
    walking with O_DIRECTORY | O_NOFOLLOW does.

    We model this by setting up the symlinked parent before the call; if the
    fix uses dir_fd walking, the symlinked parent is rejected at open time.
    """
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    outside = tmp_path / "evil"
    outside.mkdir()
    (outside / "threats.yaml").write_text("INITIAL")

    # Replace .loupe/subdir with a symlink to .../evil/
    os.symlink(outside, loupe / "subdir")

    target = loupe / "subdir" / "threats.yaml"
    pb = PathBoundary(writable_globs=[str(target)])
    with pytest.raises(BoundaryViolation, match="symlink"):
        write_agent_artifact(pb, target, "MALICIOUS")
    assert (outside / "threats.yaml").read_text() == "INITIAL", (
        "parent symlink was followed — Layer 1 breached"
    )


def test_write_agent_artifact_writes_full_content_for_large_payload(tmp_path):
    """Confirm the full content lands even for a payload larger than typical
    POSIX short-write thresholds (~64KB). With os.fdopen + .write the stdio
    layer loops internally, so this should be trivially true; we test it
    explicitly so a future regression to bare os.write() is caught."""
    target = tmp_path / "big.yaml"
    pb = PathBoundary(writable_globs=[str(target)])
    big = "x" * 200_000  # 200KB; well above any reasonable short-write window
    write_agent_artifact(pb, target, big)
    written = target.read_text()
    assert written == big, (
        f"truncation: wrote {len(big)} bytes, read back {len(written)}"
    )
