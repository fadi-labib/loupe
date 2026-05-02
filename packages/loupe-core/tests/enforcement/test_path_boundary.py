from pathlib import Path

import pytest
from loupe_core.enforcement.path_boundary import PathBoundary


def test_exact_path_match():
    pb = PathBoundary(writable_globs=[".loupe/threats.yaml"])
    assert pb.is_agent_writable(".loupe/threats.yaml")
    assert not pb.is_agent_writable(".loupe/context.md")


def test_glob_wildcard():
    pb = PathBoundary(writable_globs=[".loupe/runs/**"])
    assert pb.is_agent_writable(".loupe/runs/2026-05-13T14-32Z-run-1.json")
    assert pb.is_agent_writable(".loupe/runs/nested/file.json")
    assert not pb.is_agent_writable(".loupe/decisions/x.md")


def test_traversal_blocked():
    pb = PathBoundary(writable_globs=[".loupe/threats.yaml"])
    assert not pb.is_agent_writable(".loupe/../secret")
    assert not pb.is_agent_writable("/etc/passwd")


def test_recursive_glob_does_not_overmatch_siblings():
    """`.loupe/**` MUST NOT match `.loupe-old/x` or `.loupex/y`.

    Recursive globs must require either an exact prefix match or a path that
    starts with prefix followed by a path separator. A bare startswith() check
    would weaken the Layer 1 boundary by letting any path that shares the
    prefix as a string match the glob.
    """
    pb = PathBoundary(writable_globs=[".loupe/**"])
    assert pb.is_agent_writable(".loupe/")
    assert pb.is_agent_writable(".loupe/runs/x.json")
    assert pb.is_agent_writable(".loupe/nested/deeper/file.json")
    # These MUST be rejected — they share the prefix as a substring but aren't inside .loupe/
    assert not pb.is_agent_writable(".loupe-old/owned.txt")
    assert not pb.is_agent_writable(".loupex/file.txt")
    assert not pb.is_agent_writable(".loupe.bak")


def test_absolute_path_under_project_root_matches_relative_glob(tmp_path: Path) -> None:
    """The real end-to-end CI flow constructs write targets as
    `Path.cwd() / .loupe / threats.yaml` — an absolute path. The
    scaffolded `agent_writable_paths` uses *relative* globs
    (`.loupe/threats.yaml`). Before the project_root fix, fnmatch
    compared `'/tmp/.../mongoose/.loupe/threats.yaml'` against
    `'.loupe/threats.yaml'` and always returned False, breaking the
    very first propose_threat tool call.
    """
    pb = PathBoundary(
        writable_globs=[".loupe/threats.yaml", ".loupe/runs/**"],
        project_root=tmp_path,
    )
    abs_threats = str(tmp_path / ".loupe" / "threats.yaml")
    abs_run = str(tmp_path / ".loupe" / "runs" / "run-abc.json")
    abs_other = str(tmp_path / ".loupe" / "context.md")
    assert pb.is_agent_writable(abs_threats)
    assert pb.is_agent_writable(abs_run)
    assert not pb.is_agent_writable(abs_other)


def test_absolute_path_outside_project_root_rejected(tmp_path: Path) -> None:
    """An absolute path that doesn't live under project_root cannot be
    silently relativised — it stays absolute and must miss every
    relative glob. This guards against accidental allow-list widening.
    """
    pb = PathBoundary(
        writable_globs=[".loupe/threats.yaml"],
        project_root=tmp_path,
    )
    # /etc is not under tmp_path; must be rejected unconditionally.
    assert not pb.is_agent_writable("/etc/passwd")
    # A sibling tmp directory is also not under project_root.
    elsewhere = tmp_path.parent / "loupe-sibling" / ".loupe" / "threats.yaml"
    assert not pb.is_agent_writable(str(elsewhere))


def test_project_root_must_be_absolute(tmp_path: Path) -> None:
    """If `project_root` is supplied it must be absolute; a relative
    project_root would be relativised against CWD on every call, which
    is exactly the implicit-CWD ambiguity this fix removes.
    """
    with pytest.raises(ValueError, match="absolute"):
        PathBoundary(
            writable_globs=[".loupe/threats.yaml"],
            project_root=Path("relative/dir"),
        )


def test_backwards_compat_no_project_root_still_works(tmp_path: Path) -> None:
    """Older callers (and the existing test suite) construct
    PathBoundary without `project_root`, and rely on plain fnmatch
    against absolute inputs when the glob list itself is absolute
    (e.g. tests that pass `str(tmp_path / "echo.txt")` in both places).
    That legacy fnmatch path must still work; an absolute input must
    not be silently relativised when there's no project_root to
    relativise against.
    """
    rel_pb = PathBoundary(writable_globs=[".loupe/threats.yaml"])
    assert rel_pb.is_agent_writable(".loupe/threats.yaml")
    # Absolute input without project_root → no relativisation, raw
    # fnmatch. The relative glob never matches; reject.
    assert not rel_pb.is_agent_writable(str(tmp_path / ".loupe" / "threats.yaml"))

    # Absolute glob + absolute input (legacy test pattern) still matches.
    abs_target = str(tmp_path / "echo.txt")
    abs_pb = PathBoundary(writable_globs=[abs_target])
    assert abs_pb.is_agent_writable(abs_target)


# ---------------------------------------------------------------------------
# safe_read_under — read-side mirror of write_agent_artifact (B.2 / D-24)
# ---------------------------------------------------------------------------


def test_safe_read_under_accepts_file_inside_project_root(tmp_path: Path) -> None:
    from loupe_core.enforcement.path_boundary import safe_read_under

    target = tmp_path / "src" / "mqtt.c"
    target.parent.mkdir()
    target.write_bytes(b"int main(){return 0;}\n")
    content = safe_read_under(project_root=tmp_path, target=target, max_bytes=1024)
    assert content == b"int main(){return 0;}\n"


def test_safe_read_under_rejects_path_outside_project_root(tmp_path: Path) -> None:
    """A target that resolves outside project_root must be refused with
    BoundaryViolation. Mirror of F-02 write-side semantics applied to reads."""
    from loupe_core.enforcement.path_boundary import safe_read_under
    from loupe_core.tools import BoundaryViolation

    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"secret")
    with pytest.raises(BoundaryViolation, match="project_root"):
        safe_read_under(project_root=project, target=outside, max_bytes=1024)


def test_safe_read_under_rejects_symlink_to_outside(tmp_path: Path) -> None:
    """A symlink inside the project whose target resolves outside must be
    refused. O_NOFOLLOW on the leaf catches this case before bytes are read."""
    from loupe_core.enforcement.path_boundary import safe_read_under
    from loupe_core.tools import BoundaryViolation

    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"secret")
    link = project / "escape.txt"
    link.symlink_to(outside)
    with pytest.raises(BoundaryViolation, match="symlink"):
        safe_read_under(project_root=project, target=link, max_bytes=1024)


def test_safe_read_under_rejects_parent_component_symlink(tmp_path: Path) -> None:
    """If any parent of the target is a symlink, the walk's O_NOFOLLOW
    on intermediate components must refuse — defends against a TOCTOU
    where a parent dir is swapped for a symlink between check and use."""
    from loupe_core.enforcement.path_boundary import safe_read_under
    from loupe_core.tools import BoundaryViolation

    project = tmp_path / "project"
    project.mkdir()
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    (real_dir / "file.txt").write_bytes(b"data")
    link_dir = project / "linked"
    link_dir.symlink_to(real_dir)
    with pytest.raises(BoundaryViolation, match="symlink"):
        safe_read_under(project_root=project, target=link_dir / "file.txt", max_bytes=1024)


def test_safe_read_under_raises_read_too_large_on_oversize_file(tmp_path: Path) -> None:
    from loupe_core.enforcement.path_boundary import ReadTooLarge, safe_read_under

    target = tmp_path / "big.txt"
    target.write_bytes(b"x" * 10_000)
    with pytest.raises(ReadTooLarge) as exc_info:
        safe_read_under(project_root=tmp_path, target=target, max_bytes=1000)
    # The exception carries enough detail for a friendly truncation marker.
    assert exc_info.value.actual_bytes >= 10_000
    assert exc_info.value.max_bytes == 1000


def test_safe_read_under_rejects_nul_byte_in_path(tmp_path: Path) -> None:
    from loupe_core.enforcement.path_boundary import safe_read_under
    from loupe_core.tools import BoundaryViolation

    # The string-level path passed to safe_read_under cannot contain NUL.
    # We pass Path because the caller usually does — but we still want the
    # check there to catch a NUL slipped in via str manipulation.
    with pytest.raises((BoundaryViolation, ValueError)):
        safe_read_under(project_root=tmp_path, target=Path("src/\x00.c"), max_bytes=1024)


def test_safe_read_under_requires_absolute_project_root(tmp_path: Path) -> None:
    from loupe_core.enforcement.path_boundary import safe_read_under

    with pytest.raises(ValueError, match="absolute"):
        safe_read_under(
            project_root=Path("relative/dir"),
            target=Path("file.txt"),
            max_bytes=1024,
        )
