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
