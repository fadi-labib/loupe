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
