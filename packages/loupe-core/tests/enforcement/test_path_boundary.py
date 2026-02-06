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
