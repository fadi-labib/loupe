"""Tests for the `git apply` wrapper used by `loupe chat` to apply
human-approved proposals to their target files."""

import subprocess
from pathlib import Path

from loupe_cli.patch_apply import ApplyResult, apply_unified_diff


def _init_repo_with_file(tmp_path: Path, relpath: str, content: str) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@e.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=tmp_path, check=True)
    target = tmp_path / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=tmp_path, check=True)


def test_apply_unified_diff_happy_path(tmp_path):
    """A clean diff applies to a clean target. Working tree reflects the patched content."""
    _init_repo_with_file(tmp_path, ".loupe/context.md", "line1\nline2\nline3\n")

    diff = (
        "--- a/.loupe/context.md\n"
        "+++ b/.loupe/context.md\n"
        "@@ -1,3 +1,4 @@\n"
        " line1\n"
        " line2\n"
        "+line2.5\n"
        " line3\n"
    )

    result = apply_unified_diff(repo_root=tmp_path, diff_text=diff)

    assert isinstance(result, ApplyResult)
    assert result.applied is True
    assert result.stderr == ""

    final = (tmp_path / ".loupe" / "context.md").read_text()
    assert final == "line1\nline2\nline2.5\nline3\n"


def test_apply_unified_diff_conflict_returns_stderr(tmp_path):
    """If the target file has changed since the proposal was staged,
    `git apply --check` fails. Returns applied=False with git's stderr."""
    _init_repo_with_file(tmp_path, ".loupe/context.md", "line1\nline2\nline3\n")

    # Modify the target so the patch no longer applies cleanly.
    (tmp_path / ".loupe" / "context.md").write_text("completely\ndifferent\ncontent\n")

    diff = (
        "--- a/.loupe/context.md\n"
        "+++ b/.loupe/context.md\n"
        "@@ -1,3 +1,4 @@\n"
        " line1\n"
        " line2\n"
        "+line2.5\n"
        " line3\n"
    )

    result = apply_unified_diff(repo_root=tmp_path, diff_text=diff)

    assert result.applied is False
    assert result.stderr  # git tells us what went wrong
    # Working tree is NOT changed by the failed apply.
    assert (tmp_path / ".loupe" / "context.md").read_text() == "completely\ndifferent\ncontent\n"


def test_apply_unified_diff_refuses_path_escape(tmp_path):
    """git apply default-refuses paths that escape the working tree.
    We assert this so the test fails loudly if we ever add --unsafe-paths."""
    _init_repo_with_file(tmp_path, ".loupe/context.md", "x\n")

    # A malicious diff trying to escape the repo root.
    diff = (
        "--- a/../etc/passwd\n"
        "+++ b/../etc/passwd\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+pwned\n"
    )

    result = apply_unified_diff(repo_root=tmp_path, diff_text=diff)

    assert result.applied is False
    assert result.stderr  # git rejected it
