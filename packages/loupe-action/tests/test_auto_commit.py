"""Tests for the auto-commit + sub-PR module.

Pattern follows existing loupe-action tests:
- httpx.MockTransport for GitHub API mocking
- file-based git remotes (git init --bare) for push tests; no live HTTPS
"""

from loupe_action.auto_commit import AutoCommitResult


def test_auto_commit_result_dataclass():
    """The result is a frozen dataclass with success and failure shapes."""
    success = AutoCommitResult(
        branch_pushed="loupe/proposal-1234",
        sub_pr_url="https://github.com/org/repo/pull/1235",
        created_new_pr=True,
        failed=False,
        error=None,
    )
    assert success.branch_pushed == "loupe/proposal-1234"
    assert success.failed is False

    failure = AutoCommitResult(
        branch_pushed=None,
        sub_pr_url=None,
        created_new_pr=False,
        failed=True,
        error="git push rejected: non-fast-forward",
    )
    assert failure.failed is True
    assert "non-fast-forward" in failure.error


import subprocess
from pathlib import Path

from loupe_action.auto_commit import _side_branch_exists


def _make_bare_remote(tmp_path: Path) -> Path:
    """Create a bare git repo at tmp_path/remote.git to serve as origin.

    File-based bare remotes accept push/fetch without network or auth —
    ideal for unit-testing git command structure.
    """
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    return bare


def _init_working_repo(tmp_path: Path, remote: Path) -> Path:
    """Init a working repo at tmp_path/work pointing origin at the bare remote."""
    work = tmp_path / "work"
    subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
    subprocess.run(["git", "config", "user.email", "t@e.com"], cwd=work, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=work, check=True)
    subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=work, check=True)
    return work


def test_side_branch_exists_returns_false_when_missing(tmp_path):
    """git fetch for a missing ref returns False (and doesn't blow up)."""
    remote = _make_bare_remote(tmp_path)
    work = _init_working_repo(tmp_path, remote)

    exists = _side_branch_exists(work, "loupe/proposal-1234")
    assert exists is False


def test_side_branch_exists_returns_true_when_present(tmp_path):
    """When the side branch exists on the remote, the function returns True."""
    remote = _make_bare_remote(tmp_path)
    work = _init_working_repo(tmp_path, remote)

    (work / "f").write_text("x")
    subprocess.run(["git", "add", "."], cwd=work, check=True)
    subprocess.run(["git", "commit", "-qm", "seed"], cwd=work, check=True)
    subprocess.run(["git", "branch", "loupe/proposal-1234"], cwd=work, check=True)
    subprocess.run(["git", "push", "-q", "origin", "loupe/proposal-1234"], cwd=work, check=True)
    subprocess.run(["git", "branch", "-D", "loupe/proposal-1234"], cwd=work, check=True)

    exists = _side_branch_exists(work, "loupe/proposal-1234")
    assert exists is True


from loupe_action.auto_commit import _commit_loupe_changes


def test_commit_loupe_changes_happy_path(tmp_path):
    """Stages .loupe/ and creates a commit with the specified author."""
    remote = _make_bare_remote(tmp_path)
    work = _init_working_repo(tmp_path, remote)
    subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", "init"], cwd=work, check=True)

    loupe = work / ".loupe"
    loupe.mkdir()
    (loupe / "threats.yaml").write_text("threats: []\n")
    (loupe / "runs").mkdir()
    (loupe / "runs" / "run-aaa.json").write_text('{"run_id": "aaa"}')

    committed = _commit_loupe_changes(
        workspace=work,
        pr_number=1234,
        run_id="aaa",
        lenses=["threatlens"],
        findings_summary="1 high, 2 medium",
        commit_author="MyBot <bot@example.com>",
    )

    assert committed is True

    log = subprocess.run(
        ["git", "log", "-1", "--format=%an|%ae|%s"],
        cwd=work,
        capture_output=True,
        text=True,
        check=True,
    )
    name, email, subject = log.stdout.strip().split("|", 2)
    assert name == "MyBot"
    assert email == "bot@example.com"
    assert "aaa" in subject
    assert "1234" in subject


def test_commit_loupe_changes_skips_empty(tmp_path):
    """If .loupe/ has no changes vs HEAD, returns False without committing."""
    remote = _make_bare_remote(tmp_path)
    work = _init_working_repo(tmp_path, remote)

    loupe = work / ".loupe"
    loupe.mkdir()
    (loupe / "threats.yaml").write_text("threats: []\n")
    subprocess.run(["git", "add", "."], cwd=work, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=work, check=True)

    committed = _commit_loupe_changes(
        workspace=work,
        pr_number=1234,
        run_id="aaa",
        lenses=["threatlens"],
        findings_summary="no findings",
        commit_author="MyBot <bot@example.com>",
    )

    assert committed is False
