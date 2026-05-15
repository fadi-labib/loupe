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


from loupe_action.auto_commit import PushResult, _push_side_branch


def test_push_side_branch_happy_path(tmp_path):
    """Push succeeds; result reports success and no stderr."""
    remote = _make_bare_remote(tmp_path)
    work = _init_working_repo(tmp_path, remote)
    (work / "f").write_text("x")
    subprocess.run(["git", "add", "."], cwd=work, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=work, check=True)
    subprocess.run(["git", "checkout", "-q", "-b", "loupe/proposal-1234"], cwd=work, check=True)

    result = _push_side_branch(work, "loupe/proposal-1234")

    assert result.success is True
    assert result.error is None


def test_push_side_branch_rejects_non_fast_forward(tmp_path):
    """If the remote side branch diverged, push is rejected (no force)."""
    remote = _make_bare_remote(tmp_path)
    work = _init_working_repo(tmp_path, remote)

    (work / "a").write_text("a")
    subprocess.run(["git", "add", "."], cwd=work, check=True)
    subprocess.run(["git", "commit", "-qm", "a"], cwd=work, check=True)
    subprocess.run(["git", "checkout", "-q", "-b", "loupe/proposal-1234"], cwd=work, check=True)
    subprocess.run(["git", "push", "-q", "origin", "loupe/proposal-1234"], cwd=work, check=True)

    work2 = tmp_path / "work2"
    subprocess.run(["git", "clone", "-q", str(remote), str(work2)], check=True)
    subprocess.run(["git", "config", "user.email", "t2@e.com"], cwd=work2, check=True)
    subprocess.run(["git", "config", "user.name", "T2"], cwd=work2, check=True)
    subprocess.run(["git", "checkout", "-q", "loupe/proposal-1234"], cwd=work2, check=True)
    (work2 / "b").write_text("b")
    subprocess.run(["git", "add", "."], cwd=work2, check=True)
    subprocess.run(["git", "commit", "-qm", "b"], cwd=work2, check=True)
    subprocess.run(["git", "push", "-q", "origin", "loupe/proposal-1234"], cwd=work2, check=True)

    (work / "c").write_text("c")
    subprocess.run(["git", "add", "."], cwd=work, check=True)
    subprocess.run(["git", "commit", "-qm", "c"], cwd=work, check=True)

    result = _push_side_branch(work, "loupe/proposal-1234")

    assert result.success is False
    assert "non-fast-forward" in result.error.lower() or "rejected" in result.error.lower()


import httpx
import pytest

from loupe_action.auto_commit import _find_existing_sub_pr


@pytest.mark.asyncio
async def test_find_existing_sub_pr_returns_none_when_no_pr():
    """If the GitHub PR list is empty, returns None."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/fadi-labib/loupe/pulls"
        assert request.url.params["head"] == "fadi-labib:loupe/proposal-1234"
        assert request.url.params["base"] == "feature/x"
        assert request.url.params["state"] == "open"
        return httpx.Response(200, json=[])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        url = await _find_existing_sub_pr(
            client=client,
            api_url="https://api.github.com",
            repo_owner="fadi-labib",
            repo_name="loupe",
            head_branch="loupe/proposal-1234",
            base_branch="feature/x",
            token="github_pat_xxx",
        )
    assert url is None


@pytest.mark.asyncio
async def test_find_existing_sub_pr_returns_url_when_present():
    """If the PR list has one entry, returns its html_url."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[
            {"html_url": "https://github.com/fadi-labib/loupe/pull/9999"}
        ])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        url = await _find_existing_sub_pr(
            client=client,
            api_url="https://api.github.com",
            repo_owner="fadi-labib",
            repo_name="loupe",
            head_branch="loupe/proposal-1234",
            base_branch="feature/x",
            token="github_pat_xxx",
        )
    assert url == "https://github.com/fadi-labib/loupe/pull/9999"


@pytest.mark.asyncio
async def test_find_existing_sub_pr_403_raises():
    """403 means the PAT lacks pull-requests:read; surface to caller."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "Resource not accessible"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await _find_existing_sub_pr(
                client=client,
                api_url="https://api.github.com",
                repo_owner="fadi-labib",
                repo_name="loupe",
                head_branch="loupe/proposal-1234",
                base_branch="feature/x",
                token="bad_token",
            )


from loupe_action.auto_commit import _create_sub_pr, format_sub_pr_body


@pytest.mark.asyncio
async def test_create_sub_pr_posts_with_correct_body():
    """Create-PR call uses the right title/head/base/body shape."""
    captured: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        captured.append(json.loads(request.content))
        return httpx.Response(201, json={"html_url": "https://github.com/fadi-labib/loupe/pull/5678"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        url = await _create_sub_pr(
            client=client,
            api_url="https://api.github.com",
            repo_owner="fadi-labib",
            repo_name="loupe",
            pr_number=1234,
            head_branch="loupe/proposal-1234",
            base_branch="feature/x",
            head_sha="abc123def",
            findings_summary="2 high, 1 medium",
            run_id="run-bbb",
            run_hash="4f0cb9d2",
            lenses=["threatlens"],
            cost_usd=0.12,
            cache_hit_rate=0.78,
            token="github_pat_xxx",
        )
    assert url == "https://github.com/fadi-labib/loupe/pull/5678"
    body = captured[0]
    assert body["title"] == "loupe: analysis for PR-1234"
    assert body["head"] == "loupe/proposal-1234"
    assert body["base"] == "feature/x"
    assert "2 high, 1 medium" in body["body"]
    assert "PR #1234" in body["body"]
    assert "run-bbb" in body["body"]


def test_format_sub_pr_body_includes_pat_scope_quote():
    """The body verbatim-quotes the PAT scope for audit-credibility."""
    body = format_sub_pr_body(
        repo_owner="fadi-labib",
        repo_name="loupe",
        pr_number=1234,
        head_sha="abc123",
        findings_summary="1 high",
        run_id="run-aaa",
        run_hash="deadbeef",
        lenses=["threatlens"],
        cost_usd=0.05,
        cache_hit_rate=0.0,
    )
    assert "contents: write" in body
    assert "loupe/proposal-*" in body
    assert "[D-08]" in body
    assert "[D-27]" in body
