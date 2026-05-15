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
