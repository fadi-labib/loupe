"""GitHub Action auto-commit + sub-PR mechanics.

Layer 2's runtime enforcement: when opted in via auto_commit_loupe_dir,
the Action pushes .loupe/ artefacts to a loupe/proposal-<pr-id> side
branch and opens a sub-PR targeting the original PR's branch. The
PAT is scoped contents:write only on refs matching `loupe/proposal-*`,
so the agent CANNOT push to main or feature branches even if Layer 1
had a bug. See docs/reference/decisions.md D-27.

This is the only source file in the codebase that calls `git push`:
    grep -RIn "git push" packages/  # → this file only

That mechanical property is what makes Layer 2's audit story
falsifiable: revoke the PAT, attempt a push, watch GitHub refuse.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import httpx


@dataclass(frozen=True)
class AutoCommitResult:
    """Outcome of one auto-commit + sub-PR cycle.

    On success: `branch_pushed` is the side-branch ref, `sub_pr_url` is
    the URL of the existing or newly-created sub-PR, `created_new_pr`
    indicates whether this run opened the sub-PR (True) or updated an
    existing one (False), `failed` is False, `error` is None.

    On failure: `failed=True`, `error` is a human-readable explanation,
    and `branch_pushed` / `sub_pr_url` / `created_new_pr` may all be None
    (depending on how far the operation got before failing).
    """

    branch_pushed: str | None
    sub_pr_url: str | None
    created_new_pr: bool
    failed: bool
    error: str | None


def _side_branch_exists(workspace: Path, branch: str) -> bool:
    """Return True iff `branch` exists on `origin`.

    Uses `git fetch origin <branch>` and distinguishes the missing-ref
    case from real failures by inspecting stderr. The missing-ref case
    has exit code 128 with stderr containing `couldn't find remote ref`;
    other failures (network, auth) get propagated as a subprocess error.
    """
    result = subprocess.run(
        ["git", "fetch", "origin", branch],
        cwd=workspace,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return True
    if "couldn't find remote ref" in result.stderr:
        return False
    raise subprocess.CalledProcessError(
        result.returncode, result.args, result.stdout, result.stderr
    )


def _commit_loupe_changes(
    *,
    workspace: Path,
    pr_number: int,
    run_id: str,
    lenses: list[str],
    findings_summary: str,
    commit_author: str,
) -> bool:
    """Stage .loupe/ and create a commit with the given author.

    Returns True if a commit was created, False if `.loupe/` had no
    changes vs HEAD (defensive guard — every run produces a unique
    runs/<id>.json so this should not fire in production).
    """
    subprocess.run(
        ["git", "add", ".loupe/"],
        cwd=workspace,
        check=True,
        capture_output=True,
    )
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", ".loupe/"],
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
    )
    if not status.stdout.strip():
        return False

    message = (
        f"chore(loupe): {run_id} analysis on PR-{pr_number}\n\n"
        f"Lenses: {', '.join(lenses) or '(none)'}. Findings: {findings_summary}.\n"
        f"Run record: .loupe/runs/{run_id}.json"
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=noreply@loupe.security",
            "-c",
            "user.name=loupe-agent",
            "commit",
            "-m",
            message,
            f"--author={commit_author}",
        ],
        cwd=workspace,
        check=True,
        capture_output=True,
    )
    return True


@dataclass(frozen=True)
class PushResult:
    """Outcome of a single `git push` invocation."""

    success: bool
    error: str | None


def _push_side_branch(workspace: Path, branch: str) -> PushResult:
    """`git push origin <branch>`. No --force, no --force-with-lease.

    Returns PushResult(success=True) on exit 0.
    Returns PushResult(success=False, error=<git stderr>) on any non-zero
    exit. The side branch is bot-owned per the design spec; a non-fast-
    forward push is treated as an error to be investigated, never auto-
    resolved by force-pushing over a human's work.
    """
    result = subprocess.run(
        ["git", "push", "origin", branch],
        cwd=workspace,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return PushResult(success=True, error=None)
    return PushResult(success=False, error=result.stderr.strip())
