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
