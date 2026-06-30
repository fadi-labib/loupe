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

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

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


async def _find_existing_sub_pr(
    *,
    client: httpx.AsyncClient,
    api_url: str,
    repo_owner: str,
    repo_name: str,
    head_branch: str,
    base_branch: str,
    token: str,
) -> str | None:
    """GET /repos/.../pulls?head=<owner>:<head>&base=<base>&state=open.

    Returns the first matching PR's html_url, or None if no open PR
    matches. Raises httpx.HTTPStatusError on non-2xx responses.
    """
    response = await client.get(
        f"{api_url}/repos/{repo_owner}/{repo_name}/pulls",
        params={
            "head": f"{repo_owner}:{head_branch}",
            "base": base_branch,
            "state": "open",
        },
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    response.raise_for_status()
    prs = cast(list[dict[str, Any]], response.json())
    if not prs:
        return None
    return cast(str, prs[0]["html_url"])


def format_sub_pr_body(
    *,
    repo_owner: str,
    repo_name: str,
    pr_number: int,
    head_sha: str,
    findings_summary: str,
    run_id: str,
    run_hash: str,
    lenses: list[str],
    cost_usd: float,
    cache_hit_rate: float,
) -> str:
    """Render the sub-PR body markdown.

    The body verbatim-quotes the PAT scope so an auditor reading any
    past sub-PR sees the security property in-place. Future maintainers
    changing the scope leave a footprint in every sub-PR ever created.
    """
    lenses_str = ", ".join(lenses) if lenses else "(none)"
    cache_str = f"{cache_hit_rate * 100:.0f}%" if cache_hit_rate else "n/a"
    return (
        f"## Loupe analysis for PR #{pr_number}\n\n"
        f"This PR contains the `.loupe/` artefacts produced by Loupe's CI run "
        f"against [PR #{pr_number}](https://github.com/{repo_owner}/{repo_name}/pull/{pr_number}) "
        f"at commit `{head_sha}`.\n\n"
        f"**Findings:** {findings_summary}.\n\n"
        f"Merge this PR to integrate the analysis into the original PR's branch.\n\n"
        f"<details>\n<summary>Run details</summary>\n\n"
        f"- **Run id:** `{run_id}`\n"
        f"- **Run hash:** `{run_hash}`\n"
        f"- **Lenses run:** {lenses_str}\n"
        f"- **Cost (estimate):** ${cost_usd:.2f}\n"
        f"- **Prompt-cache hit rate:** {cache_str}\n\n"
        f"</details>\n\n"
        f"---\n\n"
        f"🤖 This PR was opened by the Loupe GitHub Action with the `LOUPE_PAT` "
        f"token, scoped `contents: write` only on refs matching "
        f"`loupe/proposal-*`. See [D-08](../docs/reference/decisions.md#d-08) "
        f"and [D-27](../docs/reference/decisions.md#d-27) for the audit story.\n"
    )


async def _create_sub_pr(
    *,
    client: httpx.AsyncClient,
    api_url: str,
    repo_owner: str,
    repo_name: str,
    pr_number: int,
    head_branch: str,
    base_branch: str,
    head_sha: str,
    findings_summary: str,
    run_id: str,
    run_hash: str,
    lenses: list[str],
    cost_usd: float,
    cache_hit_rate: float,
    token: str,
) -> str:
    """POST /repos/.../pulls. Returns the new PR's html_url.

    Raises httpx.HTTPStatusError on non-2xx (caller maps to AutoCommitResult).
    """
    body = format_sub_pr_body(
        repo_owner=repo_owner,
        repo_name=repo_name,
        pr_number=pr_number,
        head_sha=head_sha,
        findings_summary=findings_summary,
        run_id=run_id,
        run_hash=run_hash,
        lenses=lenses,
        cost_usd=cost_usd,
        cache_hit_rate=cache_hit_rate,
    )
    response = await client.post(
        f"{api_url}/repos/{repo_owner}/{repo_name}/pulls",
        json={
            "title": f"loupe: analysis for PR-{pr_number}",
            "head": head_branch,
            "base": base_branch,
            "body": body,
        },
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    response.raise_for_status()
    return cast(str, response.json()["html_url"])


async def commit_and_open_sub_pr(
    *,
    workspace: Path,
    api_url: str,
    repo_owner: str,
    repo_name: str,
    pr_number: int,
    original_pr_branch: str,
    head_sha: str,
    run_id: str,
    run_hash: str,
    lenses: list[str],
    findings_summary: str,
    cost_usd: float,
    cache_hit_rate: float,
    commit_author: str,
    pat: str,
    client: httpx.AsyncClient,
) -> AutoCommitResult:
    """Auto-commit .loupe/ to a side branch and open (or update) a sub-PR.

    See docs/plans/2026-05-17-track-a-layer2-autocommit-design.md §4 for
    the full sequence. Summary:

    1. Fetch `loupe/proposal-<pr_number>` from origin (does it exist?).
    2. Checkout / create the side branch (from head_sha if new).
    3. Stage + commit .loupe/ (skip if empty diff).
    4. Push (no force). Conflict is an error, not a recovery.
    5. List existing open PRs with this head/base; create one if missing.

    Returns AutoCommitResult capturing the outcome.
    """
    side_branch = f"loupe/proposal-{pr_number}"

    try:
        exists = _side_branch_exists(workspace, side_branch)
    except subprocess.CalledProcessError as exc:
        return AutoCommitResult(
            branch_pushed=None,
            sub_pr_url=None,
            created_new_pr=False,
            failed=True,
            error=f"git fetch failed: {exc.stderr or exc.stdout}",
        )

    loupe_dir = workspace / ".loupe"
    if exists:
        # The workspace may have untracked or locally-modified .loupe/ files
        # (freshly produced by the current CI run). Stash them to a temp dir,
        # force-checkout the side branch (which may carry an older .loupe/),
        # then restore the new content so _commit_loupe_changes picks it up.
        with tempfile.TemporaryDirectory() as _tmp:
            tmp = Path(_tmp)
            if loupe_dir.exists():
                shutil.copytree(str(loupe_dir), str(tmp / ".loupe"))
            subprocess.run(
                ["git", "checkout", "-f", side_branch],
                cwd=workspace,
                check=True,
                capture_output=True,
            )
            if (tmp / ".loupe").exists():
                if loupe_dir.exists():
                    shutil.rmtree(str(loupe_dir))
                shutil.copytree(str(tmp / ".loupe"), str(loupe_dir))
    else:
        subprocess.run(
            ["git", "checkout", "-b", side_branch],
            cwd=workspace,
            check=True,
            capture_output=True,
        )

    try:
        committed = _commit_loupe_changes(
            workspace=workspace,
            pr_number=pr_number,
            run_id=run_id,
            lenses=lenses,
            findings_summary=findings_summary,
            commit_author=commit_author,
        )
    except subprocess.CalledProcessError as exc:
        return AutoCommitResult(
            branch_pushed=None,
            sub_pr_url=None,
            created_new_pr=False,
            failed=True,
            error=f"git commit failed: {exc.stderr or exc.stdout}",
        )
    if not committed:
        return AutoCommitResult(
            branch_pushed=side_branch,
            sub_pr_url=None,
            created_new_pr=False,
            failed=False,
            error=None,
        )

    push = _push_side_branch(workspace, side_branch)
    if not push.success:
        return AutoCommitResult(
            branch_pushed=None,
            sub_pr_url=None,
            created_new_pr=False,
            failed=True,
            error=f"git push failed: {push.error}",
        )

    try:
        existing_url = await _find_existing_sub_pr(
            client=client,
            api_url=api_url,
            repo_owner=repo_owner,
            repo_name=repo_name,
            head_branch=side_branch,
            base_branch=original_pr_branch,
            token=pat,
        )
    except httpx.HTTPStatusError as exc:
        return AutoCommitResult(
            branch_pushed=side_branch,
            sub_pr_url=None,
            created_new_pr=False,
            failed=True,
            error=f"GitHub PR list failed: {exc.response.status_code} {exc.response.text}",
        )

    if existing_url is not None:
        return AutoCommitResult(
            branch_pushed=side_branch,
            sub_pr_url=existing_url,
            created_new_pr=False,
            failed=False,
            error=None,
        )

    try:
        new_url = await _create_sub_pr(
            client=client,
            api_url=api_url,
            repo_owner=repo_owner,
            repo_name=repo_name,
            pr_number=pr_number,
            head_branch=side_branch,
            base_branch=original_pr_branch,
            head_sha=head_sha,
            findings_summary=findings_summary,
            run_id=run_id,
            run_hash=run_hash,
            lenses=lenses,
            cost_usd=cost_usd,
            cache_hit_rate=cache_hit_rate,
            token=pat,
        )
    except httpx.HTTPStatusError as exc:
        return AutoCommitResult(
            branch_pushed=side_branch,
            sub_pr_url=None,
            created_new_pr=False,
            failed=True,
            error=f"GitHub PR create failed: {exc.response.status_code} {exc.response.text}",
        )

    return AutoCommitResult(
        branch_pushed=side_branch,
        sub_pr_url=new_url,
        created_new_pr=True,
        failed=False,
        error=None,
    )
