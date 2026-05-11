"""`loupe chat` — Layer 4 enforcement entry point.

Reviews staged `.loupe/.proposed/<...>.patch` files with a
`[y/N/edit/skip]` prompt. Approved proposals are `git apply`'d to their
target file and the `.patch` is moved to `.applied/`. Skipped proposals
move to `.skipped/`. Deferred proposals (default-N) stay in `.proposed/`
for next session.

The default is intentionally "N" — Enter means "do not apply,"
matching VALUES.md §5 (humans stay in the decision seat).

There is no `--auto-confirm` flag. There is no environment variable that
lowers the bar. By design. See decisions.md D-02 and D-08.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import click
import typer
from rich.console import Console
from rich.syntax import Syntax

from loupe_cli.ci_cmd import ci_command
from loupe_cli.patch_apply import apply_unified_diff
from loupe_cli.proposals import Proposal, load_proposals, move_proposal

# BSD sysexits.h EX_USAGE — operator-config / usage errors.
USAGE_ERROR = 64

_console = Console()


def _stdin_is_tty() -> bool:
    """Indirection so tests can patch the TTY check directly.

    `sys.stdin.isatty()` is hard to mock under typer.testing.CliRunner
    because click's `invoke()` replaces `sys.stdin` with a fake stream
    for the duration of the call, which clobbers any monkeypatch on the
    original `sys.stdin`. Patching this function works because the patch
    is on the module attribute, not on the stdin object.
    """
    return sys.stdin.isatty()


def chat_command(
    review_only: bool = False,
    diff_text: str = "",
    base_sha: str | None = None,
    head_sha: str | None = None,
    config_path: Path | None = None,
) -> int:
    """Layer 4 interactive review of staged `.loupe/.proposed/` patches.

    Preconditions (all must hold):
      1. Running in a TTY (use `loupe ci` for headless).
      2. `.loupe/` exists in cwd.
      3. `git` is on PATH.
      4. `.loupe/.proposed/` is clean against HEAD (committed).

    When `review_only=False` (default), runs `ci_command` first so the
    session always reviews fresh proposals. When `review_only=True`,
    operates on whatever is already in `.loupe/.proposed/`.
    """
    if not _stdin_is_tty():
        typer.echo(
            "loupe chat requires an interactive TTY. "
            "Use `loupe ci` for headless / scripted contexts.",
            err=True,
        )
        return USAGE_ERROR

    cwd = Path.cwd()
    loupe_dir = cwd / ".loupe"
    if not loupe_dir.exists():
        typer.echo(
            "Error: .loupe/ not found in the current directory.\nRun `loupe init` first.",
            err=True,
        )
        return USAGE_ERROR

    if shutil.which("git") is None:
        typer.echo(
            "Error: git not found on PATH. loupe chat requires git for apply.",
            err=True,
        )
        return USAGE_ERROR

    if not _proposed_dir_is_clean(cwd):
        typer.echo(
            "Error: .loupe/.proposed/ has uncommitted changes.\n"
            "Commit them first so they're in git history as a baseline:\n"
            "  git add .loupe/.proposed/\n"
            '  git commit -m "stage proposals from ci run"\n'
            "Then re-run `loupe chat`.",
            err=True,
        )
        return USAGE_ERROR

    pre_existing = load_proposals(loupe_dir)
    if review_only:
        proposals = pre_existing
    else:
        keep_carryover = True
        if pre_existing:
            keep_carryover = typer.confirm(
                f"{len(pre_existing)} unreviewed proposals from previous run(s) found.\n"
                "Include in this review session?",
                default=True,
            )
        ci_exit = ci_command(
            diff_text,
            base_sha,
            head_sha,
            config_path or (loupe_dir / "config.yaml"),
        )
        # Exit codes 0 (clean) and 1 (gate failure: still has artefacts) are
        # both fine to continue from — both mean ci wrote artefacts. Other
        # codes (64 = usage error, etc.) mean ci itself failed; bail.
        if ci_exit not in (0, 1):
            typer.echo(
                f"loupe ci failed with exit {ci_exit}; aborting chat session.",
                err=True,
            )
            return ci_exit
        all_now = load_proposals(loupe_dir)
        if keep_carryover:
            proposals = all_now
        else:
            pre_paths = {p.patch_file_path for p in pre_existing}
            proposals = [p for p in all_now if p.patch_file_path not in pre_paths]

    if not proposals:
        typer.echo("Clean run; nothing to review.")
        return 0

    typer.echo(f"{len(proposals)} proposals to review.")
    outcomes: list[str] = []
    for i, p in enumerate(proposals, start=1):
        outcomes.append(_review_one_proposal(p, index=i, total=len(proposals), repo_root=cwd))

    return _print_summary(outcomes)


def confirm_with_diff(target: str, unified_diff: str, rationale: str) -> bool:
    """Default-N prompt with diff preview, used by every protected-path proposal.

    No --auto-confirm flag, no environment override. Layer 4 by design.
    Returns True iff the user explicitly typed `y`. Anything else
    (including empty input, the literal "edit", "skip", or "N") returns False.
    """
    typer.echo(f"\nProposed change to: {target}")
    typer.echo(unified_diff)
    typer.echo(f"Rationale: {rationale}")
    answer: str = typer.prompt("Apply? [y/N/edit/skip]", default="N", show_default=False)
    return answer.strip().lower() == "y"


def _proposed_dir_is_clean(repo_root: Path) -> bool:
    """True if `.loupe/.proposed/` has no untracked or modified files vs HEAD."""
    proposed = repo_root / ".loupe" / ".proposed"
    if not proposed.exists():
        return True
    result = subprocess.run(
        ["git", "status", "--porcelain", "--", ".loupe/.proposed"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == ""


def _review_one_proposal(
    proposal: Proposal,
    index: int,
    total: int,
    repo_root: Path,
) -> str:
    """Walk the y/N/edit/skip prompt for one proposal.

    Returns an outcome label: ``applied``, ``edited-applied``, ``skipped``,
    ``deferred``, or ``failed`` (user wanted to apply but declined re-edit).
    """
    typer.echo(f"\nProposal {index}/{total}: {proposal.target_path} (protected)")
    _console.print(Syntax(proposal.diff_body, "diff", theme="ansi_dark"))
    typer.echo(f"Rationale: {proposal.rationale}")
    answer = typer.prompt("Apply? [y/N/edit/skip]", default="N", show_default=False)
    choice = answer.strip().lower()

    if choice == "y":
        result = apply_unified_diff(repo_root=repo_root, diff_text=proposal.diff_body)
        if result.applied:
            move_proposal(proposal, to_state="applied", repo_root=repo_root)
            typer.echo(f"✓ applied to {proposal.target_path}")
            return "applied"
        typer.echo(f"git apply failed:\n{result.stderr}")
        retry = typer.prompt("Re-edit? [y/N]", default="N", show_default=False)
        if retry.strip().lower() != "y":
            return "failed"
        return _run_edit_flow(proposal, repo_root, starting_diff=proposal.diff_body)

    if choice == "skip":
        move_proposal(proposal, to_state="skipped", repo_root=repo_root)
        typer.echo("↷ moved to .loupe/.skipped/")
        return "skipped"

    if choice == "edit":
        return _run_edit_flow(proposal, repo_root, starting_diff=proposal.diff_body)

    # Empty input, 'N', or anything else: deferred (Layer 4 default-N).
    return "deferred"


def _run_edit_flow(proposal: Proposal, repo_root: Path, starting_diff: str) -> str:
    """Open `click.edit()` on the diff. Dry-run check. Secondary y/N. Apply or revert."""
    edited = click.edit(starting_diff, extension=".patch")
    if not edited or not edited.strip():
        typer.echo("Edit cancelled; proposal deferred.")
        return "deferred"
    check = apply_unified_diff(repo_root=repo_root, diff_text=edited, dry_run=True)
    if not check.applied:
        typer.echo(f"Edited diff doesn't apply cleanly:\n{check.stderr}")
        return "deferred"
    secondary = typer.prompt("Apply edited? [y/N]", default="N", show_default=False)
    if secondary.strip().lower() != "y":
        typer.echo("Edit declined; proposal deferred.")
        return "deferred"
    final_apply = apply_unified_diff(repo_root=repo_root, diff_text=edited)
    if not final_apply.applied:
        typer.echo(f"Apply failed after dry-run passed (race?):\n{final_apply.stderr}")
        return "failed"
    move_proposal(proposal, to_state="applied", repo_root=repo_root)
    typer.echo(f"✓ applied to {proposal.target_path} (human-edited)")
    return "edited-applied"


def _print_summary(outcomes: list[str]) -> int:
    """End-of-session summary. Returns the chat exit code."""
    applied = outcomes.count("applied")
    edited_applied = outcomes.count("edited-applied")
    skipped = outcomes.count("skipped")
    deferred = outcomes.count("deferred")
    failed = outcomes.count("failed")
    summary = (
        f"\nReviewed {len(outcomes)} proposals: "
        f"{applied} applied, {edited_applied} edited+applied, "
        f"{deferred} deferred, {skipped} skipped"
    )
    if failed:
        summary += f", {failed} failed-apply"
    typer.echo(summary + ".")
    if applied or edited_applied:
        typer.echo(
            "\nApplied changes modify your working tree but are not committed.\n"
            "Review with `git diff`, then commit when ready\n"
            "(or `git restore <path>` to abort a specific file)."
        )
    return 1 if failed else 0
