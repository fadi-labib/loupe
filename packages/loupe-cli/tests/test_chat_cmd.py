"""Tests for `loupe chat` — Layer 4 enforcement entry point.

Covers TTY guard, preconditions (.loupe/ scaffold, git on PATH, clean
.proposed/), the empty-case path, the y/N/edit/skip review loop, and
the carry-over detection prompt.
"""

import subprocess
from pathlib import Path
from unittest.mock import patch

from loupe_cli.__main__ import app
from loupe_cli.chat_cmd import confirm_with_diff
from typer.testing import CliRunner

runner = CliRunner()


# -- TTY guard + confirm_with_diff (Layer 4 primitive) --------------------


def test_chat_refuses_in_non_tty():
    """CliRunner's input is non-TTY by default — chat must refuse it."""
    result = runner.invoke(app, ["chat"])
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "tty" in combined.lower()


def test_confirm_default_n_blocks_apply():
    """Empty input (just Enter) MUST mean "don't apply" — Layer 4 default-N."""
    with patch("typer.prompt", return_value="N"):
        applied = confirm_with_diff(
            target="context.md",
            unified_diff="--- a/context.md\n+++ b/context.md\n@@ -1 +1 @@\n-x\n+y\n",
            rationale="example",
        )
    assert applied is False


def test_confirm_explicit_y_applies():
    with patch("typer.prompt", return_value="y"):
        applied = confirm_with_diff(
            target="context.md",
            unified_diff="--- a/context.md\n+++ b/context.md\n@@ -1 +1 @@\n-x\n+y\n",
            rationale="example",
        )
    assert applied is True


def test_confirm_y_case_insensitive():
    with patch("typer.prompt", return_value="Y"):
        applied = confirm_with_diff(
            target="x",
            unified_diff="diff",
            rationale="r",
        )
    assert applied is True


def test_confirm_skip_does_not_apply():
    with patch("typer.prompt", return_value="skip"):
        applied = confirm_with_diff(
            target="x",
            unified_diff="diff",
            rationale="r",
        )
    assert applied is False


# -- Helpers used by the review-loop tests --------------------------------


def _git_init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@e.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=path, check=True)


def _seed_one_committed_proposal(tmp_path: Path) -> None:
    """Create .loupe/ with one applicable .patch and commit everything.

    The .patch targets .loupe/context.md, which we also initialise.
    """
    _git_init_repo(tmp_path)
    loupe = tmp_path / ".loupe"
    loupe.mkdir(exist_ok=True)
    (loupe / "context.md").write_text("line1\nline2\nline3\n")

    proposal_dir = loupe / ".proposed" / ".loupe_context.md"
    proposal_dir.mkdir(parents=True)
    (proposal_dir / "abc.patch").write_text(
        "# Proposed patch for .loupe/context.md\n"
        "# Rationale: add line\n"
        "# Run: abc\n"
        "---\n"
        "--- a/.loupe/context.md\n"
        "+++ b/.loupe/context.md\n"
        "@@ -1,3 +1,4 @@\n"
        " line1\n"
        " line2\n"
        "+line2.5\n"
        " line3\n"
    )
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "stage proposal"], cwd=tmp_path, check=True)


# -- Precondition checks --------------------------------------------------


def test_chat_fails_when_loupe_dir_missing(tmp_path, monkeypatch):
    """If .loupe/ doesn't exist, chat must point the user at `loupe init`."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)
    result = runner.invoke(app, ["chat", "--review-only"])
    combined = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 64, combined
    assert ".loupe/" in combined
    assert "loupe init" in combined


def test_chat_fails_when_git_not_on_path(tmp_path, monkeypatch):
    """git is required for the apply / mv operations. Bail loudly if missing."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".loupe").mkdir()
    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)
    monkeypatch.setattr("loupe_cli.chat_cmd.shutil.which", lambda binary: None)
    result = runner.invoke(app, ["chat", "--review-only"])
    combined = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 64, combined
    assert "git" in combined.lower()


def test_chat_fails_when_proposed_dir_is_dirty(tmp_path, monkeypatch):
    """If .loupe/.proposed/ has uncommitted patches, chat refuses with a
    remediation hint that the user can copy-paste."""
    monkeypatch.chdir(tmp_path)
    _git_init_repo(tmp_path)
    loupe = tmp_path / ".loupe"
    proposed_dir = loupe / ".proposed" / ".loupe_context.md"
    proposed_dir.mkdir(parents=True)
    (proposed_dir / "abc.patch").write_text(
        "# Proposed patch for .loupe/context.md\n"
        "# Rationale: r\n# Run: abc\n---\n"
        "--- a/.loupe/context.md\n+++ b/.loupe/context.md\n"
    )
    # Note: NOT committed. The file is untracked.
    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)

    result = runner.invoke(app, ["chat", "--review-only"])
    combined = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 64, combined
    assert "git add .loupe" in combined
    assert "commit" in combined.lower()


# -- Empty case + ordering ------------------------------------------------


def test_chat_clean_run_when_no_proposals(tmp_path, monkeypatch):
    """With .loupe/ scaffolded but .proposed/ empty, chat exits 0
    after printing a 'nothing to review' message."""
    monkeypatch.chdir(tmp_path)
    _git_init_repo(tmp_path)
    (tmp_path / ".loupe").mkdir()
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "init", "--allow-empty"], cwd=tmp_path, check=True)
    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)

    result = runner.invoke(app, ["chat", "--review-only"])
    combined = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 0, combined
    assert "nothing to review" in combined.lower()


def test_chat_review_loop_ordering(tmp_path, monkeypatch):
    """With 3 proposals across 2 targets, the review order is alphabetical
    by target, then by run id within each target."""
    monkeypatch.chdir(tmp_path)
    _git_init_repo(tmp_path)
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    (loupe / "context.md").write_text("c\n")
    (loupe / "decisions").mkdir()
    (loupe / "decisions" / "D-12.md").write_text("d\n")

    def write_patch(target: str, run_id: str) -> None:
        encoded = target.replace("/", "_")
        d = loupe / ".proposed" / encoded
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{run_id}.patch").write_text(
            f"# Proposed patch for {target}\n"
            f"# Rationale: r\n# Run: {run_id}\n---\n"
            f"--- a/{target}\n+++ b/{target}\n"
        )

    # Out-of-order writes so we test sort behaviour.
    write_patch(".loupe/decisions/D-12.md", "zzz")
    write_patch(".loupe/context.md", "bbb")
    write_patch(".loupe/context.md", "aaa")

    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "stage"], cwd=tmp_path, check=True)

    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)

    with patch("typer.prompt", return_value="N"):
        result = runner.invoke(app, ["chat", "--review-only"])

    combined = result.stdout or ""
    idx_ctx_aaa = combined.find("Proposal 1/3: .loupe/context.md")
    idx_ctx_bbb = combined.find("Proposal 2/3: .loupe/context.md")
    idx_dec = combined.find("Proposal 3/3: .loupe/decisions/D-12.md")
    assert idx_ctx_aaa >= 0, combined
    assert idx_ctx_bbb >= 0, combined
    assert idx_dec >= 0, combined
    assert idx_ctx_aaa < idx_ctx_bbb < idx_dec


# -- Review-loop per-answer behaviour -------------------------------------


def test_chat_review_loop_accepts_proposal(tmp_path, monkeypatch):
    """When the user types 'y', the patch applies and the .patch file moves to .applied/."""
    monkeypatch.chdir(tmp_path)
    _seed_one_committed_proposal(tmp_path)
    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)

    with patch("typer.prompt", return_value="y"):
        result = runner.invoke(app, ["chat", "--review-only"])

    combined = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 0, combined
    assert "applied" in combined.lower()

    final = (tmp_path / ".loupe" / "context.md").read_text()
    assert "line2.5" in final

    assert not (tmp_path / ".loupe" / ".proposed" / ".loupe_context.md" / "abc.patch").exists()
    assert (tmp_path / ".loupe" / ".applied" / ".loupe_context.md" / "abc.patch").exists()


def test_chat_review_loop_skip_moves_to_skipped(tmp_path, monkeypatch):
    """Typing 'skip' moves the .patch to .skipped/ without modifying the target."""
    monkeypatch.chdir(tmp_path)
    _seed_one_committed_proposal(tmp_path)
    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)
    original = (tmp_path / ".loupe" / "context.md").read_text()

    with patch("typer.prompt", return_value="skip"):
        result = runner.invoke(app, ["chat", "--review-only"])

    combined = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 0, combined
    assert "skipped" in combined.lower()

    assert (tmp_path / ".loupe" / "context.md").read_text() == original
    assert not (tmp_path / ".loupe" / ".proposed" / ".loupe_context.md" / "abc.patch").exists()
    assert (tmp_path / ".loupe" / ".skipped" / ".loupe_context.md" / "abc.patch").exists()


def test_chat_review_loop_default_n_defers(tmp_path, monkeypatch):
    """Empty input / 'N' leaves the .patch in .proposed/ — Layer 4 default-N."""
    monkeypatch.chdir(tmp_path)
    _seed_one_committed_proposal(tmp_path)
    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)

    with patch("typer.prompt", return_value="N"):
        result = runner.invoke(app, ["chat", "--review-only"])

    combined = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 0, combined
    assert "deferred" in combined.lower()

    assert (tmp_path / ".loupe" / ".proposed" / ".loupe_context.md" / "abc.patch").exists()
    assert not (tmp_path / ".loupe" / ".applied").exists()
    assert not (tmp_path / ".loupe" / ".skipped").exists()


# -- Edit flow ------------------------------------------------------------


def test_chat_review_loop_edit_then_apply(tmp_path, monkeypatch):
    """'edit' opens click.edit() with the diff; if user saves an applicable
    diff and answers 'y' to the secondary prompt, it's applied as 'edited+applied'."""
    monkeypatch.chdir(tmp_path)
    _seed_one_committed_proposal(tmp_path)
    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)

    edited_diff = (
        "--- a/.loupe/context.md\n"
        "+++ b/.loupe/context.md\n"
        "@@ -1,3 +1,4 @@\n"
        " line1\n"
        " line2\n"
        "+human-edited-line\n"
        " line3\n"
    )

    prompt_returns = iter(["edit", "y"])
    with patch("typer.prompt", side_effect=lambda *a, **kw: next(prompt_returns)):
        with patch("loupe_cli.chat_cmd.click.edit", return_value=edited_diff):
            result = runner.invoke(app, ["chat", "--review-only"])

    combined = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 0, combined
    assert "edited+applied" in combined or "edited-applied" in combined

    final = (tmp_path / ".loupe" / "context.md").read_text()
    assert "human-edited-line" in final
    assert "line2.5" not in final

    assert (tmp_path / ".loupe" / ".applied" / ".loupe_context.md" / "abc.patch").exists()


def test_chat_edit_cancelled_empty_defers(tmp_path, monkeypatch):
    """If click.edit returns empty/None (user saved nothing), proposal is deferred."""
    monkeypatch.chdir(tmp_path)
    _seed_one_committed_proposal(tmp_path)
    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)

    with patch("typer.prompt", return_value="edit"):
        with patch("loupe_cli.chat_cmd.click.edit", return_value=None):
            result = runner.invoke(app, ["chat", "--review-only"])

    combined = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 0
    assert "deferred" in combined.lower() or "cancelled" in combined.lower()
    assert (tmp_path / ".loupe" / ".proposed" / ".loupe_context.md" / "abc.patch").exists()


def test_chat_edit_unapplicable_diff_defers(tmp_path, monkeypatch):
    """If the edited diff doesn't apply, proposal is deferred with git's stderr."""
    monkeypatch.chdir(tmp_path)
    _seed_one_committed_proposal(tmp_path)
    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)

    broken_diff = "this is not a valid diff at all\n"
    with patch("typer.prompt", return_value="edit"):
        with patch("loupe_cli.chat_cmd.click.edit", return_value=broken_diff):
            result = runner.invoke(app, ["chat", "--review-only"])

    combined = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 0
    assert "doesn't apply" in combined.lower() or "deferred" in combined.lower()
    assert (tmp_path / ".loupe" / ".proposed" / ".loupe_context.md" / "abc.patch").exists()


# -- Carry-over detection -------------------------------------------------


def test_chat_carry_over_prompt_skips_when_no(tmp_path, monkeypatch):
    """With existing .proposed/ but user declines carry-over, those proposals
    are NOT reviewed in this session. (Uses --review-only to bypass ci_command.)"""
    monkeypatch.chdir(tmp_path)
    _seed_one_committed_proposal(tmp_path)
    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)

    # With --review-only there's no carry-over prompt; carry-over only fires
    # when chat would run ci. We test the carry-over decline path by mocking
    # ci_command and confirm.
    with patch("loupe_cli.chat_cmd.ci_command", return_value=0):
        with patch("typer.confirm", return_value=False):
            result = runner.invoke(app, ["chat", "--diff", "(empty)"])

    combined = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 0, combined
    # User declined carry-over → no proposals → empty path
    assert "nothing to review" in combined.lower()
    # The .patch is untouched.
    assert (tmp_path / ".loupe" / ".proposed" / ".loupe_context.md" / "abc.patch").exists()


def test_chat_carry_over_prompt_includes_when_yes(tmp_path, monkeypatch):
    """With existing .proposed/ and user accepts carry-over, those proposals
    are presented in the review loop."""
    monkeypatch.chdir(tmp_path)
    _seed_one_committed_proposal(tmp_path)
    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)

    with patch("loupe_cli.chat_cmd.ci_command", return_value=0):
        with patch("typer.confirm", return_value=True):
            with patch("typer.prompt", return_value="N"):
                result = runner.invoke(app, ["chat", "--diff", "(empty)"])

    combined = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 0, combined
    assert "1 proposals to review" in combined or "Proposal 1/1" in combined


# -- Rich diff rendering --------------------------------------------------


def test_chat_diff_rendering_uses_rich_syntax(tmp_path, monkeypatch):
    """The diff body is rendered via rich.syntax.Syntax so '+'/'-' lines
    get the diff color scheme. We assert by patching the constructor."""
    monkeypatch.chdir(tmp_path)
    _seed_one_committed_proposal(tmp_path)
    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)

    constructed_with: list[tuple] = []

    class FakeSyntax:
        def __init__(self, code, lang, **_kwargs):
            constructed_with.append((code, lang))

        def __rich_console__(self, *_: object):
            yield ""

    with patch("loupe_cli.chat_cmd.Syntax", FakeSyntax):
        with patch("typer.prompt", return_value="N"):
            result = runner.invoke(app, ["chat", "--review-only"])

    assert result.exit_code == 0
    assert len(constructed_with) == 1
    code, lang = constructed_with[0]
    assert lang == "diff"
    assert "+" in code or "-" in code


# -- Retry on apply conflict ----------------------------------------------


def test_chat_apply_conflict_prompts_reedit_then_succeeds(tmp_path, monkeypatch):
    """If git apply fails on 'y', chat prompts 'Re-edit? [y/N]'. Saying 'y'
    drops into click.edit; a working modified diff applies."""
    monkeypatch.chdir(tmp_path)
    _seed_one_committed_proposal(tmp_path)
    # Modify the target so the original proposal won't apply.
    (tmp_path / ".loupe" / "context.md").write_text("changed\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "drift"], cwd=tmp_path, check=True)
    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)

    working_diff = (
        "--- a/.loupe/context.md\n+++ b/.loupe/context.md\n@@ -1 +1,2 @@\n changed\n+manual-line\n"
    )

    # Sequence: 'y' (original fails) → 'y' (re-edit) → 'y' (apply edited).
    prompt_returns = iter(["y", "y", "y"])
    with patch("typer.prompt", side_effect=lambda *a, **kw: next(prompt_returns)):
        with patch("loupe_cli.chat_cmd.click.edit", return_value=working_diff):
            result = runner.invoke(app, ["chat", "--review-only"])

    combined = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 0, combined
    assert "edited+applied" in combined or "edited-applied" in combined
    final = (tmp_path / ".loupe" / "context.md").read_text()
    assert "manual-line" in final
