"""End-to-end happy path for `loupe chat`.

Seeds two proposals as if a prior `loupe ci` run had staged them, then
drives one chat session that accepts the first and skips the second.
Asserts the final on-disk state matches the design's section 10 example."""

import subprocess
from pathlib import Path
from unittest.mock import patch

from loupe_cli.__main__ import app
from typer.testing import CliRunner

runner = CliRunner()


def _git_init(path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@e.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=path, check=True)


def _write_patch(loupe: Path, target: str, run_id: str, diff: str, rationale: str) -> None:
    encoded = target.replace("/", "_")
    d = loupe / ".proposed" / encoded
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{run_id}.patch").write_text(
        f"# Proposed patch for {target}\n# Rationale: {rationale}\n# Run: {run_id}\n---\n{diff}"
    )


def test_full_happy_path_accept_and_skip(tmp_path, monkeypatch):
    """Seed two proposals, accept the first, skip the second.

    Final state should be:
      - context.md patched in working tree
      - decisions/D-12.md untouched
      - .proposed/ empty
      - .applied/.../abc.patch exists
      - .skipped/.../def.patch exists
    """
    monkeypatch.chdir(tmp_path)
    _git_init(tmp_path)
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    (loupe / "context.md").write_text("line1\nline2\nline3\n")
    (loupe / "decisions").mkdir()
    (loupe / "decisions" / "D-12.md").write_text("alpha\nbeta\n")

    _write_patch(
        loupe,
        target=".loupe/context.md",
        run_id="abc",
        diff=(
            "--- a/.loupe/context.md\n"
            "+++ b/.loupe/context.md\n"
            "@@ -1,3 +1,4 @@\n"
            " line1\n"
            " line2\n"
            "+line2.5\n"
            " line3\n"
        ),
        rationale="missing element",
    )
    _write_patch(
        loupe,
        target=".loupe/decisions/D-12.md",
        run_id="def",
        diff=(
            "--- a/.loupe/decisions/D-12.md\n"
            "+++ b/.loupe/decisions/D-12.md\n"
            "@@ -1,2 +1,3 @@\n"
            " alpha\n"
            "+inserted\n"
            " beta\n"
        ),
        rationale="needs update",
    )

    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "stage proposals"], cwd=tmp_path, check=True)

    monkeypatch.setattr("loupe_cli.chat_cmd._stdin_is_tty", lambda: True)

    # Order: proposal 1 = .loupe/context.md (accept), proposal 2 = decisions/D-12.md (skip).
    prompt_returns = iter(["y", "skip"])
    with patch("typer.prompt", side_effect=lambda *a, **kw: next(prompt_returns)):
        result = runner.invoke(app, ["chat", "--review-only"])

    combined = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 0, combined

    # context.md was patched.
    assert "line2.5" in (tmp_path / ".loupe" / "context.md").read_text()
    # decisions/D-12.md was NOT patched.
    assert "inserted" not in (tmp_path / ".loupe" / "decisions" / "D-12.md").read_text()

    # Lifecycle: applied + skipped directories present, .proposed/ empty of .patch files.
    assert (tmp_path / ".loupe" / ".applied" / ".loupe_context.md" / "abc.patch").exists()
    assert (tmp_path / ".loupe" / ".skipped" / ".loupe_decisions_D-12.md" / "def.patch").exists()
    proposed_remaining = list((tmp_path / ".loupe" / ".proposed").rglob("*.patch"))
    assert proposed_remaining == []

    # Summary mentions both outcomes.
    assert "1 applied" in combined
    assert "1 skipped" in combined
