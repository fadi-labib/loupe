"""Tests for the `.loupe/.proposed/` lifecycle helpers used by `loupe chat`."""

import subprocess
from pathlib import Path

import pytest
from loupe_cli.proposals import Proposal, load_proposals, move_proposal


def test_proposal_dataclass_round_trips_all_fields():
    """The Proposal dataclass is the in-memory view of one .patch file.
    Hold every field load_proposals will need to populate."""
    p = Proposal(
        target_path=".loupe/context.md",
        rationale="T-003 references a missing element 'Auth API'.",
        run_id="abc123",
        diff_body="--- a/.loupe/context.md\n+++ b/.loupe/context.md\n",
        patch_file_path=Path("/tmp/.loupe/.proposed/_loupe_context.md/abc123.patch"),
    )
    assert p.target_path == ".loupe/context.md"
    assert p.run_id == "abc123"
    assert p.patch_file_path.name == "abc123.patch"


def _write_patch_file(loupe_dir: Path, target: str, run_id: str, diff: str, rationale: str) -> Path:
    """Mimic loupe_core.tools.propose_patch's on-disk format."""
    encoded = target.replace("/", "_")
    proposal_dir = loupe_dir / ".proposed" / encoded
    proposal_dir.mkdir(parents=True, exist_ok=True)
    patch_path = proposal_dir / f"{run_id}.patch"
    body = f"# Proposed patch for {target}\n# Rationale: {rationale}\n# Run: {run_id}\n---\n{diff}"
    patch_path.write_text(body)
    return patch_path


def test_load_proposals_walks_proposed_tree(tmp_path):
    loupe = tmp_path / ".loupe"
    _write_patch_file(
        loupe,
        target=".loupe/context.md",
        run_id="abc",
        diff="--- a/.loupe/context.md\n+++ b/.loupe/context.md\n",
        rationale="missing element",
    )
    _write_patch_file(
        loupe,
        target=".loupe/decisions/D-12.md",
        run_id="def",
        diff="--- a/.loupe/decisions/D-12.md\n+++ b/.loupe/decisions/D-12.md\n",
        rationale="needs update",
    )

    proposals = load_proposals(loupe)

    assert len(proposals) == 2
    targets = {p.target_path for p in proposals}
    assert targets == {".loupe/context.md", ".loupe/decisions/D-12.md"}
    for p in proposals:
        assert p.rationale  # parsed
        assert p.diff_body.startswith("--- a/")  # diff body separated from headers


def test_load_proposals_empty_when_no_proposed_dir(tmp_path):
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    assert load_proposals(loupe) == []


def test_load_proposals_raises_on_missing_separator(tmp_path):
    loupe = tmp_path / ".loupe"
    proposal_dir = loupe / ".proposed" / "_loupe_context.md"
    proposal_dir.mkdir(parents=True)
    (proposal_dir / "abc.patch").write_text(
        "# Proposed patch for .loupe/context.md\n"
        "# Rationale: missing separator below\n"
        "# Run: abc\n"
        "no separator follows\n"
    )
    with pytest.raises(ValueError, match="missing '---' separator"):
        load_proposals(loupe)


def test_load_proposals_raises_on_missing_target_header(tmp_path):
    loupe = tmp_path / ".loupe"
    proposal_dir = loupe / ".proposed" / "_loupe_context.md"
    proposal_dir.mkdir(parents=True)
    (proposal_dir / "abc.patch").write_text(
        "# Rationale: missing target line\n# Run: abc\n---\ndiff body here\n"
    )
    with pytest.raises(ValueError, match="header missing line starting with"):
        load_proposals(loupe)


def _init_git_repo(path: Path) -> None:
    """Init a real git repo in path. Used so `git mv` operates on tracked files."""
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)


def test_move_proposal_to_applied(tmp_path):
    """An accepted proposal is git-mv'd from .proposed/ to .applied/."""
    _init_git_repo(tmp_path)
    loupe = tmp_path / ".loupe"
    patch_path = _write_patch_file(
        loupe,
        target=".loupe/context.md",
        run_id="abc",
        diff="--- a/.loupe/context.md\n+++ b/.loupe/context.md\n",
        rationale="r",
    )
    subprocess.run(["git", "add", ".loupe"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "stage"], cwd=tmp_path, check=True)

    proposals = load_proposals(loupe)
    assert len(proposals) == 1

    moved = move_proposal(proposals[0], to_state="applied", repo_root=tmp_path)

    assert moved.exists()
    assert ".applied" in str(moved)
    assert not patch_path.exists()  # original .proposed/ entry is gone


def test_move_proposal_to_skipped(tmp_path):
    """A rejected proposal is git-mv'd from .proposed/ to .skipped/."""
    _init_git_repo(tmp_path)
    loupe = tmp_path / ".loupe"
    _write_patch_file(
        loupe,
        target=".loupe/context.md",
        run_id="xyz",
        diff="--- a/.loupe/context.md\n+++ b/.loupe/context.md\n",
        rationale="r",
    )
    subprocess.run(["git", "add", ".loupe"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "stage"], cwd=tmp_path, check=True)

    proposals = load_proposals(loupe)
    moved = move_proposal(proposals[0], to_state="skipped", repo_root=tmp_path)

    assert moved.exists()
    assert ".skipped" in str(moved)


def test_move_proposal_refuses_collision(tmp_path):
    """Moving to a destination that already exists raises FileExistsError."""
    _init_git_repo(tmp_path)
    loupe = tmp_path / ".loupe"
    _write_patch_file(
        loupe,
        target=".loupe/context.md",
        run_id="abc",
        diff="--- a/.loupe/context.md\n+++ b/.loupe/context.md\n",
        rationale="r",
    )
    # Pre-create the destination so the move would collide.
    # propose_patch encodes "/" → "_" but preserves leading dot, so
    # ".loupe/context.md" becomes ".loupe_context.md".
    (loupe / ".applied" / ".loupe_context.md").mkdir(parents=True)
    (loupe / ".applied" / ".loupe_context.md" / "abc.patch").write_text("existing")

    subprocess.run(["git", "add", ".loupe"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "stage"], cwd=tmp_path, check=True)

    proposals = load_proposals(loupe)
    assert len(proposals) == 1  # only the .proposed/ one

    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        move_proposal(proposals[0], to_state="applied", repo_root=tmp_path)
