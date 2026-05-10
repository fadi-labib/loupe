"""Tests for the `.loupe/.proposed/` lifecycle helpers used by `loupe chat`."""

from pathlib import Path

from loupe_cli.proposals import Proposal


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
