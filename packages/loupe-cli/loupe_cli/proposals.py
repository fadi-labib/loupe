"""`.loupe/.proposed/` lifecycle helpers for `loupe chat`.

The on-disk format is laid down by `loupe_core.tools.propose_patch`:
4-line `#`-comment header (target / rationale / run / `---` separator),
followed by the unified diff body. See tools.py:108-138.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class Proposal:
    """In-memory view of one `.loupe/.proposed/<encoded>/<run-id>.patch` file."""

    target_path: str
    rationale: str
    run_id: str
    diff_body: str
    patch_file_path: Path


def load_proposals(loupe_dir: Path) -> list[Proposal]:
    """Walk `.loupe/.proposed/**/*.patch` and parse each file into a Proposal.

    Returns proposals sorted by (target_path, run_id) — alphabetical target,
    oldest run first within a target. Matches `loupe chat`'s presentation order.
    """
    proposed_root = loupe_dir / ".proposed"
    if not proposed_root.exists():
        return []
    out: list[Proposal] = []
    for patch_path in sorted(proposed_root.rglob("*.patch")):
        out.append(_parse_patch_file(patch_path))
    out.sort(key=lambda p: (p.target_path, p.run_id))
    return out


def _parse_patch_file(patch_path: Path) -> Proposal:
    """Parse the 4-line header + `---` + diff body format from tools.propose_patch."""
    text = patch_path.read_text()
    if "\n---\n" not in text:
        raise ValueError(
            f"malformed proposal {patch_path}: missing '---' separator between header and diff"
        )
    header, diff_body = text.split("\n---\n", 1)
    lines = header.splitlines()
    target = _extract_header_value(lines, prefix="# Proposed patch for ", path=patch_path)
    rationale = _extract_header_value(lines, prefix="# Rationale: ", path=patch_path)
    run_id = _extract_header_value(lines, prefix="# Run: ", path=patch_path)
    return Proposal(
        target_path=target,
        rationale=rationale,
        run_id=run_id,
        diff_body=diff_body,
        patch_file_path=patch_path,
    )


def _extract_header_value(lines: list[str], *, prefix: str, path: Path) -> str:
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix):]
    raise ValueError(
        f"malformed proposal {path}: header missing line starting with {prefix!r}"
    )


def move_proposal(
    proposal: Proposal,
    *,
    to_state: Literal["applied", "skipped"],
    repo_root: Path,
) -> Path:
    """`git mv` the proposal's .patch file from .proposed/ to .applied/ or .skipped/.

    Requires the .patch file to be tracked in git (caller must have committed it
    via the user's normal `git add .loupe/ && git commit` workflow after
    `loupe ci`). The move is staged; the caller is responsible for committing it.

    Returns the new path. Raises FileExistsError if the destination already
    contains a file with the same encoded-target + run-id (means the user
    manually re-staged a previously-reviewed proposal; refuse rather than clobber).
    """
    src = proposal.patch_file_path
    rel = src.relative_to(repo_root / ".loupe" / ".proposed")
    dest_root = repo_root / ".loupe" / f".{to_state}"
    dest = dest_root / rel
    if dest.exists():
        raise FileExistsError(
            f"Refusing to overwrite {dest}; remove or rename it first."
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "mv", str(src), str(dest)],
        cwd=repo_root,
        check=True,
        capture_output=True,
    )
    return dest
