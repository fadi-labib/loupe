from __future__ import annotations

import os
from pathlib import Path

from loupe_core.enforcement.path_boundary import PathBoundary


class BoundaryViolation(PermissionError):
    """Raised when an agent tool attempts to write outside the allow-list."""


def _validate_relative_target(target_path: str) -> None:
    """Reject path traversal, absolute paths, NUL bytes, and empty strings.

    `propose_patch` joins `target_path` under `.loupe/.proposed/`; without these
    checks a `target_path` of `".."` (or similar) would resolve outside the
    proposal directory, breaking Layer 1 containment.
    """
    if not target_path:
        raise ValueError("target_path may not be empty")
    if "\x00" in target_path:
        raise ValueError(f"target_path contains NUL byte: {target_path!r}")
    if Path(target_path).is_absolute():
        raise ValueError(
            f"target_path must be relative, got absolute: {target_path!r}"
        )
    if ".." in Path(target_path).parts:
        raise ValueError(
            f"target_path contains path traversal '..': {target_path!r}"
        )


def write_agent_artifact(boundary: PathBoundary, path: Path, content: str) -> str:
    if not boundary.is_agent_writable(str(path)):
        raise BoundaryViolation(
            f"Path '{path}' is not in agent_writable_paths. "
            f"Use propose_patch() for human-owned files."
        )
    # Refuse to follow any symlink — at the target itself or anywhere in its
    # ancestry. A pre-planted symlink would otherwise redirect the write
    # outside the Layer 1 boundary (TOCTOU breach).
    if path.is_symlink():
        raise BoundaryViolation(
            f"refused to follow symlink at target {str(path)!r}"
        )
    for parent in path.parents:
        if parent.is_symlink():
            raise BoundaryViolation(
                f"refused to follow symlinked parent {str(parent)!r} of {str(path)!r}"
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    # O_NOFOLLOW + O_CREAT + O_TRUNC: if the target is replaced with a symlink
    # between the check above and the open, the open fails with ELOOP rather
    # than silently following.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as e:
        # ELOOP from O_NOFOLLOW indicates a TOCTOU race with a symlink.
        raise BoundaryViolation(
            f"refused to follow symlink at target {str(path)!r}"
        ) from e
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)
    return str(path)


def propose_patch(
    boundary: PathBoundary,
    loupe_dir: Path,
    target_path: str,
    unified_diff: str,
    rationale: str,
    run_id: str,
) -> str:
    """Stage a proposed patch against a human-owned file.

    Writes a draft into .loupe/.proposed/ and returns its path. Rejects
    targets that are agent-writable (use write_agent_artifact for those).
    """
    _validate_relative_target(target_path)
    if boundary.is_agent_writable(target_path):
        raise BoundaryViolation(
            f"Path '{target_path}' is agent-writable; "
            f"use write_agent_artifact() directly instead of propose_patch()."
        )
    proposal_dir = loupe_dir / ".proposed" / target_path.replace("/", "_")
    proposal_dir.mkdir(parents=True, exist_ok=True)
    proposal_path = proposal_dir / f"{run_id}.patch"
    body = (
        f"# Proposed patch for {target_path}\n"
        f"# Rationale: {rationale}\n"
        f"# Run: {run_id}\n"
        f"---\n"
        f"{unified_diff}"
    )
    proposal_path.write_text(body)
    return str(proposal_path)
