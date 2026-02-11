from __future__ import annotations

from pathlib import Path

from loupe_core.enforcement.path_boundary import PathBoundary


class BoundaryViolation(PermissionError):
    """Raised when an agent tool attempts to write outside the allow-list."""


def write_agent_artifact(boundary: PathBoundary, path: Path, content: str) -> str:
    if not boundary.is_agent_writable(str(path)):
        raise BoundaryViolation(
            f"Path '{path}' is not in agent_writable_paths. "
            f"Use propose_patch() for human-owned files."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
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
