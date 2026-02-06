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
