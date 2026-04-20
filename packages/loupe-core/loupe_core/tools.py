from __future__ import annotations

import os
from pathlib import Path

from loupe_core.enforcement.path_boundary import (
    PathBoundary,
    validate_relative_target_path,
)


class BoundaryViolation(PermissionError):
    """Raised when an agent tool attempts to write outside the allow-list."""


def write_agent_artifact(boundary: PathBoundary, path: Path, content: str) -> str:
    if not boundary.is_agent_writable(str(path)):
        raise BoundaryViolation(
            f"Path '{path}' is not in agent_writable_paths. "
            f"Use propose_patch() for human-owned files."
        )
    # Walk the entire parent chain from the filesystem root using anchored
    # file descriptors, with O_DIRECTORY | O_NOFOLLOW on every step. This is
    # the only TOCTOU-safe way to ensure no component is (or is swapped for)
    # a symlink between check and use: each component is verified atomically
    # at open time. The previous `path.is_symlink()` + `for parent in
    # path.parents: parent.is_symlink()` loop was racy — any parent could be
    # replaced after the check and before the final open. O_NOFOLLOW on the
    # final open only protects the leaf, not intermediate components.
    abs_path = Path(os.path.abspath(path))
    parts = abs_path.parts
    if not parts:
        raise BoundaryViolation(f"refused empty path {str(path)!r}")
    # On POSIX, abs_path.parts[0] is "/"; that's our trusted anchor.
    anchor = parts[0]
    parent_components = parts[1:-1]
    filename = parts[-1]
    if not filename:
        raise BoundaryViolation(f"refused trailing-separator path {str(path)!r}")

    # Open the filesystem root with O_NOFOLLOW. `/` itself cannot be a symlink,
    # so this is the trusted base for the walk.
    parent_fd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in parent_components:
            try:
                child_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
            except FileNotFoundError:
                # The component doesn't exist yet — create it and re-open.
                try:
                    os.mkdir(component, mode=0o755, dir_fd=parent_fd)
                except FileExistsError:
                    # Someone created it between our open and mkdir; that's
                    # fine — we'll re-open below and O_NOFOLLOW will catch a
                    # symlink if one was planted.
                    pass
                except OSError as exc:
                    raise BoundaryViolation(
                        f"refused to create directory {component!r}: {exc}"
                    ) from exc
                try:
                    child_fd = os.open(
                        component,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=parent_fd,
                    )
                except OSError as exc:
                    raise BoundaryViolation(
                        f"refused to follow symlink at parent component "
                        f"{component!r} of {str(path)!r}"
                    ) from exc
            except OSError as exc:
                # ELOOP (O_NOFOLLOW caught a symlink) / ENOTDIR / etc.
                raise BoundaryViolation(
                    f"refused to follow symlink at parent component {component!r} of {str(path)!r}"
                ) from exc
            os.close(parent_fd)
            parent_fd = child_fd
        # Final open of the leaf. O_NOFOLLOW on the leaf still matters —
        # rejects a pre-planted symlink at the target itself.
        try:
            fd = os.open(
                filename,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                0o644,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise BoundaryViolation(f"refused to follow symlink at target {str(path)!r}") from exc
        # Wrap the fd in a stdio file object so .write() loops internally
        # until the full buffer is written. Bare os.write() may short-write
        # under POSIX, which would silently truncate the artifact. closefd=True
        # gives ownership of the fd to fdopen so the `with` block closes it.
        with os.fdopen(fd, "w", encoding="utf-8", closefd=True) as f:
            f.write(content)
    finally:
        try:
            os.close(parent_fd)
        except OSError:
            pass
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
    validate_relative_target_path(target_path)
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
