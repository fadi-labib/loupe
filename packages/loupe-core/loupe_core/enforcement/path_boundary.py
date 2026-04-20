from __future__ import annotations

import fnmatch
from pathlib import Path, PurePosixPath


def validate_relative_target_path(target_path: str) -> None:
    """Reject path traversal, absolute paths, NUL bytes, and empty strings.

    Useful anywhere a caller-supplied path is joined under a containment root
    (e.g., `.loupe/.proposed/`); without these checks a `target_path` of `".."`
    (or similar) would resolve outside the containment directory, breaking
    Layer 1 enforcement.
    """
    if not target_path:
        raise ValueError("target_path may not be empty")
    if "\x00" in target_path:
        raise ValueError(f"target_path contains NUL byte: {target_path!r}")
    if Path(target_path).is_absolute():
        raise ValueError(f"target_path must be relative, got absolute: {target_path!r}")
    if ".." in Path(target_path).parts:
        raise ValueError(f"target_path contains path traversal '..': {target_path!r}")


class PathBoundary:
    """Decides whether a given path is writable by an agent tool.

    Paths are normalised; any path that traverses outside `.loupe/` (e.g., `..`),
    is absolute, or contains a NUL byte is rejected regardless of the allow-list.
    """

    def __init__(self, writable_globs: list[str]) -> None:
        self._globs = list(writable_globs)

    def is_agent_writable(self, path: str) -> bool:
        if "\x00" in path:
            return False
        normalized = PurePosixPath(path).as_posix()
        if ".." in normalized.split("/"):
            return False
        # Absolute paths are allowed only if explicitly listed in the allow-list
        # (e.g., when tests pass tmp_path). Relative paths must match a glob.
        return any(self._match(normalized, g) for g in self._globs)

    @staticmethod
    def _match(path: str, glob: str) -> bool:
        if glob.endswith("/**"):
            # Recursive prefix glob: match exactly the prefix or any descendant
            # path under it. We must NOT match a path that shares the prefix as
            # a substring (e.g., `.loupe/**` must not match `.loupe-old/x`).
            prefix = glob[:-3]
            return path == prefix or path.startswith(prefix + "/")
        return fnmatch.fnmatchcase(path, glob)
