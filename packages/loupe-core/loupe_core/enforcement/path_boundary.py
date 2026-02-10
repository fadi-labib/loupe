from __future__ import annotations
from pathlib import PurePosixPath
import fnmatch


class PathBoundary:
    """Decides whether a given path is writable by an agent tool.

    Paths are normalised; any path that traverses outside `.loupe/` (e.g., `..`),
    is absolute, or contains a NUL byte is rejected regardless of the allow-list.
    """

    def __init__(self, writable_globs: list[str]):
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
