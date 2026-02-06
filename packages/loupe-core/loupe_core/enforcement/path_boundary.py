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
        if path.startswith("/"):
            return False
        normalized = PurePosixPath(path).as_posix()
        if ".." in normalized.split("/"):
            return False
        return any(self._match(normalized, g) for g in self._globs)

    @staticmethod
    def _match(path: str, glob: str) -> bool:
        if glob.endswith("/**"):
            prefix = glob[:-3]
            return path == prefix or path.startswith(prefix + "/") or path.startswith(prefix)
        return fnmatch.fnmatchcase(path, glob)
