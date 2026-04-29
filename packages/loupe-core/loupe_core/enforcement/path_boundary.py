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

    Paths are normalised; any path that traverses outside `.loupe/` (e.g., `..`)
    or contains a NUL byte is rejected regardless of the allow-list.

    The allow-list globs in config.yaml are project-root-relative
    (e.g. `.loupe/threats.yaml`). Real call sites — `loupe ci`,
    `loupe scan`, the MCP server — construct write targets as
    absolute paths (`Path.cwd() / .loupe / threats.yaml`). When the
    caller supplies `project_root`, `is_agent_writable` relativises
    absolute inputs against it before glob-matching, so the allow-list
    semantics stay project-root-relative regardless of the caller's CWD.
    Absolute paths that don't live under `project_root` (e.g. `/etc/passwd`)
    are rejected unconditionally; this keeps the allow-list from being
    silently widened by a stray CWD.
    """

    def __init__(
        self,
        writable_globs: list[str],
        *,
        project_root: Path | None = None,
    ) -> None:
        if project_root is not None and not project_root.is_absolute():
            raise ValueError(f"project_root must be absolute, got {project_root!r}")
        self._globs = list(writable_globs)
        self._project_root = project_root

    def is_agent_writable(self, path: str) -> bool:
        if "\x00" in path:
            return False
        candidate = PurePosixPath(path)
        if candidate.is_absolute() and self._project_root is not None:
            # Real CLI flow: project_root is set, input is absolute.
            # Relativise against project_root so the glob comparison stays
            # project-root-relative. Absolute paths outside project_root are
            # rejected — refusing to silently widen the allow-list by
            # whatever the caller's CWD happens to be.
            try:
                rel = candidate.relative_to(PurePosixPath(self._project_root.as_posix()))
            except ValueError:
                return False
            normalized = rel.as_posix()
        else:
            # No project_root: fall back to raw fnmatch. This preserves
            # the legacy contract some call sites and tests rely on, where
            # absolute paths in `writable_globs` are matched against
            # absolute inputs directly (no relativisation).
            normalized = candidate.as_posix()
        if ".." in normalized.split("/"):
            return False
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
