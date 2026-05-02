"""Shared filesystem helpers — code extension allow-list.

The `CODE_EXTENSIONS` tuple is the canonical "is this a source file we
care about" filter used in three places:

- `loupe-threatlens/lens.py`'s `is_relevant()` (filters changed_paths
  to decide whether ThreatLens should run on a diff)
- `loupe-cli/scan_cmd.py`'s scoped-source assembly (filters expanded
  directory contents to skip docs / configs / binaries)
- future lenses that want the same "this looks like code" heuristic

Extending the list here means every consumer picks it up. The tuple
ordering is alphabetical with C-family clustered for readability;
order doesn't affect semantics (it's used through `str.endswith` and
set membership).
"""

from __future__ import annotations

# Tuple (not frozenset) because the primary consumer uses
# `str.endswith(CODE_EXTENSIONS)`, which accepts a tuple of suffixes
# directly. A frozenset would require a list comprehension at the call
# site.
CODE_EXTENSIONS: tuple[str, ...] = (
    ".c",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".py",
    ".rb",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
)
