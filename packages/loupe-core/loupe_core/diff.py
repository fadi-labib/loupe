"""Unified-diff parser and the typed `CodeDiff` value-object.

`CodeDiff` previously lived in `run_context.py`, which forced
`run_context.RunContext.bootstrap` to use a local import to break a
circular dependency (diff.py imported `CodeDiff` from run_context.py).
Phase 7 moves the type here — where the parser lives — and re-exports
it from `run_context.py` for backward compatibility.
"""

from __future__ import annotations

import re

from pydantic import BaseModel

_PATH_RE = re.compile(r"^diff --git a/(.+?) b/.+$")


class CodeDiff(BaseModel):
    base_sha: str
    head_sha: str
    changed_paths: list[str]
    added_lines: int
    removed_lines: int
    raw_unified: str


def parse_unified_diff(unified: str, *, base_sha: str, head_sha: str) -> CodeDiff:
    changed_paths: list[str] = []
    added = 0
    removed = 0
    for line in unified.splitlines():
        m = _PATH_RE.match(line)
        if m:
            changed_paths.append(m.group(1))
            continue
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            added += 1
        elif line.startswith("-"):
            removed += 1
    return CodeDiff(
        base_sha=base_sha,
        head_sha=head_sha,
        changed_paths=changed_paths,
        added_lines=added,
        removed_lines=removed,
        raw_unified=unified,
    )
