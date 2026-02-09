from __future__ import annotations
import re
from loupe_core.run_context import CodeDiff


_PATH_RE = re.compile(r"^diff --git a/(.+?) b/.+$")


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
