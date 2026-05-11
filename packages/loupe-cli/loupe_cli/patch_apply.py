"""Apply a unified diff to its target by shelling out to `git apply`.

`git apply` is preferred over a pure-Python differ for three reasons:
1. Battle-tested edge cases (whitespace, context fuzz, conflicts)
2. Already on PATH for every Loupe user (repos are git-tracked)
3. Default-refuses path-escape (no --unsafe-paths flag set)

Lives in loupe-cli (not loupe-core) because patch-apply is the human-write
side of Layer 4 — the agent runtime has no code path that auto-applies
proposed patches. An auditor verifies with:
    grep -r "git apply" packages/loupe-core/   # → no hits
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ApplyResult:
    """Outcome of one `git apply` invocation.

    `applied=True` means the working tree has been modified (unless `dry_run`,
    in which case only `git apply --check` ran).
    `applied=False` carries `stderr` so the caller can show the user why.
    """

    applied: bool
    stderr: str


def apply_unified_diff(*, repo_root: Path, diff_text: str, dry_run: bool = False) -> ApplyResult:
    """Run `git apply --check` then (unless dry_run) `git apply` on the diff.

    Two-step so the working tree is never partially modified: --check is a
    pure dry-run that fails the same way the real apply would.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".patch", delete=False, dir=repo_root) as tf:
        tf.write(diff_text)
        patch_path = Path(tf.name)
    try:
        check = subprocess.run(
            ["git", "apply", "--check", str(patch_path)],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        if check.returncode != 0:
            return ApplyResult(applied=False, stderr=check.stderr)
        if dry_run:
            return ApplyResult(applied=True, stderr="")
        apply = subprocess.run(
            ["git", "apply", str(patch_path)],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        if apply.returncode != 0:
            return ApplyResult(applied=False, stderr=apply.stderr)
        return ApplyResult(applied=True, stderr="")
    finally:
        patch_path.unlink(missing_ok=True)
