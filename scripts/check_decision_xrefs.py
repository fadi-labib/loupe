"""CI check: every D-NN identifier referenced in docs or code exists in decisions.md.

Run from the repo root:

    uv run python scripts/check_decision_xrefs.py

Exit code 0 if every reference resolves; non-zero on the first mismatch.

The pattern matches `D-NN` (two-digit, e.g., D-04, D-18) — the identifier shape
documented at docs/reference/decisions.md. It deliberately does NOT match the
ADR-style `D-YYYY-MM-DD-<slug>` identifiers used for risk acceptances in
.loupe/decisions/, which have a different namespace.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# Decision identifier shape: D-NN (two-digit) used in the design-decisions log.
# Word-boundary on both sides avoids matching D-YYYY dates accidentally.
DECISION_PATTERN = re.compile(r"\bD-(\d{2})\b")
# Anchor definitions in decisions.md look like: `## D-04: ...` or `{ #d-04 }`.
DEFINITION_PATTERN = re.compile(r"^##\s*D-(\d{2})\b|{\s*#d-(\d{2})\s*}", re.MULTILINE)

# Scan these locations for references. Skip generated/vendor dirs.
SEARCH_GLOBS = [
    "docs/**/*.md",
    "packages/**/*.py",
    "packages/**/*.toml",
    "README.md",
    "CHANGELOG.md",
    "SECURITY.md",
]
SKIP_DIRS = {".venv", "node_modules", "site", "dist", "build", ".mypy_cache", ".pytest_cache"}


def find_definitions(repo: Path) -> set[str]:
    """Return the set of D-NN identifiers defined in the decisions log."""
    decisions = repo / "docs" / "reference" / "decisions.md"
    if not decisions.exists():
        sys.exit(f"error: decisions.md not found at {decisions}")
    text = decisions.read_text()
    defined: set[str] = set()
    for m in DEFINITION_PATTERN.finditer(text):
        # Either group 1 (## D-NN) or group 2 ({ #d-NN }) carries the digits.
        digits = m.group(1) or m.group(2)
        defined.add(f"D-{digits}")
    return defined


def find_references(repo: Path) -> dict[str, list[tuple[Path, int]]]:
    """Return D-NN → list of (file, line) where it's referenced."""
    refs: dict[str, list[tuple[Path, int]]] = {}
    for pattern in SEARCH_GLOBS:
        for path in repo.glob(pattern):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            # Don't count the decisions.md file's own definitions as references.
            if path == repo / "docs" / "reference" / "decisions.md":
                continue
            try:
                content = path.read_text()
            except UnicodeDecodeError:
                continue
            for lineno, line in enumerate(content.splitlines(), start=1):
                for m in DECISION_PATTERN.finditer(line):
                    ident = f"D-{m.group(1)}"
                    refs.setdefault(ident, []).append((path, lineno))
    return refs


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    defined = find_definitions(repo)
    refs = find_references(repo)

    if not defined:
        print("error: no D-NN definitions found in decisions.md", file=sys.stderr)
        return 2

    errors: list[str] = []

    referenced = set(refs.keys())
    unresolved = referenced - defined
    for ident in sorted(unresolved):
        locations = refs[ident]
        loc_str = ", ".join(f"{p.relative_to(repo)}:{ln}" for p, ln in locations[:5])
        errors.append(f"unresolved {ident} referenced at: {loc_str}")

    unreferenced = defined - referenced
    # Unreferenced definitions are warnings (a decision can stand alone), not errors.
    if unreferenced:
        print(
            "note: defined but never referenced outside decisions.md: "
            + ", ".join(sorted(unreferenced)),
            file=sys.stderr,
        )

    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1

    print(
        f"ok: {len(defined)} D-NN definitions, "
        f"{len(referenced)} referenced, all references resolve."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
