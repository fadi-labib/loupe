"""`loupe verify` — Layer 3 enforcement entry point.

Runs every verification check the platform supports against the current
.loupe/ and exits 0 only if all pass. Designed to be installable as both
a pre-commit hook and a required CI status check.

Default checks (every run):
- Run-record hash chain integrity
- Artefact schema consistency (threats.yaml, mitigations.yaml)
- Threats-to-mitigations cross-reference integrity

Strict-only checks (`--strict`):
- Authorship of protected paths (context.md, decisions/, config.yaml,
  knowledge.yaml must not be touched by an agent-identity commit)
"""
from __future__ import annotations

from pathlib import Path

import typer
from loupe_core.enforcement.verify import verify_repo


def verify_command(strict: bool = False) -> int:
    cwd = Path.cwd()
    if not (cwd / ".loupe").exists():
        typer.echo(
            "Error: .loupe/ not found in the current directory.\n"
            "Run `loupe init` first.",
            err=True,
        )
        return 2

    failures = verify_repo(cwd, strict=strict)
    if not failures:
        scope = "OK (strict)" if strict else "OK"
        typer.echo(f"loupe verify: {scope}")
        return 0
    for f in failures:
        suffix = f" (run {f.run_id})" if f.run_id else ""
        typer.echo(f"X {f.kind}: {f.detail}{suffix}", err=True)
    typer.echo(
        f"\nloupe verify: {len(failures)} failure(s)",
        err=True,
    )
    return 1
