"""`loupe chat` — Layer 4 enforcement entry point.

v1 scope is intentionally narrow:
- TTY guard: refuse to run in non-interactive contexts (use `loupe ci`)
- Default-N confirmation helper for protected-path proposals
- Placeholder message: the full conversational REPL is a v1.x feature

The confirm helper is exported so other modules (e.g., a future
interactive lens driver) can use the same UX gate without re-implementing
it. The default is intentionally "N" — Enter means "do not apply,"
matching VALUES.md §5 (humans stay in the decision seat).

There is no `--auto-confirm` flag. There is no environment variable that
lowers the bar. By design.
"""

from __future__ import annotations

import sys

import typer

# BSD sysexits.h EX_USAGE — operator-config / usage errors.
USAGE_ERROR = 64


def chat_command() -> int:
    if not sys.stdin.isatty():
        typer.echo(
            "loupe chat requires an interactive TTY. "
            "Use `loupe ci` for headless / scripted contexts.",
            err=True,
        )
        return USAGE_ERROR
    typer.echo("loupe chat — interactive mode")
    typer.echo("(Full conversational REPL is a v1.x feature; not yet implemented.)")
    return 0


def confirm_with_diff(target: str, unified_diff: str, rationale: str) -> bool:
    """Default-N prompt with diff preview, used by every protected-path proposal.

    No --auto-confirm flag, no environment override. Layer 4 by design.
    Returns True iff the user explicitly typed `y`. Anything else
    (including empty input, the literal "edit", "skip", or "N") returns False.
    """
    typer.echo(f"\nProposed change to: {target}")
    typer.echo(unified_diff)
    typer.echo(f"Rationale: {rationale}")
    answer: str = typer.prompt("Apply? [y/N/edit/skip]", default="N", show_default=False)
    return answer.strip().lower() == "y"
