from pathlib import Path

import typer
from loupe_core import __version__

from loupe_cli.chat_cmd import chat_command
from loupe_cli.ci_cmd import ci_command
from loupe_cli.discovery_cmd import cap_list_command, lens_list_command
from loupe_cli.doctor_cmd import doctor_command
from loupe_cli.init_cmd import init_command
from loupe_cli.mcp_cmd import mcp_command
from loupe_cli.scan_cmd import scan_command
from loupe_cli.verify_cmd import verify_command

# BSD sysexits.h: usage / operator-config errors land on exit code 64.
# Mirrors what `loupe-action/action.yml` documents and what `EX_USAGE`
# means in sysexits(3). Gate failures (cfg.ci.fail_on triggered) keep
# exit 1 — they're NOT usage errors, they're "policy said fail."
USAGE_ERROR = 64

app = typer.Typer(no_args_is_help=True, add_completion=False)

# `loupe lens ...` and `loupe cap ...` are noun-then-verb subcommand groups
# (mirroring kubectl, gh, etc.). Today each group has one verb (`list`); the
# structure leaves room for `lens info <name>` / `cap doctor` / etc.
lens_app = typer.Typer(no_args_is_help=True, help="Inspect installed lenses.")
cap_app = typer.Typer(no_args_is_help=True, help="Inspect installed capability backends.")
app.add_typer(lens_app, name="lens")
app.add_typer(cap_app, name="cap")


@app.callback(invoke_without_command=True)
def main(version: bool = typer.Option(False, "--version", help="Print version and exit.")) -> None:
    if version:
        typer.echo(f"loupe {__version__}")
        raise typer.Exit()


@app.command("init")
def init_cmd(
    force: bool = typer.Option(
        False,
        "--force",
        help=(
            "Regenerate scaffold files (config.yaml, knowledge.yaml) when .loupe/ "
            "already exists. context.md is preserved if it has been edited; runs/ "
            "and decisions/ are never touched."
        ),
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print what would be created or overwritten, without writing.",
    ),
) -> None:
    """Initialise a .loupe/ directory in the current repo."""
    init_command(force=force, dry_run=dry_run)


@app.command("ci")
def ci_cmd(
    pr: str | None = typer.Option(
        None,
        "--pr",
        help=(
            "Pull request number; recorded in the run record. Does NOT fetch the "
            "diff — pass --diff or --diff-file. The GitHub Action wrapper fetches "
            "the PR diff automatically before invoking the CLI."
        ),
    ),
    diff: str = typer.Option(
        "",
        "--diff",
        help="Unified diff text (mutually exclusive with --diff-file).",
    ),
    diff_file: Path | None = typer.Option(
        None,
        "--diff-file",
        help="Path to a unified diff (mutually exclusive with --diff).",
    ),
    base_sha: str | None = typer.Option(
        None,
        "--base-sha",
        help="Base commit SHA; recorded in the run record. Does not affect diff parsing.",
    ),
    head_sha: str | None = typer.Option(
        None,
        "--head-sha",
        help="Head commit SHA; recorded in the run record. Does not affect diff parsing.",
    ),
    config: Path = typer.Option(
        Path(".loupe/config.yaml"),
        "--config",
        help="Path to the Loupe config file.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help=(
            "Print plan-trace output: which lenses were considered, their relevance "
            "scores, which were dispatched, and per-lens token / cost telemetry as "
            "each finishes. Default off — the run record (`runs/<id>.json`) carries "
            "the same information."
        ),
    ),
) -> None:
    """Run Loupe in CI mode on a unified diff.

    Exactly one of ``--diff`` (raw text) or ``--diff-file`` (path) is
    required. Passing both, or neither, exits with code 64 (sysexits.h
    EX_USAGE) — matching the contract documented in
    ``loupe-action/action.yml``.
    """
    if diff and diff_file is not None:
        typer.echo(
            "error: --diff and --diff-file are mutually exclusive",
            err=True,
        )
        raise typer.Exit(code=USAGE_ERROR)
    if not diff and diff_file is None:
        typer.echo(
            "error: provide exactly one of --diff or --diff-file",
            err=True,
        )
        raise typer.Exit(code=USAGE_ERROR)
    text = diff_file.read_text() if diff_file is not None else diff
    raise typer.Exit(code=ci_command(text, base_sha, head_sha, config, verbose=verbose))


@app.command("doctor")
def doctor_cmd(
    loupe_dir: Path = typer.Option(
        Path(".loupe"),
        "--loupe-dir",
        help="Path to the .loupe/ directory to diagnose.",
    ),
) -> None:
    """Run preflight checks: env vars, capability binaries, scaffold completeness."""
    raise typer.Exit(code=doctor_command(loupe_dir))


@app.command("verify")
def verify_cmd(
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Run extended checks (protected-path authorship via git).",
    ),
) -> None:
    """Verify Loupe state — hash chain, schemas, cross-references, +authorship under --strict."""
    raise typer.Exit(code=verify_command(strict=strict))


@app.command("chat")
def chat_cmd(
    review_only: bool = typer.Option(
        False,
        "--review-only",
        help="Skip the in-process ci run; review existing .loupe/.proposed/ patches only.",
    ),
    diff: str = typer.Option(
        "",
        "--diff",
        help="Unified diff text (passed to ci_command when not --review-only).",
    ),
    diff_file: Path | None = typer.Option(
        None,
        "--diff-file",
        help="Path to a unified diff (passed to ci_command when not --review-only).",
    ),
    base_sha: str | None = typer.Option(None, "--base-sha", help="Base commit SHA."),
    head_sha: str | None = typer.Option(None, "--head-sha", help="Head commit SHA."),
    config: Path | None = typer.Option(
        None,
        "--config",
        help="Path to .loupe/config.yaml.",
    ),
) -> None:
    """Interactive review of staged proposals (Layer 4 enforcement)."""
    if not review_only:
        if diff and diff_file is not None:
            typer.echo(
                "error: --diff and --diff-file are mutually exclusive",
                err=True,
            )
            raise typer.Exit(code=USAGE_ERROR)
    diff_text = ""
    if diff_file is not None:
        diff_text = diff_file.read_text()
    elif diff:
        diff_text = diff
    raise typer.Exit(
        code=chat_command(
            review_only=review_only,
            diff_text=diff_text,
            base_sha=base_sha,
            head_sha=head_sha,
            config_path=config,
        )
    )


@app.command("scan")
def scan_cmd(
    positional_paths: list[str] = typer.Argument(
        None,
        metavar="[PATHS...]",
        help=(
            "Paths to scan (positional). Equivalent to repeating `--paths`. "
            "Mix with `--paths` if you want; both inputs merge."
        ),
    ),
    paths: list[str] = typer.Option(
        [],
        "--paths",
        help="Limit scan to these paths (repeatable). Empty = full-repo scan.",
    ),
    config: Path = typer.Option(Path(".loupe/config.yaml"), "--config"),
    max_chars_per_file: int = typer.Option(
        50_000,
        "--max-chars-per-file",
        help=(
            "Per-file source-byte cap for scoped scans (D-24). Files larger "
            "than this truncate at the cap with a visible marker. Lower this "
            "for tight budgets; raise it (and the scan budget) for thorough "
            "single-file analysis."
        ),
    ),
) -> None:
    """Run Loupe over the whole repo (or a subset) — D-15 scan mode.

    Bypasses the per-lens relevance threshold. Disabled lenses (config-level
    enabled=False) are still skipped. Use when onboarding, re-baselining,
    or doing an architectural review.

    Paths can be supplied positionally (`loupe scan src/mqtt.c src/http.c`)
    or via `--paths` (repeatable). Both forms merge — `loupe scan src/a.c
    --paths src/b.c` runs against both. F-05 ergonomic parity with grep/ruff.
    """
    # Merge positional + --paths. positional_paths defaults to None when
    # no positional args were given (Typer's nargs=-1 convention).
    merged = list(positional_paths or []) + list(paths)
    raise typer.Exit(code=scan_command(merged, config, max_chars_per_file))


@app.command("mcp")
def mcp_cmd(
    loupe_dir: Path = typer.Option(
        Path(".loupe"),
        "--loupe-dir",
        help="Path to the .loupe/ directory the MCP server serves from.",
    ),
) -> None:
    """Run the Loupe MCP server over stdio (third frontend per D-09)."""
    raise typer.Exit(code=mcp_command(loupe_dir))


@lens_app.command("list")
def lens_list_cmd() -> None:
    """List installed lenses (loupe.lenses entry-point group)."""
    raise typer.Exit(code=lens_list_command())


@cap_app.command("list")
def cap_list_cmd() -> None:
    """List installed capability backends (loupe.capabilities entry-point group)."""
    raise typer.Exit(code=cap_list_command())


if __name__ == "__main__":
    app()
