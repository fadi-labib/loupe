from pathlib import Path

import typer
from loupe_core import __version__

from loupe_cli.chat_cmd import chat_command
from loupe_cli.ci_cmd import ci_command
from loupe_cli.discovery_cmd import cap_list_command, lens_list_command
from loupe_cli.init_cmd import init_command
from loupe_cli.mcp_cmd import mcp_command
from loupe_cli.scan_cmd import scan_command
from loupe_cli.verify_cmd import verify_command

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
def init_cmd() -> None:
    """Initialise a .loupe/ directory in the current repo."""
    init_command()


@app.command("ci")
def ci_cmd(
    pr: str | None = typer.Option(None, "--pr", help="Pull request number (informational)."),
    diff: str = typer.Option("", "--diff", help="Unified diff text."),
    diff_file: Path | None = typer.Option(None, "--diff-file", help="Path to a unified diff."),
    base_sha: str | None = typer.Option(None, "--base-sha"),
    head_sha: str | None = typer.Option(None, "--head-sha"),
    config: Path = typer.Option(Path(".loupe/config.yaml"), "--config"),
) -> None:
    """Run Loupe in CI mode on a unified diff."""
    text = diff_file.read_text() if diff_file is not None else diff
    raise typer.Exit(code=ci_command(text, base_sha, head_sha, config))


@app.command("verify")
def verify_cmd(
    strict: bool = typer.Option(
        False, "--strict",
        help="Run extended checks (protected-path authorship via git).",
    ),
) -> None:
    """Verify Loupe state — hash chain, schemas, cross-references, +authorship under --strict."""
    raise typer.Exit(code=verify_command(strict=strict))


@app.command("chat")
def chat_cmd() -> None:
    """Interactive Loupe chat session (requires TTY)."""
    raise typer.Exit(code=chat_command())


@app.command("scan")
def scan_cmd(
    paths: list[str] = typer.Option(
        [], "--paths",
        help="Limit scan to these paths (repeatable). Empty = full-repo scan.",
    ),
    config: Path = typer.Option(Path(".loupe/config.yaml"), "--config"),
) -> None:
    """Run Loupe over the whole repo (or a subset) — D-15 scan mode.

    Bypasses the per-lens relevance threshold. Disabled lenses (config-level
    enabled=False) are still skipped. Use when onboarding, re-baselining,
    or doing an architectural review.
    """
    raise typer.Exit(code=scan_command(paths, config))


@app.command("mcp")
def mcp_cmd(
    loupe_dir: Path = typer.Option(
        Path(".loupe"), "--loupe-dir",
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
