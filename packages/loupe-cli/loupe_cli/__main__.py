from pathlib import Path

import typer
from loupe_core import __version__

from loupe_cli.ci_cmd import ci_command
from loupe_cli.init_cmd import init_command

app = typer.Typer(no_args_is_help=True, add_completion=False)


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


if __name__ == "__main__":
    app()
