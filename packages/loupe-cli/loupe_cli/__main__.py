from pathlib import Path
import typer
from loupe_core import __version__

app = typer.Typer(no_args_is_help=True, add_completion=False)


@app.callback(invoke_without_command=True)
def main(version: bool = typer.Option(False, "--version", help="Print version and exit.")) -> None:
    if version:
        typer.echo(f"loupe {__version__}")
        raise typer.Exit()


@app.command("ci")
def ci_cmd(
    pr: str | None = typer.Option(None, "--pr", help="Pull request number."),
    diff: str = typer.Option("", "--diff", help="Unified diff text."),
    diff_file: Path | None = typer.Option(None, "--diff-file", help="Path to a unified diff."),
    base_sha: str | None = typer.Option(None, "--base-sha"),
    head_sha: str | None = typer.Option(None, "--head-sha"),
    config: Path = typer.Option(Path(".loupe/config.yaml"), "--config"),
) -> None:
    """Run Loupe in CI mode on a unified diff (stub — Phase 7 implements the real flow)."""
    typer.echo(
        "loupe ci: not yet implemented (Phase 7 of the implementation plan).\n"
        "This stub exists so the GitHub Action wrapper doesn't fail on an unknown command.\n"
        f"Received: pr={pr!r} config={config} base_sha={base_sha!r} head_sha={head_sha!r}",
        err=True,
    )
    raise typer.Exit(code=64)  # EX_USAGE — clear "not ready" signal


if __name__ == "__main__":
    app()
