from loupe_cli.__main__ import app
from loupe_core import __version__
from typer.testing import CliRunner

runner = CliRunner()


def test_version_command_outputs_package_version():
    """`loupe --version` must print the actual package version, not a placeholder.

    Asserting that the printed string CONTAINS __version__ catches the regression
    where the formatter drops the value (e.g., `f"loupe {version}"` becomes
    `"loupe "` because `version` was unbound or empty).
    """
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout
    assert "loupe" in result.stdout.lower()
