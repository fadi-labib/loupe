from loupe_cli.__main__ import app
from typer.testing import CliRunner

runner = CliRunner()


def test_loupe_version_command():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "loupe" in result.stdout.lower()
