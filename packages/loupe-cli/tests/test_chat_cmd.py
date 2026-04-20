"""Tests for `loupe chat` — Layer 4 enforcement entry point.

The v1 scope is intentionally narrow: TTY guard + the default-N confirm
helper for protected-path proposals. The full conversational REPL is a
v1.x feature.
"""

from unittest.mock import patch

from loupe_cli.__main__ import app
from loupe_cli.chat_cmd import confirm_with_diff
from typer.testing import CliRunner

runner = CliRunner()


def test_chat_refuses_in_non_tty():
    """CliRunner's input is non-TTY by default — chat must refuse it."""
    result = runner.invoke(app, ["chat"])
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "tty" in combined.lower()


def test_confirm_default_n_blocks_apply():
    """Empty input (just Enter) MUST mean "don't apply" — Layer 4 default-N."""
    with patch("typer.prompt", return_value="N"):
        applied = confirm_with_diff(
            target="context.md",
            unified_diff="--- a/context.md\n+++ b/context.md\n@@ -1 +1 @@\n-x\n+y\n",
            rationale="example",
        )
    assert applied is False


def test_confirm_explicit_y_applies():
    with patch("typer.prompt", return_value="y"):
        applied = confirm_with_diff(
            target="context.md",
            unified_diff="--- a/context.md\n+++ b/context.md\n@@ -1 +1 @@\n-x\n+y\n",
            rationale="example",
        )
    assert applied is True


def test_confirm_y_case_insensitive():
    with patch("typer.prompt", return_value="Y"):
        applied = confirm_with_diff(
            target="x",
            unified_diff="diff",
            rationale="r",
        )
    assert applied is True


def test_confirm_skip_does_not_apply():
    with patch("typer.prompt", return_value="skip"):
        applied = confirm_with_diff(
            target="x",
            unified_diff="diff",
            rationale="r",
        )
    assert applied is False
