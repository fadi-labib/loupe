"""Tests for the gitleaks secret-detection backend.

Uses the same pattern as syft_sbom / grype_cve tests: the real
`gitleaks` binary is not required (and would make CI non-hermetic).
We mock subprocess.run to return canned JSON output and assert the
backend parses it into typed SecretFinding objects.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from loupe_core.capabilities.backends.gitleaks_secret import (
    GitleaksSecretBackend,
    _parse_gitleaks_json,
    _redact,
)
from loupe_core.capabilities.errors import BackendError

# ---------------------------------------------------------------------------
# _redact
# ---------------------------------------------------------------------------


def test_redact_keeps_prefix():
    """Operator should recognise the key class without seeing the full value."""
    redacted = _redact("AKIAIOSFODNN7EXAMPLE")
    assert redacted.startswith("AKIA")
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "redacted" in redacted


def test_redact_handles_empty():
    assert _redact("") == ""


def test_redact_includes_length():
    """The redaction MUST encode original length so operators can sanity-check."""
    redacted = _redact("X" * 30)
    assert "len=30" in redacted


# ---------------------------------------------------------------------------
# _parse_gitleaks_json
# ---------------------------------------------------------------------------


def test_parse_empty_stdout_returns_empty():
    assert _parse_gitleaks_json("") == []
    assert _parse_gitleaks_json("   \n") == []


def test_parse_single_finding():
    payload = json.dumps(
        [
            {
                "Description": "AWS access token detected",
                "StartLine": 42,
                "EndLine": 42,
                "File": "src/api/secrets.py",
                "Match": "key = AKIAIOSFODNN7EXAMPLE",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "RuleID": "aws-access-token",
            }
        ]
    )
    findings = _parse_gitleaks_json(payload)
    assert len(findings) == 1
    f = findings[0]
    assert f.file == "src/api/secrets.py"
    assert f.line == 42
    assert f.rule_id == "aws-access-token"
    assert "AKIA" in f.redacted_match
    assert "AKIAIOSFODNN7EXAMPLE" not in f.redacted_match
    assert f.severity == "high"


def test_parse_multiple_findings():
    payload = json.dumps(
        [
            {"File": "a.py", "StartLine": 1, "RuleID": "rule-a", "Secret": "s1"},
            {"File": "b.py", "StartLine": 2, "RuleID": "rule-b", "Secret": "s2"},
        ]
    )
    findings = _parse_gitleaks_json(payload)
    assert len(findings) == 2
    assert findings[0].file == "a.py"
    assert findings[1].file == "b.py"


def test_parse_handles_missing_fields():
    """Gitleaks sometimes omits StartLine for whole-file matches; the
    protocol sentinel for whole-file / unknown is `line=None` (was `0`
    before Phase 7's 1-based-or-None refactor)."""
    payload = json.dumps([{"File": "x.py", "RuleID": "x", "Secret": "y"}])
    findings = _parse_gitleaks_json(payload)
    assert len(findings) == 1
    assert findings[0].line is None
    assert findings[0].rule_id == "x"


def test_parse_malformed_json_raises():
    with pytest.raises(BackendError) as exc_info:
        _parse_gitleaks_json("not json at all")
    assert "gitleaks" in str(exc_info.value)


# ---------------------------------------------------------------------------
# GitleaksSecretBackend.run — mocked subprocess
# ---------------------------------------------------------------------------


def _make_gitleaks_subprocess_side_effect(
    *,
    report_payload: str,
    returncode: int = 0,
    stderr: str = "",
):
    """Build a subprocess.run side_effect that mimics gitleaks writing its
    report to the path passed after ``--report-path``. The backend now
    reads from a tempfile (Phase 7 cross-platform fix) instead of
    ``/dev/stdout``; the side_effect performs the disk write the real
    binary would have done."""

    def _side_effect(cmd: list[str], *args: object, **kwargs: object) -> object:
        report_path = None
        for i, tok in enumerate(cmd):
            if tok == "--report-path" and i + 1 < len(cmd):
                report_path = Path(cmd[i + 1])
                break
        if report_path is not None:
            report_path.write_text(report_payload)
        proc = MagicMock()
        proc.returncode = returncode
        proc.stdout = ""
        proc.stderr = stderr
        return proc

    return _side_effect


@pytest.mark.asyncio
async def test_backend_returns_typed_result(tmp_path: Path):
    payload = json.dumps(
        [
            {
                "File": "leak.py",
                "StartLine": 5,
                "RuleID": "generic-api-key",
                "Secret": "sk-test-XXXXXXX",
            }
        ]
    )

    with (
        patch("shutil.which", return_value="/usr/bin/gitleaks"),
        patch(
            "subprocess.run",
            side_effect=_make_gitleaks_subprocess_side_effect(report_payload=payload),
        ),
    ):
        result = await GitleaksSecretBackend().run(tmp_path)

    assert result.backend_name == "gitleaks"
    assert len(result.findings) == 1
    assert result.findings[0].file == "leak.py"
    assert result.findings[0].rule_id == "generic-api-key"


@pytest.mark.asyncio
async def test_backend_returns_empty_when_no_findings(tmp_path: Path):
    """gitleaks emits an empty JSON array when nothing is found; backend
    should not crash."""
    with (
        patch("shutil.which", return_value="/usr/bin/gitleaks"),
        patch(
            "subprocess.run",
            side_effect=_make_gitleaks_subprocess_side_effect(report_payload="[]"),
        ),
    ):
        result = await GitleaksSecretBackend().run(tmp_path)

    assert result.findings == []
    assert result.backend_name == "gitleaks"


@pytest.mark.asyncio
async def test_backend_raises_when_binary_missing(tmp_path: Path):
    with patch("shutil.which", return_value=None):
        with pytest.raises(BackendError) as exc_info:
            await GitleaksSecretBackend().run(tmp_path)
    assert "gitleaks" in str(exc_info.value)


@pytest.mark.asyncio
async def test_backend_raises_on_subprocess_failure(tmp_path: Path):
    """Real failures (not findings) surface as BackendError, not silent zero."""
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = ""
    mock_proc.stderr = "fatal: not a git repository"

    with (
        patch("shutil.which", return_value="/usr/bin/gitleaks"),
        patch("subprocess.run", return_value=mock_proc),
    ):
        with pytest.raises(BackendError) as exc_info:
            await GitleaksSecretBackend().run(tmp_path)
    assert "not a git repository" in str(exc_info.value)


def test_backend_registered_under_secret_detect_capability():
    """The class-level `name` attribute must match the registry key."""
    assert GitleaksSecretBackend.name == "secret_detect"
    assert GitleaksSecretBackend.backend_name == "gitleaks"
