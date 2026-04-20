"""Tests for the TruffleHog secret-detection backend."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from loupe_core.capabilities.backends.trufflehog_secret import (
    TruffleHogSecretBackend,
    _parse_trufflehog_ndjson,
    _redact,
)
from loupe_core.capabilities.errors import BackendError


def _entry(
    *,
    file_path: str = "src/api.py",
    line: int = 12,
    detector: str = "AWS",
    verified: bool = False,
    raw: str = "AKIA....",
    redacted: str | None = "AKIA****",
) -> dict:
    e = {
        "SourceMetadata": {
            "Data": {"Filesystem": {"file": file_path, "line": line}},
        },
        "DetectorName": detector,
        "Verified": verified,
        "Raw": raw,
    }
    if redacted is not None:
        e["Redacted"] = redacted
    return e


# ---------------------------------------------------------------------------
# _redact
# ---------------------------------------------------------------------------


def test_redact_local_helper_keeps_prefix():
    out = _redact("XXXXXXXXXXXXXXXXXXXX")
    assert out.startswith("XXXX")
    assert "redacted" in out


def test_redact_empty_returns_empty():
    assert _redact("") == ""


# ---------------------------------------------------------------------------
# _parse_trufflehog_ndjson
# ---------------------------------------------------------------------------


def test_parse_empty_stdout_returns_empty():
    assert _parse_trufflehog_ndjson("") == []


def test_parse_skips_non_json_lines():
    """TruffleHog sometimes prints a banner before NDJSON; tolerated, not error."""
    payload = "starting trufflehog v3.85.0\n" + json.dumps(_entry()) + "\n"
    findings = _parse_trufflehog_ndjson(payload)
    assert len(findings) == 1


def test_parse_logs_skipped_line_count(caplog: pytest.LogCaptureFixture):
    """Skipped (banner / unparseable) lines must surface as a WARNING so
    silent detection drops are at least observable to the operator."""
    payload = (
        "banner line one\n"
        + "banner line two\n"
        + "{not valid json\n"
        + json.dumps(_entry())
        + "\n"
    )
    with caplog.at_level("WARNING"):
        findings = _parse_trufflehog_ndjson(payload)
    assert len(findings) == 1
    assert any("skipped 3" in r.message for r in caplog.records)


def test_parse_extracts_file_and_line():
    payload = json.dumps(_entry(file_path="lib/x.py", line=99)) + "\n"
    findings = _parse_trufflehog_ndjson(payload)
    assert findings[0].file == "lib/x.py"
    assert findings[0].line == 99


def test_parse_uses_redacted_field_when_present():
    """Backend MUST prefer TruffleHog's own Redacted field over our redactor."""
    payload = json.dumps(_entry(redacted="AWS_TEST_*****")) + "\n"
    findings = _parse_trufflehog_ndjson(payload)
    assert findings[0].redacted_match == "AWS_TEST_*****"


def test_parse_falls_back_to_local_redact_when_no_redacted_field():
    """If TruffleHog omits Redacted, we synthesise one from Raw."""
    payload = json.dumps(_entry(raw="AKIA12345678", redacted=None)) + "\n"
    findings = _parse_trufflehog_ndjson(payload)
    assert findings[0].redacted_match.startswith("AKIA")
    assert "AKIA12345678" not in findings[0].redacted_match


def test_parse_severity_promotes_verified_to_critical():
    payload = "\n".join(
        [
            json.dumps(_entry(file_path="a.py", verified=True)),
            json.dumps(_entry(file_path="b.py", verified=False)),
        ]
    )
    findings = _parse_trufflehog_ndjson(payload)
    verified_f = next(f for f in findings if f.file == "a.py")
    unverified_f = next(f for f in findings if f.file == "b.py")
    assert verified_f.severity == "critical"
    assert unverified_f.severity == "high"


def test_parse_rule_id_marks_verified_findings():
    payload = json.dumps(_entry(detector="GitHub", verified=True)) + "\n"
    findings = _parse_trufflehog_ndjson(payload)
    assert findings[0].rule_id == "trufflehog/GitHub/verified"


def test_parse_malformed_lines_are_skipped_not_fatal():
    """One bad line shouldn't sink the whole scan."""
    payload = "\n".join(
        [
            json.dumps(_entry(file_path="ok.py")),
            '{"truncated incomplete json',  # malformed
            json.dumps(_entry(file_path="also_ok.py")),
        ]
    )
    findings = _parse_trufflehog_ndjson(payload)
    assert {f.file for f in findings} == {"ok.py", "also_ok.py"}


# ---------------------------------------------------------------------------
# TruffleHogSecretBackend.run — mocked subprocess
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_backend_returns_typed_result(tmp_path: Path):
    payload = "\n".join(
        [
            json.dumps(_entry(file_path="leak.py", verified=True)),
        ]
    )
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = payload
    mock_proc.stderr = ""

    with (
        patch("shutil.which", return_value="/usr/bin/trufflehog"),
        patch("subprocess.run", return_value=mock_proc),
    ):
        result = await TruffleHogSecretBackend().run(tmp_path)

    assert result.backend_name == "trufflehog"
    assert len(result.findings) == 1
    assert result.findings[0].file == "leak.py"
    assert result.findings[0].severity == "critical"


@pytest.mark.asyncio
async def test_backend_raises_when_binary_missing(tmp_path: Path):
    with patch("shutil.which", return_value=None):
        with pytest.raises(BackendError) as exc_info:
            await TruffleHogSecretBackend().run(tmp_path)
    assert "trufflehog" in str(exc_info.value)


@pytest.mark.asyncio
async def test_backend_raises_on_subprocess_failure(tmp_path: Path):
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = ""
    mock_proc.stderr = "detectors error"

    with (
        patch("shutil.which", return_value="/usr/bin/trufflehog"),
        patch("subprocess.run", return_value=mock_proc),
    ):
        with pytest.raises(BackendError) as exc_info:
            await TruffleHogSecretBackend().run(tmp_path)
    assert "detectors error" in str(exc_info.value)


def test_backend_registered_under_secret_detect_capability():
    assert TruffleHogSecretBackend.name == "secret_detect"
    assert TruffleHogSecretBackend.backend_name == "trufflehog"
