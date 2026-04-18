"""Tests for the Semgrep static-analysis backend."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from loupe_core.capabilities.backends.semgrep_static import (
    SemgrepStaticBackend,
    _parse_semgrep_json,
)
from loupe_core.capabilities.errors import BackendError


def _result(
    *,
    check_id: str = "python.lang.security.audit.dangerous-eval-detected",
    path: str = "/repo/src/handler.py",
    line: int = 12,
    severity: str = "ERROR",
    message: str = "Detected dangerous primitive.",
) -> dict:
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": 4},
        "end": {"line": line, "col": 30},
        "extra": {"message": message, "severity": severity},
    }


def _document(*results: dict) -> str:
    return json.dumps({"results": list(results), "errors": []})


# ---------------------------------------------------------------------------
# _parse_semgrep_json
# ---------------------------------------------------------------------------


def test_parse_empty_stdout_returns_empty(tmp_path: Path):
    assert _parse_semgrep_json("", repo_path=tmp_path) == []
    assert _parse_semgrep_json("   ", repo_path=tmp_path) == []


def test_parse_empty_results_array_returns_empty(tmp_path: Path):
    assert _parse_semgrep_json(_document(), repo_path=tmp_path) == []


def test_parse_extracts_rule_and_message(tmp_path: Path):
    out = _parse_semgrep_json(
        _document(_result(check_id="rule.x", message="problem here")),
        repo_path=tmp_path,
    )
    assert len(out) == 1
    assert out[0].rule_id == "rule.x"
    assert out[0].message == "problem here"


def test_parse_converts_absolute_to_repo_relative_path(tmp_path: Path):
    """Semgrep emits absolute paths; backend normalises to repo-relative."""
    abs_path = str(tmp_path / "src" / "handler.py")
    out = _parse_semgrep_json(_document(_result(path=abs_path)), repo_path=tmp_path)
    assert out[0].file == "src/handler.py"


def test_parse_keeps_external_path_unchanged(tmp_path: Path):
    """If Semgrep returns a path outside repo_path (unusual), don't crash."""
    out = _parse_semgrep_json(
        _document(_result(path="/etc/something")),
        repo_path=tmp_path,
    )
    assert out[0].file == "/etc/something"


@pytest.mark.parametrize("semgrep_severity, expected", [
    ("ERROR", "high"),
    ("WARNING", "medium"),
    ("INFO", "low"),
    ("INVENTORY", "informational"),
    ("EXPERIMENT", "informational"),
    ("UNKNOWN_FUTURE_LEVEL", "informational"),  # graceful fallback
    ("error", "high"),  # case-insensitive
])
def test_parse_severity_mapping(tmp_path: Path, semgrep_severity, expected):
    out = _parse_semgrep_json(
        _document(_result(severity=semgrep_severity)),
        repo_path=tmp_path,
    )
    assert out[0].severity == expected


def test_parse_handles_missing_message(tmp_path: Path):
    """A result without extra.message MUST not blank-string into the finding."""
    result = _result()
    result["extra"]["message"] = ""
    out = _parse_semgrep_json(_document(result), repo_path=tmp_path)
    assert out[0].message == "(no message)"


def test_parse_malformed_json_raises(tmp_path: Path):
    with pytest.raises(BackendError) as exc_info:
        _parse_semgrep_json("this is not JSON", repo_path=tmp_path)
    assert "semgrep" in str(exc_info.value)


# ---------------------------------------------------------------------------
# SemgrepStaticBackend.run — mocked subprocess
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_backend_returns_typed_result(tmp_path: Path):
    payload = _document(_result(path=str(tmp_path / "x.py")))
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = payload
    mock_proc.stderr = ""

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("subprocess.run", return_value=mock_proc),
    ):
        result = await SemgrepStaticBackend().run(tmp_path)

    assert result.backend_name == "semgrep"
    assert len(result.findings) == 1
    assert result.findings[0].file == "x.py"


@pytest.mark.asyncio
async def test_backend_treats_exit_one_as_success(tmp_path: Path):
    """Semgrep returns exit 1 when findings+errors exist; this is still a valid scan."""
    payload = _document(_result(path=str(tmp_path / "x.py")))
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = payload
    mock_proc.stderr = "warning: some rules skipped"

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("subprocess.run", return_value=mock_proc),
    ):
        result = await SemgrepStaticBackend().run(tmp_path)
    assert len(result.findings) == 1


@pytest.mark.asyncio
async def test_backend_raises_on_environmental_failure(tmp_path: Path):
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = ""
    mock_proc.stderr = "semgrep: error: invalid config"

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("subprocess.run", return_value=mock_proc),
    ):
        with pytest.raises(BackendError) as exc_info:
            await SemgrepStaticBackend().run(tmp_path)
    assert "invalid config" in str(exc_info.value)


@pytest.mark.asyncio
async def test_backend_raises_when_binary_missing(tmp_path: Path):
    with patch("shutil.which", return_value=None):
        with pytest.raises(BackendError) as exc_info:
            await SemgrepStaticBackend().run(tmp_path)
    assert "semgrep" in str(exc_info.value)


def test_backend_registered_under_static_analysis_capability():
    assert SemgrepStaticBackend.name == "static_analysis"
    assert SemgrepStaticBackend.backend_name == "semgrep"
