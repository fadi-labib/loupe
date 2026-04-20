"""Tests for the three follow-up backends: osv-scanner, bandit, detect-secrets.

Same hermetic pattern as the existing backend tests — subprocess.run
is mocked so no real binary is required. The tests pin the JSON-shape
contract each backend depends on so an upstream tool format change
surfaces here, not in production.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from loupe_core.capabilities.backends.bandit_static import (
    BanditStaticBackend,
    _parse_bandit_json,
)
from loupe_core.capabilities.backends.detect_secrets import (
    DetectSecretsBackend,
    _parse_detect_secrets_json,
)
from loupe_core.capabilities.backends.osv_scanner_cve import (
    OsvScannerCveBackend,
    _parse_osv_json,
)
from loupe_core.capabilities.errors import BackendError
from loupe_core.capabilities.protocols import SbomResult

# ===========================================================================
# osv-scanner
# ===========================================================================


def _osv_doc(*findings: dict) -> str:
    by_pkg: dict[str, list[dict]] = {}
    for f in findings:
        key = f"{f['name']}@{f['version']}"
        by_pkg.setdefault(key, []).append(f)
    packages = []
    for fs in by_pkg.values():
        f0 = fs[0]
        packages.append(
            {
                "package": {"name": f0["name"], "version": f0["version"], "ecosystem": "PyPI"},
                "vulnerabilities": [
                    {
                        "id": f.get("ghsa", f["cve"]),
                        "aliases": [f["cve"]],
                        "summary": f.get("summary", "Example summary."),
                        "database_specific": {
                            "severity": f.get("severity", "MODERATE"),
                        },
                        "references": [{"url": f.get("url", "https://example.com")}],
                    }
                    for f in fs
                ],
            }
        )
    return json.dumps({"results": [{"packages": packages}]})


def test_osv_parse_empty_stdout_returns_empty():
    assert _parse_osv_json("") == []


def test_osv_parse_basic_finding():
    payload = _osv_doc(
        {
            "name": "requests",
            "version": "2.31.0",
            "cve": "CVE-2024-35195",
            "severity": "MODERATE",
        }
    )
    findings = _parse_osv_json(payload)
    assert len(findings) == 1
    f = findings[0]
    assert f.cve_id == "CVE-2024-35195"
    assert f.component_name == "requests"
    assert f.component_version == "2.31.0"
    assert f.severity == "medium"  # MODERATE → medium


def test_osv_prefers_cve_alias_over_ghsa_id():
    """The union composition dedups on cve_id — must match Grype's ID space."""
    payload = _osv_doc(
        {
            "name": "requests",
            "version": "2.31.0",
            "cve": "CVE-2024-1234",
            "ghsa": "GHSA-j8r2-6x86-q33q",
            "severity": "HIGH",
        }
    )
    findings = _parse_osv_json(payload)
    assert findings[0].cve_id == "CVE-2024-1234"


@pytest.mark.parametrize(
    "osv_sev, expected",
    [
        ("CRITICAL", "critical"),
        ("HIGH", "high"),
        ("MODERATE", "medium"),
        ("MEDIUM", "medium"),
        ("LOW", "low"),
        ("UNKNOWN", "informational"),
        ("anything-weird", "informational"),  # graceful fallback
    ],
)
def test_osv_severity_mapping(osv_sev, expected):
    payload = _osv_doc(
        {
            "name": "x",
            "version": "1",
            "cve": "CVE-X",
            "severity": osv_sev,
        }
    )
    findings = _parse_osv_json(payload)
    assert findings[0].severity == expected


def test_osv_parse_malformed_json_raises():
    with pytest.raises(BackendError):
        _parse_osv_json("not JSON")


@pytest.mark.asyncio
async def test_osv_backend_returns_typed_result(tmp_path):
    payload = _osv_doc(
        {
            "name": "fastapi",
            "version": "0.104.0",
            "cve": "CVE-2024-5678",
            "severity": "HIGH",
        }
    )
    mock_proc = MagicMock()
    mock_proc.returncode = 1  # findings present → exit 1; still success
    mock_proc.stdout = payload
    mock_proc.stderr = ""

    sbom = SbomResult(raw_document='{"bomFormat":"CycloneDX"}', backend_name="syft")

    with (
        patch("shutil.which", return_value="/usr/bin/osv-scanner"),
        patch("subprocess.run", return_value=mock_proc),
    ):
        result = await OsvScannerCveBackend().run(sbom)

    assert result.backend_name == "osv-scanner"
    assert len(result.findings) == 1
    assert result.findings[0].cve_id == "CVE-2024-5678"


@pytest.mark.asyncio
async def test_osv_backend_raises_when_binary_missing(tmp_path):
    sbom = SbomResult(backend_name="syft")
    with patch("shutil.which", return_value=None):
        with pytest.raises(BackendError):
            await OsvScannerCveBackend().run(sbom)


def test_osv_backend_registered_under_cve_capability():
    assert OsvScannerCveBackend.name == "cve"
    assert OsvScannerCveBackend.backend_name == "osv-scanner"


# ===========================================================================
# bandit
# ===========================================================================


def _bandit_doc(*results: dict) -> str:
    return json.dumps({"results": list(results), "errors": []})


def _bandit_result(
    *,
    test_id: str = "B201",
    filename: str = "/repo/src/app.py",
    line: int = 14,
    severity: str = "HIGH",
    text: str = "Flask debug=True.",
) -> dict:
    return {
        "test_id": test_id,
        "test_name": "flask_debug_true",
        "filename": filename,
        "line_number": line,
        "issue_severity": severity,
        "issue_confidence": "MEDIUM",
        "issue_text": text,
    }


def test_bandit_parse_empty_returns_empty(tmp_path):
    assert _parse_bandit_json("", repo_path=tmp_path) == []


def test_bandit_parse_basic_finding(tmp_path):
    out = _parse_bandit_json(
        _bandit_doc(_bandit_result(filename=str(tmp_path / "app.py"))),
        repo_path=tmp_path,
    )
    assert len(out) == 1
    f = out[0]
    assert f.rule_id == "B201"
    assert f.file == "app.py"
    assert f.line == 14
    assert f.severity == "high"


@pytest.mark.parametrize(
    "bandit_sev, expected",
    [
        ("HIGH", "high"),
        ("MEDIUM", "medium"),
        ("LOW", "low"),
        ("UNDEFINED", "informational"),
        ("WHATEVER", "informational"),
    ],
)
def test_bandit_severity_mapping(tmp_path, bandit_sev, expected):
    out = _parse_bandit_json(
        _bandit_doc(_bandit_result(severity=bandit_sev)),
        repo_path=tmp_path,
    )
    assert out[0].severity == expected


def test_bandit_parse_malformed_raises(tmp_path):
    with pytest.raises(BackendError):
        _parse_bandit_json("not JSON", repo_path=tmp_path)


@pytest.mark.asyncio
async def test_bandit_backend_returns_typed_result(tmp_path):
    payload = _bandit_doc(_bandit_result(filename=str(tmp_path / "app.py")))
    mock_proc = MagicMock()
    mock_proc.returncode = 1  # findings present → exit 1
    mock_proc.stdout = payload
    mock_proc.stderr = ""

    with (
        patch("shutil.which", return_value="/usr/bin/bandit"),
        patch("subprocess.run", return_value=mock_proc),
    ):
        result = await BanditStaticBackend().run(tmp_path)

    assert result.backend_name == "bandit"
    assert result.findings[0].rule_id == "B201"


@pytest.mark.asyncio
async def test_bandit_backend_raises_when_binary_missing(tmp_path):
    with patch("shutil.which", return_value=None):
        with pytest.raises(BackendError):
            await BanditStaticBackend().run(tmp_path)


def test_bandit_backend_registered_under_static_analysis_capability():
    assert BanditStaticBackend.name == "static_analysis"
    assert BanditStaticBackend.backend_name == "bandit"


# ===========================================================================
# detect-secrets
# ===========================================================================


def _ds_doc(results: dict[str, list[dict]]) -> str:
    return json.dumps(
        {
            "version": "1.5.0",
            "plugins_used": [],
            "results": results,
        }
    )


def _ds_entry(
    *,
    detector: str = "AWS Access Key",
    filename: str = "src/secrets.py",
    line: int = 14,
    verified: bool = False,
) -> dict:
    return {
        "type": detector,
        "filename": filename,
        "hashed_secret": "deadbeef" * 8,
        "is_verified": verified,
        "line_number": line,
    }


def test_ds_parse_empty_returns_empty(tmp_path):
    assert _parse_detect_secrets_json("", repo_path=tmp_path) == []


def test_ds_parse_basic_finding(tmp_path):
    payload = _ds_doc({"src/secrets.py": [_ds_entry()]})
    findings = _parse_detect_secrets_json(payload, repo_path=tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.file == "src/secrets.py"
    assert f.line == 14
    assert f.rule_id == "detect-secrets/AWS Access Key"
    assert f.severity == "high"
    # detect-secrets never carries the raw value — only a hash. The
    # redacted_match should describe the detector class, not the secret.
    assert "AWS Access Key" in f.redacted_match


def test_ds_verified_secret_is_critical(tmp_path):
    payload = _ds_doc({"x.py": [_ds_entry(verified=True)]})
    findings = _parse_detect_secrets_json(payload, repo_path=tmp_path)
    assert findings[0].severity == "critical"
    assert "verified" in findings[0].rule_id


def test_ds_multiple_secrets_per_file(tmp_path):
    payload = _ds_doc(
        {
            "a.py": [_ds_entry(line=1), _ds_entry(line=2)],
            "b.py": [_ds_entry(line=5)],
        }
    )
    findings = _parse_detect_secrets_json(payload, repo_path=tmp_path)
    assert len(findings) == 3
    # All entries serialise; per-file order preserved.
    a_lines = sorted(f.line for f in findings if f.file == "a.py")
    assert a_lines == [1, 2]


def test_ds_strips_leading_dot_slash(tmp_path):
    payload = _ds_doc({"./src/app.py": [_ds_entry(filename="./src/app.py")]})
    findings = _parse_detect_secrets_json(payload, repo_path=tmp_path)
    assert findings[0].file == "src/app.py"


def test_ds_parse_malformed_raises(tmp_path):
    with pytest.raises(BackendError):
        _parse_detect_secrets_json("not JSON", repo_path=tmp_path)


@pytest.mark.asyncio
async def test_ds_backend_returns_typed_result(tmp_path):
    payload = _ds_doc({"src/x.py": [_ds_entry()]})
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = payload
    mock_proc.stderr = ""

    with (
        patch("shutil.which", return_value="/usr/bin/detect-secrets"),
        patch("subprocess.run", return_value=mock_proc),
    ):
        result = await DetectSecretsBackend().run(tmp_path)

    assert result.backend_name == "detect-secrets"
    assert len(result.findings) == 1


@pytest.mark.asyncio
async def test_ds_backend_raises_when_binary_missing(tmp_path):
    with patch("shutil.which", return_value=None):
        with pytest.raises(BackendError):
            await DetectSecretsBackend().run(tmp_path)


def test_ds_backend_registered_under_secret_detect_capability():
    assert DetectSecretsBackend.name == "secret_detect"
    assert DetectSecretsBackend.backend_name == "detect-secrets"
