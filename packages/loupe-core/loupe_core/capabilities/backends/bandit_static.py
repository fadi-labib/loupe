"""Bandit as a third Python-only StaticAnalysisCapability backend.

Bandit (PyCQA) is Python-specific by design. Useful in consensus mode
with Semgrep + CodeQL when the audit target is a Python codebase:
three independent analysers, ``threshold: 2`` filters false positives
aggressively. For non-Python repos, Bandit emits zero findings — same
shape as Syft on a vendor directory with no manifests.

Bandit JSON output (verified against bandit 1.7, 2026-05-15):

    {
      "results": [
        {
          "test_id": "B201",
          "test_name": "flask_debug_true",
          "issue_text": "...",
          "issue_severity": "HIGH",
          "issue_confidence": "MEDIUM",
          "filename": "src/api/app.py",
          "line_number": 14,
          ...
        }
      ],
      "errors": []
    }
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from pathlib import Path

from loupe_core.capabilities.errors import BackendError
from loupe_core.capabilities.protocols import (
    StaticAnalysisResult,
    StaticFinding,
)
from loupe_core.capabilities.protocols.static_analysis import Severity

# Bandit severity vocabulary → Loupe severity. Bandit's HIGH already
# means "definitely a security issue", so we don't gate it on confidence
# at the backend level — that's a job for the lens / agent reviewing
# findings. (Consensus mode does the FP filtering more reliably anyway.)
_SEVERITY_MAP: dict[str, Severity] = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNDEFINED": "informational",
}


class BanditStaticBackend:
    """Bandit (PyCQA) as a Python-only static-analysis backend."""

    name = "static_analysis"
    backend_name = "bandit"

    async def run(self, repo_path: Path) -> StaticAnalysisResult:
        if shutil.which("bandit") is None:
            raise BackendError(
                backend_name=self.backend_name,
                message=(
                    "bandit binary not on PATH "
                    "(install via `pip install bandit` or `uv tool install bandit`)"
                ),
            )

        # ``-r`` recurses into the target; ``-f json`` is the structured
        # output mode. We capture stderr for hard errors but ignore the
        # standard bandit summary it prints there during a normal run.
        proc = await asyncio.to_thread(
            subprocess.run,
            [
                "bandit",
                "-r", str(repo_path),
                "-f", "json",
                "-q",  # quiet: suppress non-JSON banner output
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        # Bandit exits 1 when findings exist; 0 when clean; >1 for real errors.
        if proc.returncode not in (0, 1):
            raise BackendError(
                backend_name=self.backend_name,
                message=proc.stderr.strip() or f"bandit exited {proc.returncode}",
            )

        findings = _parse_bandit_json(proc.stdout, repo_path=repo_path)
        return StaticAnalysisResult(findings=findings, backend_name=self.backend_name)


def _parse_bandit_json(stdout: str, *, repo_path: Path) -> list[StaticFinding]:
    text = stdout.strip()
    if not text:
        return []
    try:
        document = json.loads(text)
    except json.JSONDecodeError as cause:
        raise BackendError(
            backend_name="bandit",
            message=f"could not parse bandit JSON output: {cause}",
        ) from cause

    findings: list[StaticFinding] = []
    for entry in document.get("results", []):
        # Bandit emits absolute paths by default; convert to repo-relative
        # for cross-backend consistency (gitleaks/TruffleHog/Semgrep all
        # do this).
        filename = entry.get("filename", "")
        try:
            rel = str(Path(filename).relative_to(repo_path)) if filename else ""
        except ValueError:
            rel = filename

        rule_id = entry.get("test_id") or entry.get("test_name") or "unknown"
        message = (entry.get("issue_text") or "").strip() or "(no message)"
        severity = _SEVERITY_MAP.get(
            (entry.get("issue_severity") or "").upper(),
            "informational",
        )
        line_raw = int(entry.get("line_number", 0) or 0)
        line: int | None = line_raw if line_raw >= 1 else None

        findings.append(StaticFinding(
            rule_id=rule_id,
            file=rel,
            line=line,
            severity=severity,
            message=message,
        ))
    return findings
