"""Semgrep as a StaticAnalysisCapability backend (roadmap v1.x-E).

Semgrep ships ~2000 OSS rules out of the box covering the OWASP Top 10,
the CWE Top 25, and language-specific footguns. We invoke
``semgrep scan --config=auto --json`` against the working tree and
parse the typed result into StaticAnalysisResult.

Semgrep's severity vocabulary differs from Loupe's. The mapping:

| Semgrep ``severity`` | Loupe ``severity`` |
|---|---|
| ERROR    | high     |
| WARNING  | medium   |
| INFO     | low      |
| (other)  | informational |

Semgrep also has an ``impact`` field on some findings; we ignore it at
v1 — Loupe operators re-grade severity in mitigation review and the
mapping above is the conservative starting point.

JSON output shape (verified against semgrep 1.92, 2026-05-15):

    {
      "results": [
        {
          "check_id": "python.lang.security.audit.dangerous-eval-detected",
          "path": "src/handler.py",
          "start": {"line": 12, "col": 4},
          "end": {"line": 12, "col": 30},
          "extra": {
            "message": "Detected the use of a dangerous-eval primitive.",
            "severity": "ERROR"
          }
        }
      ],
      "errors": [ ... ]
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

# Semgrep → Loupe severity mapping. Anything not in this dict falls back
# to "informational" so the result type stays valid; the rule_id still
# surfaces and an operator can grade manually.
_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    "INVENTORY": "informational",
    "EXPERIMENT": "informational",
}


class SemgrepStaticBackend:
    """Semgrep as the default static-analysis backend."""

    name = "static_analysis"
    backend_name = "semgrep"

    async def run(self, repo_path: Path) -> StaticAnalysisResult:
        if shutil.which("semgrep") is None:
            raise BackendError(
                backend_name=self.backend_name,
                message=(
                    "semgrep binary not on PATH "
                    "(install from https://semgrep.dev/docs/getting-started/)"
                ),
            )

        # `--config=auto` loads Semgrep's curated default rulepack for the
        # languages it detects in the target. `--json` emits the structured
        # output to stdout. `--metrics=off` keeps Semgrep from phoning home
        # to their telemetry endpoint — required for [principle §1] (no
        # surprise outbound network from a tool an auditor reads).
        proc = await asyncio.to_thread(
            subprocess.run,
            [
                "semgrep", "scan",
                "--config=auto",
                "--json",
                "--metrics=off",
                "--quiet",
                str(repo_path),
            ],
            capture_output=True,
            text=True,
            timeout=300,  # Semgrep can be slow on large repos; 5 min budget.
        )

        # Semgrep returns 0 with findings, 1 with findings + errors, and
        # non-zero codes for environmental failures. We treat 0 and 1 as
        # successful scans and anything else as a hard error.
        if proc.returncode not in (0, 1):
            raise BackendError(
                backend_name=self.backend_name,
                message=proc.stderr.strip() or f"semgrep exited {proc.returncode}",
            )

        findings = _parse_semgrep_json(proc.stdout, repo_path=repo_path)
        return StaticAnalysisResult(
            findings=findings,
            backend_name=self.backend_name,
        )


def _parse_semgrep_json(stdout: str, *, repo_path: Path) -> list[StaticFinding]:
    """Convert Semgrep's JSON ``results`` array into StaticFinding objects."""
    text = stdout.strip()
    if not text:
        return []
    try:
        document = json.loads(text)
    except json.JSONDecodeError as cause:
        raise BackendError(
            backend_name="semgrep",
            message=f"could not parse semgrep JSON output: {cause}",
        ) from cause

    findings: list[StaticFinding] = []
    for entry in document.get("results", []):
        rule_id = entry.get("check_id", "unknown")
        path = entry.get("path", "")
        # Semgrep emits absolute paths; convert to repo-relative for
        # cross-tool consistency (gitleaks / TruffleHog emit relative).
        try:
            rel = str(Path(path).relative_to(repo_path)) if path else ""
        except ValueError:
            rel = path  # path not under repo_path; leave as-is.

        start = entry.get("start") or {}
        start_line = int(start.get("line", 0) or 0)
        line: int | None = start_line if start_line >= 1 else None
        extra = entry.get("extra") or {}
        message = extra.get("message", "").strip() or "(no message)"
        severity = _SEVERITY_MAP.get(extra.get("severity", "").upper(), "informational")

        findings.append(StaticFinding(
            rule_id=rule_id,
            file=rel,
            line=line,
            severity=severity,
            message=message,
        ))
    return findings
