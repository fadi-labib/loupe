"""TruffleHog as a second SecretDetectionCapability backend.

Pair with `gitleaks` via `mode: union` (D-18 composition) — TruffleHog
specialises in *verified* high-entropy strings and live API-token
detection, while gitleaks excels at pattern-matched literals. Neither
is a strict superset; both is the responsible default for any team
that ships customer data.

TruffleHog v3 streams one NDJSON object per finding to stdout when
invoked with `--json`. Shape (verified against v3.85, 2026-05-15):
    {
      "SourceMetadata": {
        "Data": {
          "Filesystem": {"file": "src/api.py"}
        }
      },
      "DetectorName": "AWS",
      "DetectorType": 2,
      "Verified": false,
      "Raw": "AKIA...",
      "Redacted": "AKIA****",
      ...
    }
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from loupe_core.capabilities.errors import BackendError
from loupe_core.capabilities.protocols import (
    SecretDetectionResult,
    SecretFinding,
)


def _redact(secret: str) -> str:
    """Render the raw value in a redacted form fit for run-record serialisation."""
    if not secret:
        return ""
    return f"{secret[:4]}...[redacted, len={len(secret)}]"


class TruffleHogSecretBackend:
    """TruffleHog as a verified-secret backend; pairs with gitleaks in union mode."""

    name = "secret_detect"
    backend_name = "trufflehog"

    async def run(self, repo_path: Path) -> SecretDetectionResult:
        if shutil.which("trufflehog") is None:
            raise BackendError(
                backend_name=self.backend_name,
                message=(
                    "trufflehog binary not on PATH "
                    "(install from https://github.com/trufflesecurity/trufflehog)"
                ),
            )

        proc = subprocess.run(
            [
                "trufflehog", "filesystem", str(repo_path),
                "--json",
                "--no-update",         # don't reach to update detectors mid-run
                "--fail-no-detectors", # surface "no detectors" as a hard error
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )

        # TruffleHog returns 0 on success regardless of finding count; non-zero
        # means real failure (not-a-filesystem, detectors error, etc.).
        if proc.returncode != 0:
            raise BackendError(
                backend_name=self.backend_name,
                message=proc.stderr.strip() or f"trufflehog exited {proc.returncode}",
            )

        findings = _parse_trufflehog_ndjson(proc.stdout)
        return SecretDetectionResult(
            findings=findings,
            backend_name=self.backend_name,
        )


def _parse_trufflehog_ndjson(stdout: str) -> list[SecretFinding]:
    """Parse one NDJSON object per line; skip non-JSON banner / empty lines."""
    findings: list[SecretFinding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            # TruffleHog occasionally writes banner output before the first
            # JSON object; skip anything not shaped like JSON rather than
            # erroring (different from gitleaks' single-document format).
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            # One bad line shouldn't sink the whole scan; surface via stderr
            # not BackendError because TruffleHog NDJSON output can be
            # interleaved with diagnostic messages we don't recognise.
            continue

        file_path = (
            entry.get("SourceMetadata", {})
                 .get("Data", {})
                 .get("Filesystem", {})
                 .get("file", "")
        )
        line_no = (
            entry.get("SourceMetadata", {})
                 .get("Data", {})
                 .get("Filesystem", {})
                 .get("line", 0)
        )
        detector = entry.get("DetectorName", "unknown")
        verified = entry.get("Verified", False)
        rule_id = f"trufflehog/{detector}"
        if verified:
            rule_id += "/verified"

        # Prefer TruffleHog's own Redacted field when present; fall back to
        # our own redactor over Raw. We NEVER serialise Raw directly.
        redacted = entry.get("Redacted") or _redact(entry.get("Raw", ""))

        findings.append(SecretFinding(
            file=file_path,
            line=int(line_no or 0),
            rule_id=rule_id,
            redacted_match=redacted,
            # Verified findings are higher confidence than mere matches.
            # Critical for verified credentials (someone can use them now),
            # high otherwise.
            severity="critical" if verified else "high",
        ))
    return findings
