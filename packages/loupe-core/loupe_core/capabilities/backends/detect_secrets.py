"""Yelp's detect-secrets as a third SecretDetectionCapability backend.

Adds a third independent secret scanner alongside gitleaks and
TruffleHog. detect-secrets uses entropy detection + a curated set of
named plugins (AWSKeyDetector, GitHubTokenDetector, SoftlayerDetector,
...). Running ``mode: union, backends: [gitleaks, trufflehog,
detect-secrets]`` catches what each alone misses; running consensus
threshold 2 across them filters out one-scanner false positives.

detect-secrets scan emits a JSON document with a ``results`` map
keyed by filename. Shape (verified against detect-secrets 1.5, 2026-
05-15):

    {
      "version": "1.5.0",
      "plugins_used": [ ... ],
      "results": {
        "src/api/secrets.py": [
          {
            "type": "AWS Access Key",
            "filename": "src/api/secrets.py",
            "hashed_secret": "...",
            "is_verified": false,
            "line_number": 14
          }
        ]
      }
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


class DetectSecretsBackend:
    """Yelp detect-secrets as a third secret-detection backend."""

    name = "secret_detect"
    backend_name = "detect-secrets"

    async def run(self, repo_path: Path) -> SecretDetectionResult:
        if shutil.which("detect-secrets") is None:
            raise BackendError(
                backend_name=self.backend_name,
                message=(
                    "detect-secrets binary not on PATH "
                    "(install via `pip install detect-secrets` or "
                    "`uv tool install detect-secrets`)"
                ),
            )

        # `detect-secrets scan <path>` emits the baseline JSON to stdout.
        # No file is written; we parse it directly.
        proc = subprocess.run(
            ["detect-secrets", "scan", str(repo_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            raise BackendError(
                backend_name=self.backend_name,
                message=proc.stderr.strip()
                        or f"detect-secrets exited {proc.returncode}",
            )

        findings = _parse_detect_secrets_json(proc.stdout, repo_path=repo_path)
        return SecretDetectionResult(
            findings=findings,
            backend_name=self.backend_name,
        )


def _parse_detect_secrets_json(
    stdout: str, *, repo_path: Path,
) -> list[SecretFinding]:
    """Convert detect-secrets' file-keyed `results` map to a flat list."""
    text = stdout.strip()
    if not text:
        return []
    try:
        document = json.loads(text)
    except json.JSONDecodeError as cause:
        raise BackendError(
            backend_name="detect-secrets",
            message=f"could not parse detect-secrets JSON output: {cause}",
        ) from cause

    findings: list[SecretFinding] = []
    for filename, entries in (document.get("results") or {}).items():
        # detect-secrets emits paths relative to where it was invoked
        # from — we ran it with repo_path, so the keys are already
        # repo-relative. Strip any leading "./" for consistency.
        rel = filename.removeprefix("./")
        for entry in entries:
            detector = entry.get("type", "unknown")
            verified = entry.get("is_verified", False)
            rule_id = f"detect-secrets/{detector}"
            if verified:
                rule_id += "/verified"
            # detect-secrets only emits hashed_secret (intentional — they
            # don't carry the raw value around). Show the detector type
            # plus a verification hint as the "match" so operators can
            # recognise the class.
            redacted = f"<{detector}{' (verified)' if verified else ''}>"
            line_raw = int(entry.get("line_number", 0) or 0)
            findings.append(SecretFinding(
                file=rel,
                line=line_raw if line_raw >= 1 else None,
                rule_id=rule_id,
                redacted_match=redacted,
                severity="critical" if verified else "high",
            ))
    return findings
