"""Gitleaks as a SecretDetectionCapability backend (roadmap v1.x-D).

Gitleaks scans the working tree (and git history) for high-entropy
strings and pattern-matched secret leaks. We invoke `gitleaks detect`
in JSON-output mode and parse the result into the platform-typed
SecretDetectionResult.

Why gitleaks specifically: it's the most-used OSS secret scanner, ships
with a permissive licence, and has a stable JSON output schema. The
union composition mode (D-18) lets operators pair gitleaks with
TruffleHog for belt-and-braces coverage — different scanners find
different things.

Gitleaks' JSON schema as of v8.21 (verified 2026-05-15):
    [
      {
        "Description": "...",
        "StartLine": 12,
        "EndLine": 12,
        "File": "src/api/secrets.py",
        "Match": "AKIA...",
        "Secret": "AKIA...",
        "RuleID": "aws-access-token",
        ...
      },
      ...
    ]
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from loupe_core.capabilities.errors import BackendError
from loupe_core.capabilities.protocols import (
    SecretDetectionResult,
    SecretFinding,
)

# Length of the "redacted" rendering we substitute for the raw secret.
# Long enough for an operator to recognise the prefix, short enough that
# the redaction never reconstructs the original.
_REDACTION_PREFIX_CHARS = 4


def _redact(secret: str) -> str:
    """Render a secret value so an operator can recognise it without revealing it."""
    if not secret:
        return ""
    prefix = secret[:_REDACTION_PREFIX_CHARS]
    return f"{prefix}...[redacted, len={len(secret)}]"


class GitleaksSecretBackend:
    """Gitleaks as the default secret-detection backend."""

    name = "secret_detect"
    backend_name = "gitleaks"

    async def run(self, repo_path: Path) -> SecretDetectionResult:
        if shutil.which("gitleaks") is None:
            raise BackendError(
                backend_name=self.backend_name,
                message=(
                    "gitleaks binary not on PATH "
                    "(install from https://github.com/gitleaks/gitleaks)"
                ),
            )

        # `--no-banner` keeps stderr quiet; we ask gitleaks to write the
        # JSON report to a tempfile (cross-platform — the previous
        # `/dev/stdout` arg was Linux-only; macOS would treat it as a
        # literal filename). The cdxgen backend uses the same pattern.
        # Gitleaks exits 1 when findings are present, which is informational —
        # we treat the run as successful as long as the JSON parses.
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".gitleaks.json", delete=False,
        ) as fh:
            report_path = Path(fh.name)

        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                [
                    "gitleaks", "detect",
                    "--source", str(repo_path),
                    "--no-banner",
                    "--report-format", "json",
                    "--report-path", str(report_path),
                    "--exit-code", "0",   # always exit 0; we read findings from the report file
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )

            # Even with --exit-code 0, a real failure (e.g., not-a-git-repo) returns
            # non-zero with details on stderr.
            if proc.returncode != 0:
                raise BackendError(
                    backend_name=self.backend_name,
                    message=proc.stderr.strip() or f"gitleaks exited {proc.returncode}",
                )

            report_text = report_path.read_text() if report_path.exists() else "[]"
        finally:
            try:
                report_path.unlink()
            except OSError:
                pass

        findings = _parse_gitleaks_json(report_text)
        return SecretDetectionResult(
            findings=findings,
            backend_name=self.backend_name,
        )


def _parse_gitleaks_json(stdout: str) -> list[SecretFinding]:
    """Convert gitleaks' JSON array into a list of SecretFinding.

    Empty stdout (no findings) is treated as an empty result, not an
    error. Malformed JSON raises BackendError to surface the parser
    issue rather than silently swallow scan output.
    """
    text = stdout.strip()
    if not text:
        return []
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BackendError(
            backend_name="gitleaks",
            message=f"could not parse gitleaks JSON output: {exc}",
        ) from exc

    findings: list[SecretFinding] = []
    for entry in raw:
        line_raw = int(entry.get("StartLine", 0) or 0)
        findings.append(SecretFinding(
            file=entry.get("File", ""),
            line=line_raw if line_raw >= 1 else None,
            rule_id=entry.get("RuleID", "unknown"),
            redacted_match=_redact(entry.get("Secret", "")),
            # gitleaks doesn't emit a severity; convention is HIGH for any
            # matched secret because the consequence is the same regardless
            # of which rule fired. Operators can re-grade in mitigation review.
            severity="high",
        ))
    return findings
