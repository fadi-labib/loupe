from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from loupe_core.capabilities.errors import BackendError
from loupe_core.capabilities.protocols import CveFinding, CveResult, SbomResult
from loupe_core.capabilities.protocols.cve import Severity

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "negligible": "informational",
    "unknown": "informational",
}


class GrypeCveBackend:
    """Anchore Grype as the default CVE scanner. Consumes a CycloneDX SBOM via stdin."""

    name = "cve"
    backend_name = "grype"

    async def run(self, sbom: SbomResult) -> CveResult:
        if shutil.which("grype") is None:
            raise BackendError(
                backend_name=self.backend_name,
                message="grype binary not on PATH (install from https://github.com/anchore/grype)",
            )
        proc = subprocess.run(
            ["grype", "sbom:-", "-o", "json"],
            input=sbom.raw_document,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if proc.returncode != 0:
            raise BackendError(backend_name=self.backend_name, message=proc.stderr.strip())
        parsed = json.loads(proc.stdout)
        findings = [self._finding_from_match(m) for m in parsed.get("matches", [])]
        return CveResult(findings=findings, backend_name=self.backend_name)

    def _finding_from_match(self, match: dict[str, Any]) -> CveFinding:
        vuln = match.get("vulnerability", {})
        artefact = match.get("artifact", {})
        raw_sev = str(vuln.get("severity", "unknown")).lower()
        severity: Severity = _SEVERITY_MAP.get(raw_sev, "informational")
        return CveFinding(
            cve_id=vuln.get("id", ""),
            component_name=artefact.get("name", ""),
            component_version=artefact.get("version", ""),
            severity=severity,
            summary=vuln.get("description", ""),
            source_url=vuln.get("dataSource"),
        )
