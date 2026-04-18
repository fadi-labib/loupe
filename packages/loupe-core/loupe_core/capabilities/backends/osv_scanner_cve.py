"""Google osv-scanner as a CVE backend (v1.x-C completion).

Second CVE backend so operators can run ``cve: mode=union, backends:
[grype, osv-scanner]`` for genuine coverage breadth. The two scanners
draw on different vulnerability databases — Grype uses Anchore's curated
mirror; osv-scanner consumes the OSV.dev feed maintained by Google plus
the GitHub Advisory Database. Findings are deduped by ``(cve_id,
component_name, component_version)`` in the union composition.

osv-scanner accepts an SBOM as input via ``--sbom=<file>`` and emits
JSON with one finding per (package, vulnerability). Shape, as of
osv-scanner v1.9 (verified 2026-05-15):

    {
      "results": [
        {
          "source": {"path": "sbom.cdx.json"},
          "packages": [
            {
              "package": {"name": "requests", "version": "2.31.0",
                          "ecosystem": "PyPI"},
              "vulnerabilities": [
                {
                  "id": "GHSA-j8r2-6x86-q33q",
                  "aliases": ["CVE-2024-35195"],
                  "summary": "Requests vulnerability allows session ...",
                  "severity": [{"type": "CVSS_V3",
                                "score": "CVSS:3.1/AV:N/AC:L/.../C:H/I:H/A:H"}],
                  "database_specific": {"severity": "MODERATE"}
                }
              ]
            }
          ]
        }
      ]
    }
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from loupe_core.capabilities.backends import format_subprocess_failure
from loupe_core.capabilities.errors import BackendError
from loupe_core.capabilities.protocols import (
    CveFinding,
    CveResult,
    SbomResult,
)
from loupe_core.capabilities.protocols.cve import Severity

# OSV / GHSA severity vocabulary → Loupe severity.
_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "MODERATE": "medium",
    "LOW": "low",
    "INFORMATIONAL": "informational",
    "UNKNOWN": "informational",
}


class OsvScannerCveBackend:
    """Google osv-scanner against a CycloneDX SBOM."""

    name = "cve"
    backend_name = "osv-scanner"

    async def run(self, sbom: SbomResult) -> CveResult:
        if shutil.which("osv-scanner") is None:
            raise BackendError(
                backend_name=self.backend_name,
                message=(
                    "osv-scanner binary not on PATH "
                    "(install from https://github.com/google/osv-scanner)"
                ),
            )

        # osv-scanner reads the SBOM from disk; write the SbomResult's raw
        # CycloneDX document to a temp file. The temp file holds the SBOM
        # only for the duration of the scan; never persisted.
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cdx.json", delete=False,
        ) as fh:
            sbom_path = Path(fh.name)
            fh.write(sbom.raw_document or "")

        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                [
                    "osv-scanner", "scan", "source",
                    "--sbom", str(sbom_path),
                    "--format", "json",
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )
            # osv-scanner returns 1 when vulnerabilities are found; both 0
            # and 1 are successful scans. Anything else is a real error.
            if proc.returncode not in (0, 1):
                raise BackendError(
                    backend_name=self.backend_name,
                    message=format_subprocess_failure(proc),
                )
            findings = _parse_osv_json(proc.stdout)
        finally:
            try:
                sbom_path.unlink()
            except OSError:
                pass

        return CveResult(findings=findings, backend_name=self.backend_name)


def _parse_osv_json(stdout: str) -> list[CveFinding]:
    """Walk the nested OSV JSON output into a flat list of CveFinding."""
    text = stdout.strip()
    if not text:
        return []
    try:
        document = json.loads(text)
    except json.JSONDecodeError as cause:
        raise BackendError(
            backend_name="osv-scanner",
            message=f"could not parse osv-scanner JSON output: {cause}",
        ) from cause

    findings: list[CveFinding] = []
    for source in document.get("results", []):
        for package in source.get("packages", []):
            pkg_info = package.get("package") or {}
            name = pkg_info.get("name", "")
            version = pkg_info.get("version", "")
            for vuln in package.get("vulnerabilities", []) or []:
                # Prefer the CVE alias when present so the union dedup
                # against grype works on the same ID space; fall back to
                # GHSA / OSV ids only when no CVE is listed.
                aliases = vuln.get("aliases") or []
                cve_id = next(
                    (a for a in aliases if a.startswith("CVE-")),
                    vuln.get("id", "UNKNOWN"),
                )
                summary = (vuln.get("summary") or "").strip() or "(no summary)"
                # database_specific severity is the closest thing OSV has
                # to a categorical level; CVSS_V3 score string is harder
                # to map cleanly. Fall back to "informational" if neither
                # is present.
                db = vuln.get("database_specific") or {}
                level_raw = (db.get("severity") or "").upper()
                severity = _SEVERITY_MAP.get(level_raw, "informational")
                source_url = next(
                    (r.get("url") for r in (vuln.get("references") or [])
                     if r.get("url", "").startswith("http")),
                    None,
                )
                findings.append(CveFinding(
                    cve_id=cve_id,
                    component_name=name,
                    component_version=version,
                    severity=severity,
                    summary=summary,
                    source_url=source_url,
                ))
    return findings
