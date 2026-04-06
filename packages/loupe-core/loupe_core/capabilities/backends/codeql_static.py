"""CodeQL as a second StaticAnalysisCapability backend.

Pairs with Semgrep via ``mode: consensus, threshold: 2`` (D-18) for
false-positive reduction — only findings the two analysers both flag
make it through. CodeQL's queries are slower and more thorough; Semgrep
is faster and broader. Both is the audit-credibility default.

CodeQL fundamentally needs a *database* to query, built from the source
tree. Database construction is heavyweight (minutes on a real codebase)
and out of scope for this backend; we expect the operator to have
already run::

    codeql database create <db-path> \\
        --language=python \\
        --source-root=<repo>

before invoking ``loupe ci``. The backend locates the database in one
of three ways, in order:

1. ``capabilities.static_analysis.options.database_path`` from
   ``.loupe/config.yaml`` (preferred — explicit, typed, visible in
   the audit trail).
2. ``LOUPE_CODEQL_DB`` environment variable. **Deprecated**:
   emits ``DeprecationWarning``. Will be removed in a future minor.
3. ``<repo>/.codeql-db/`` directory if it exists.

When none is present we raise BackendError with the canonical
``codeql database create`` command so the operator can fix the setup
without grepping docs.

Output format: SARIF 2.1.0 — the same standard the GitHub Code Scanning
flow consumes. CodeQL writes SARIF; we parse the subset we care about
(ruleId, message, level, location).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import warnings
from pathlib import Path

from loupe_core.capabilities.errors import BackendError
from loupe_core.capabilities.protocols import (
    StaticAnalysisResult,
    StaticFinding,
)
from loupe_core.capabilities.protocols.static_analysis import Severity

# SARIF severity → Loupe severity. SARIF's vocabulary is "error",
# "warning", "note", "none" with optional security-severity (CVSS-like).
# We map by `level`; CVSS-style scoring is out of scope for v1.
_SARIF_LEVEL_MAP: dict[str, Severity] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "informational",
}


class CodeQLStaticBackend:
    """CodeQL as a corroboration backend for static_analysis (consensus mode).

    The optional ``options`` attribute (set by the registry from
    ``CapabilityActivation.options``) may carry ``"database_path"`` —
    the typed replacement for the deprecated ``LOUPE_CODEQL_DB`` env var.
    """

    name = "static_analysis"
    backend_name = "codeql"

    # Populated by ``CapabilityRegistry.resolve`` from the operator's
    # ``capabilities.static_analysis.options`` mapping. Empty if unset.
    options: dict[str, str] = {}

    async def run(self, repo_path: Path) -> StaticAnalysisResult:
        if shutil.which("codeql") is None:
            raise BackendError(
                backend_name=self.backend_name,
                message=(
                    "codeql binary not on PATH (install the CodeQL CLI bundle "
                    "from https://github.com/github/codeql-cli-binaries)"
                ),
            )

        configured_db = self.options.get("database_path") if self.options else None
        db_path = _locate_database(repo_path, database_path=configured_db)
        if db_path is None:
            raise BackendError(
                backend_name=self.backend_name,
                message=(
                    "CodeQL database not found. Build one first:\n"
                    "  codeql database create .codeql-db "
                    "--language=python --source-root=.\n"
                    "or point LOUPE_CODEQL_DB at an existing database directory."
                ),
            )

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sarif", delete=False,
        ) as fh:
            sarif_path = Path(fh.name)

        try:
            proc = subprocess.run(
                [
                    "codeql", "database", "analyze",
                    str(db_path),
                    "--format=sarif-latest",
                    f"--output={sarif_path}",
                    "--quiet",
                ],
                capture_output=True,
                text=True,
                timeout=600,  # CodeQL can be slow on large databases.
            )
            if proc.returncode != 0:
                raise BackendError(
                    backend_name=self.backend_name,
                    message=proc.stderr.strip()
                            or f"codeql exited {proc.returncode}",
                )
            sarif_text = sarif_path.read_text()
        finally:
            try:
                sarif_path.unlink()
            except OSError:
                pass

        findings = _parse_sarif(sarif_text)
        return StaticAnalysisResult(
            findings=findings,
            backend_name=self.backend_name,
        )


def _locate_database(
    repo_path: Path,
    *,
    database_path: str | None = None,
) -> Path | None:
    """Return the CodeQL database path or None if no source resolves.

    Resolution order:

    1. ``database_path`` (typed config from ``CapabilityActivation.options``).
    2. ``LOUPE_CODEQL_DB`` env var (deprecated — emits ``DeprecationWarning``).
    3. ``<repo_path>/.codeql-db`` convention directory.

    A stale path that points at a non-existent location is treated as
    "not configured" rather than an error, matching the pre-existing
    forgiving behaviour for env-var paths.
    """
    if database_path:
        candidate = Path(database_path)
        if candidate.exists():
            return candidate
    env_path = os.environ.get("LOUPE_CODEQL_DB")
    if env_path:
        warnings.warn(
            "LOUPE_CODEQL_DB is deprecated; configure "
            "`capabilities.static_analysis.options.database_path` in "
            ".loupe/config.yaml instead. The env-var fallback will be "
            "removed in a future minor.",
            DeprecationWarning,
            stacklevel=2,
        )
        candidate = Path(env_path)
        if candidate.exists():
            return candidate
    default = repo_path / ".codeql-db"
    if default.exists():
        return default
    return None


def _parse_sarif(sarif_text: str) -> list[StaticFinding]:
    """Convert SARIF 2.1.0 output to StaticFinding objects.

    SARIF allows multiple ``runs`` per document; CodeQL emits one. We
    walk every result in every run for robustness. Defensive about
    missing fields — the same SARIF schema is used by half a dozen
    tools and they don't all populate every optional path.
    """
    text = sarif_text.strip()
    if not text:
        return []
    try:
        document = json.loads(text)
    except json.JSONDecodeError as cause:
        raise BackendError(
            backend_name="codeql",
            message=f"could not parse SARIF output: {cause}",
        ) from cause

    findings: list[StaticFinding] = []
    for run in document.get("runs", []):
        for result in run.get("results", []):
            findings.append(_sarif_result_to_finding(result))
    return findings


def _sarif_result_to_finding(result: dict) -> StaticFinding:
    rule_id = result.get("ruleId", "unknown")
    message = (result.get("message") or {}).get("text", "").strip() or "(no message)"
    level = result.get("level", "warning").lower()
    severity = _SARIF_LEVEL_MAP.get(level, "informational")

    # SARIF locations is a list; we record the first physical location.
    locations = result.get("locations") or []
    file_uri = ""
    line: int | None = None
    if locations:
        phys = locations[0].get("physicalLocation") or {}
        file_uri = (phys.get("artifactLocation") or {}).get("uri", "")
        start_line = int((phys.get("region") or {}).get("startLine", 0) or 0)
        line = start_line if start_line >= 1 else None

    return StaticFinding(
        rule_id=rule_id,
        file=file_uri,
        line=line,
        severity=severity,
        message=message,
    )
