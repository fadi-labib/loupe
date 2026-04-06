"""cdxgen as a second SBOM backend.

Maintained by the OWASP CycloneDX project; ships native support for
JS/TS, Node, Java/Maven, Ruby, Python, Go, .NET, Swift, Rust, and more.
Emits CycloneDX JSON natively — same standard Syft emits — so the
SbomResult shape is identical and the two backends are union-mode-
ready out of the box. cdxgen is generally faster than Syft on
JavaScript monorepos (where Syft requires extra config) and slower
on container scanning (where Syft excels).

cdxgen CLI (verified against @cyclonedx/cdxgen 10.x, 2026-05-15):

    cdxgen -t <type> -o <output-path> <project-path>

We invoke it with the universal-language preset (``-t universal``)
which auto-detects every manifest type cdxgen knows about. Output
goes to a temp file because cdxgen historically wrote stdout banner
text that pollutes JSON parsing.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from loupe_core.capabilities.errors import BackendError
from loupe_core.capabilities.protocols import SbomComponent, SbomResult


class CdxgenSbomBackend:
    """cdxgen (OWASP CycloneDX-cdxgen) — second SBOM backend."""

    name = "sbom"
    backend_name = "cdxgen"

    async def run(self, repo_path: Path) -> SbomResult:
        if shutil.which("cdxgen") is None:
            raise BackendError(
                backend_name=self.backend_name,
                message=(
                    "cdxgen binary not on PATH "
                    "(install via `npm install -g @cyclonedx/cdxgen` or "
                    "use the official Docker image)"
                ),
            )

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cdx.json", delete=False,
        ) as fh:
            out_path = Path(fh.name)

        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                [
                    "cdxgen",
                    "-t", "universal",
                    "-o", str(out_path),
                    str(repo_path),
                ],
                capture_output=True,
                text=True,
                timeout=300,  # cdxgen can be slow on JS monorepos with many packages.
            )
            if proc.returncode != 0:
                raise BackendError(
                    backend_name=self.backend_name,
                    message=proc.stderr.strip()
                            or f"cdxgen exited {proc.returncode}",
                )
            document = out_path.read_text()
        finally:
            try:
                out_path.unlink()
            except OSError:
                pass

        components = _parse_cyclonedx(document)
        return SbomResult(
            components=components,
            sbom_format="cyclonedx-json",
            raw_document=document,
            backend_name=self.backend_name,
        )


def _parse_cyclonedx(document: str) -> list[SbomComponent]:
    """Extract SbomComponent objects from a CycloneDX 1.6 JSON document.

    Same parser shape used by the Syft backend — both tools emit
    CycloneDX, so the parsing is provider-agnostic. Defensive against
    missing optional fields (`purl`, `licenses`).
    """
    text = document.strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as cause:
        raise BackendError(
            backend_name="cdxgen",
            message=f"could not parse cdxgen CycloneDX output: {cause}",
        ) from cause

    components: list[SbomComponent] = []
    for c in parsed.get("components", []):
        components.append(SbomComponent(
            name=c.get("name", ""),
            version=c.get("version", ""),
            purl=c.get("purl"),
            licenses=[
                lic.get("license", {}).get("id", "")
                for lic in c.get("licenses", []) or []
            ],
        ))
    return components
