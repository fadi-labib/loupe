from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from pathlib import Path

from loupe_core.capabilities.errors import BackendError
from loupe_core.capabilities.protocols import SbomComponent, SbomResult


class SyftSbomBackend:
    """Anchore Syft as the default SBOM generator. Emits CycloneDX 1.6 JSON."""

    name = "sbom"
    backend_name = "syft"

    async def run(self, repo_path: Path) -> SbomResult:
        if shutil.which("syft") is None:
            raise BackendError(
                backend_name=self.backend_name,
                message="syft binary not on PATH (install from https://github.com/anchore/syft)",
            )
        # Wrap the blocking subprocess.run in to_thread so the event loop
        # stays responsive — capability bootstrap may fan out multiple
        # backends concurrently via asyncio.gather.
        proc = await asyncio.to_thread(
            subprocess.run,
            ["syft", str(repo_path), "-o", "cyclonedx-json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            raise BackendError(backend_name=self.backend_name, message=proc.stderr.strip())
        document = proc.stdout
        # Validate JSON early — surfaces a clear BackendError instead of an
        # opaque JSONDecodeError from a downstream parser.
        try:
            parsed = json.loads(document)
        except json.JSONDecodeError as cause:
            raise BackendError(
                backend_name=self.backend_name,
                message=f"syft output was not valid JSON: {cause}",
            ) from cause
        components = [
            SbomComponent(
                name=c["name"],
                version=c.get("version", ""),
                purl=c.get("purl"),
                licenses=[lic.get("license", {}).get("id", "") for lic in c.get("licenses", [])],
            )
            for c in parsed.get("components", [])
        ]
        return SbomResult(
            components=components,
            sbom_format="cyclonedx-json",
            raw_document=document,
            backend_name=self.backend_name,
        )
