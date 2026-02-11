from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from loupe_core.run_context import SBOMDelta


class SBOMToolError(RuntimeError):
    pass


def _run_syft(repo_path: Path) -> str:
    if shutil.which("syft") is None:
        raise SBOMToolError("syft not installed; install from https://github.com/anchore/syft")
    proc = subprocess.run(
        ["syft", str(repo_path), "-o", "cyclonedx-json"],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        raise SBOMToolError(f"syft failed: {proc.stderr}")
    return proc.stdout


def generate_sbom(*, repo_path: Path, output_path: Path) -> Path:
    output = _run_syft(repo_path)
    # Validate it parses as JSON
    json.loads(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output)
    return output_path


def diff_sboms(*, before: dict[str, Any], after: dict[str, Any]) -> SBOMDelta:
    before_map = {c["name"]: c["version"] for c in before.get("components", [])}
    after_map = {c["name"]: c["version"] for c in after.get("components", [])}
    added = [n for n in after_map if n not in before_map]
    removed = [n for n in before_map if n not in after_map]
    upgraded = [
        (n, before_map[n], after_map[n])
        for n in before_map
        if n in after_map and before_map[n] != after_map[n]
    ]
    return SBOMDelta(
        before=before_map,
        after=after_map,
        added_packages=added,
        removed_packages=removed,
        upgraded_packages=upgraded,
    )
