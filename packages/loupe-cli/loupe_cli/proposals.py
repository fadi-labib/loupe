"""`.loupe/.proposed/` lifecycle helpers for `loupe chat`.

The on-disk format is laid down by `loupe_core.tools.propose_patch`:
4-line `#`-comment header (target / rationale / run / `---` separator),
followed by the unified diff body. See tools.py:108-138.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Proposal:
    """In-memory view of one `.loupe/.proposed/<encoded>/<run-id>.patch` file."""

    target_path: str
    rationale: str
    run_id: str
    diff_body: str
    patch_file_path: Path
