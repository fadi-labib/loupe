"""Atomic write helpers shared across artefact files.

Every Loupe artefact write must be atomic so a crash mid-write cannot
strand the audit trail with a half-written YAML file. Readers (humans
and CI) should only ever see complete files.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML


def atomic_write_yaml(path: Path, payload: Any, *, yaml: YAML) -> None:
    """Write ``payload`` to ``path`` atomically (tmp file + os.replace).

    Parameters
    ----------
    path:
        Destination file. Parent directories are created if missing.
    payload:
        Already-serialisable structure (typically ``BaseModel.model_dump``).
    yaml:
        Configured ``ruamel.yaml.YAML`` instance so each artefact keeps its
        own indent / flow-style settings.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w") as f:
        yaml.dump(payload, f)
    os.replace(tmp, path)
