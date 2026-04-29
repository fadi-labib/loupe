"""D-23 — value object for soft capability failures.

`CapabilityDegradation` records that a preferred capability could not
be made available during bootstrap, but the lens that needed it was
allowed to continue with the slot set to `None`. The bootstrap pass
returns a list of these; the CLI surfaces them to the operator and
the run-record writer persists them so the degradation is auditor-
visible without breaking the run.

`DegradationKind` enumerates the four ways a capability can fail to
materialise: unconfigured (operator did not wire any backend),
backend_error (configured backend crashed at runtime), not_found
(named backend isn't registered), entry_point_malformed (plugin
packaging bug).

Hard-failure equivalents live in `errors.py` and propagate as
exceptions (`RequiredCapabilityUnavailable`) rather than degradation
records.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

DegradationKind = Literal[
    "unconfigured",
    "backend_error",
    "not_found",
    "entry_point_malformed",
]


class CapabilityDegradation(BaseModel):
    lens_name: str
    capability: str
    kind: DegradationKind
    detail: str
