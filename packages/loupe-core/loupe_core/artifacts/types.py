"""Common enum types used across Loupe artifacts."""
from __future__ import annotations
from enum import Enum
from functools import total_ordering


@total_ordering
class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def _order(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._order < other._order


class ThreatStatus(str, Enum):
    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    MITIGATED = "mitigated"
    ACCEPTED_RISK = "accepted_risk"
    REJECTED = "rejected"


class MitigationStatus(str, Enum):
    PROPOSED = "proposed"
    PLANNED = "planned"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"
    RETIRED = "retired"


class StrideCategory(str, Enum):
    SPOOFING = "S"
    TAMPERING = "T"
    REPUDIATION = "R"
    INFORMATION_DISCLOSURE = "I"
    DENIAL_OF_SERVICE = "D"
    ELEVATION_OF_PRIVILEGE = "E"


class VexStatus(str, Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"
