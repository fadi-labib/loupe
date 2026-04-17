"""Capability protocol layer (D-18).

Tool-vendor-agnostic Protocols for SBOM generation, CVE scanning,
secret detection, and static analysis. Backends register via the
``loupe.capabilities`` entry-point group; the registry resolves a
capability name + configured backend list into a callable that yields
a typed result on the RunContext blackboard.

See ``docs/CAPABILITIES.md`` and DESIGN-DECISIONS.md (D-18) for rationale.
"""

from loupe_core.capabilities.errors import (
    BackendError,
    CapabilityError,
    CapabilityNotFoundError,
    EntryPointMalformedError,
    NoBackendsConfiguredError,
)
from loupe_core.capabilities.protocols import (
    CveCapability,
    CveFinding,
    CveResult,
    SbomCapability,
    SbomComponent,
    SbomResult,
    SecretDetectionCapability,
    SecretDetectionResult,
    SecretFinding,
    StaticAnalysisCapability,
    StaticAnalysisResult,
    StaticFinding,
)

__all__ = [
    "BackendError",
    "CapabilityError",
    "CapabilityNotFoundError",
    "EntryPointMalformedError",
    "CveCapability",
    "CveFinding",
    "CveResult",
    "NoBackendsConfiguredError",
    "SbomCapability",
    "SbomComponent",
    "SbomResult",
    "SecretDetectionCapability",
    "SecretDetectionResult",
    "SecretFinding",
    "StaticAnalysisCapability",
    "StaticAnalysisResult",
    "StaticFinding",
]
