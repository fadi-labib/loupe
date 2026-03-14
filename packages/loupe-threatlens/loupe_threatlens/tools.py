"""ThreatLens tool implementations.

These functions are the actual implementations that the PydanticAI agent's
tool decorators wrap. They are kept separate from the agent definition so
they can be unit-tested without an LLM call (and so the agent module stays
focused on prompt + tool registration).

The functions take `ctx: RunContext`, `boundary: PathBoundary`, and
`loupe_dir: Path` as parameters rather than relying on globals — this mirrors
PydanticAI's `deps` pattern and keeps the tools testable in isolation.

Two layers of write helpers ship here:

- `propose_threat_impl` / `propose_mitigation_impl` — the full "agent-
  driven" path that records the finding on RunContext for downstream
  lenses to read. Used by the in-process PydanticAI agent.
- `write_threat_directly` / `write_mitigation_directly` — the same
  Layer-1-enforced disk write, minus the RunContext blackboard step.
  Used by the MCP write tools where there is no per-call RunContext to
  thread through. Same Layer 1 guarantees apply via write_agent_artifact.
"""
from __future__ import annotations

import io
from datetime import date
from pathlib import Path
from typing import Literal

from loupe_core.artifacts.mitigation import (
    Evidence,
    Mitigation,
    MitigationsFile,
)
from loupe_core.artifacts.threat import Threat, ThreatsFile
from loupe_core.artifacts.types import (
    MitigationStatus,
    Severity,
    StrideCategory,
    ThreatStatus,
)
from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.run_context import RunContext
from loupe_core.tools import write_agent_artifact
from pydantic import BaseModel, Field
from ruamel.yaml import YAML

_yaml = YAML()
_yaml.default_flow_style = False
_yaml.indent(mapping=2, sequence=4, offset=2)


class ProposeThreatInput(BaseModel):
    """Schema the LLM must produce when calling the `propose_threat` tool.

    These constraints become the JSON Schema visible to the model, so the
    model is guided toward valid output before any post-validation.
    """
    element_id: str = Field(
        description="ID of the architectural element this threat targets (e.g., E-001)",
    )
    stride_category: Literal["S", "T", "R", "I", "D", "E"] = Field(
        description="STRIDE category: S=Spoofing, T=Tampering, R=Repudiation, "
                    "I=Information disclosure, D=Denial of service, E=Elevation of privilege",
    )
    title: str = Field(
        min_length=1, max_length=200,
        description="Short threat title (<=200 chars).",
    )
    description: str = Field(
        min_length=1,
        description="Full threat description: what the threat is, who could exercise it.",
    )
    severity: Literal["low", "medium", "high", "critical"] = Field(
        description=(
            "Severity relative to the assets in context.md; "
            "do not use generic web-app heuristics."
        ),
    )
    rationale: str = Field(
        description="Justification for the chosen severity, citing assets from context.md.",
    )
    cwe_refs: list[str] = Field(
        default_factory=list,
        description='Optional CWE identifiers (e.g., ["CWE-287"]).',
    )
    mitigation_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Optional IDs of existing mitigations in mitigations.yaml "
            "that address this threat."
        ),
    )


class ProposeThreatResult(BaseModel):
    threat_id: str
    status: Literal["written"]


def propose_threat_impl(
    ctx: RunContext,
    boundary: PathBoundary,
    loupe_dir: Path,
    input: ProposeThreatInput,
    *,
    model_id: str,
) -> ProposeThreatResult:
    """Add a new threat to threats.yaml.

    Reads the existing file (if any), assigns the next sequential ID,
    appends the new threat, writes back through the Layer-1 path boundary,
    and records the finding in the RunContext blackboard.
    """
    threats_path = loupe_dir / "threats.yaml"
    file = ThreatsFile.load(threats_path) if threats_path.exists() else ThreatsFile()

    next_id = _next_threat_id([t.id for t in file.threats])
    threat = Threat(
        id=next_id,
        element_id=input.element_id,
        stride_category=StrideCategory(input.stride_category),
        title=input.title,
        description=input.description,
        severity=Severity(input.severity),
        status=ThreatStatus.PROPOSED,
        mitigation_ids=list(input.mitigation_ids),
        cwe_refs=list(input.cwe_refs),
        introduced_in_pr=None,
        last_reviewed=date.today(),
        review_due=None,
        rationale=input.rationale,
        proposed_by=f"threatlens/{model_id}",
    )
    file.threats.append(threat)

    # Serialise via ruamel and write through Layer 1 (path-boundary-checked).
    buf = io.StringIO()
    _yaml.dump(file.model_dump(mode="json"), buf)
    write_agent_artifact(boundary, threats_path, buf.getvalue())

    # Record in blackboard so later lenses / coordinator can see what was added.
    ctx.record_finding("threatlens", f"threat:{next_id}", threat.model_dump(mode="json"))

    return ProposeThreatResult(threat_id=next_id, status="written")


def _next_threat_id(existing: list[str]) -> str:
    """Return the next T-NNN id given the IDs already present in threats.yaml."""
    nums = [int(t.split("-")[1]) for t in existing if t.startswith("T-")]
    return f"T-{max(nums, default=0) + 1:03d}"


def _next_mitigation_id(existing: list[str]) -> str:
    """Return the next M-NNN id given the IDs already present in mitigations.yaml."""
    nums = [int(m.split("-")[1]) for m in existing if m.startswith("M-")]
    return f"M-{max(nums, default=0) + 1:03d}"


# ---------------------------------------------------------------------------
# Direct-write helpers (MCP / external-callers; no RunContext involvement)
# ---------------------------------------------------------------------------


def write_threat_directly(
    loupe_dir: Path,
    boundary: PathBoundary,
    input: ProposeThreatInput,
    *,
    proposed_by: str,
) -> str:
    """Append a new threat to threats.yaml without touching RunContext.

    Used by the MCP write tools and any other external caller that
    doesn't have a per-call RunContext. Same Layer 1 guarantees as
    `propose_threat_impl` — the write still goes through
    `write_agent_artifact` so a non-writable path raises BoundaryViolation.

    Returns the assigned T-NNN id. Caller is responsible for any
    blackboard / record-finding work they care about.
    """
    threats_path = loupe_dir / "threats.yaml"
    file = ThreatsFile.load(threats_path) if threats_path.exists() else ThreatsFile()
    next_id = _next_threat_id([t.id for t in file.threats])
    threat = Threat(
        id=next_id,
        element_id=input.element_id,
        stride_category=StrideCategory(input.stride_category),
        title=input.title,
        description=input.description,
        severity=Severity(input.severity),
        status=ThreatStatus.PROPOSED,
        mitigation_ids=list(input.mitigation_ids),
        cwe_refs=list(input.cwe_refs),
        introduced_in_pr=None,
        last_reviewed=date.today(),
        review_due=None,
        rationale=input.rationale,
        proposed_by=proposed_by,
    )
    file.threats.append(threat)
    buf = io.StringIO()
    _yaml.dump(file.model_dump(mode="json"), buf)
    write_agent_artifact(boundary, threats_path, buf.getvalue())
    return next_id


class ProposeMitigationInput(BaseModel):
    """Schema the MCP write tool accepts for a new mitigation."""

    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1)
    threats_addressed: list[str] = Field(
        default_factory=list,
        description="Threat IDs (T-NNN) this mitigation closes.",
    )
    status: Literal["proposed", "planned", "implemented", "verified", "retired"] = (
        Field(default="proposed")
    )
    evidence_kind: Literal["code", "doc", "test", "config", "external"] | None = (
        Field(default=None, description="Optional pointer-kind for a single evidence entry.")
    )
    evidence_location: str | None = Field(
        default=None,
        description="Optional pointer location (path/URL) for a single evidence entry.",
    )


def write_mitigation_directly(
    loupe_dir: Path,
    boundary: PathBoundary,
    input: ProposeMitigationInput,
) -> str:
    """Append a new mitigation to mitigations.yaml without RunContext.

    Same Layer 1 enforcement as write_threat_directly. Optional single
    evidence pointer is captured when both kind and location are
    provided; richer evidence editing happens via human review of the
    file directly (mitigations.yaml is human-readable YAML).

    Returns the assigned M-NNN id.
    """
    mit_path = loupe_dir / "mitigations.yaml"
    file = MitigationsFile.load(mit_path) if mit_path.exists() else MitigationsFile()
    next_id = _next_mitigation_id([m.id for m in file.mitigations])

    evidence: list[Evidence] = []
    if input.evidence_kind and input.evidence_location:
        evidence.append(Evidence(
            kind=input.evidence_kind,
            location=input.evidence_location,
        ))

    mitigation = Mitigation(
        id=next_id,
        title=input.title,
        description=input.description,
        threats_addressed=list(input.threats_addressed),
        status=MitigationStatus(input.status),
        evidence=evidence,
    )
    file.mitigations.append(mitigation)
    buf = io.StringIO()
    _yaml.dump(file.model_dump(mode="json"), buf)
    write_agent_artifact(boundary, mit_path, buf.getvalue())
    return next_id
