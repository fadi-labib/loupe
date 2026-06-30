"""Typed schema for benchmark scenario manifests and expected-threats files.

Mirrors the schema documented in `docs/reference/evaluation.md` § Scenario
manifest schema / Expected-threats schema verbatim — this module is the
single source of truth contributors write `manifest.yaml` /
`expected-threats.yaml` against, but the YAML shape is the contract;
changing a field here without updating evaluation.md is a doc bug.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field
from ruamel.yaml import YAML

_yaml = YAML(typ="safe")

SeverityLabel = Literal["low", "medium", "high", "critical"]
StrideCategory = Literal["S", "T", "R", "I", "D", "E"]

_SEVERITY_ORDER: dict[SeverityLabel, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


class ScenarioManifest(BaseModel):
    """One scenario's `manifest.yaml` — metadata about a real historical fix."""

    cve_id: str = Field(description="CVE ID, or a synthetic MONGOOSE-... id if none was assigned.")
    published: str = Field(description="ISO date the advisory (or fix commit) was published.")
    severity_cvss_v3: float | None = Field(
        default=None, description="CVSS v3 score if a formal advisory assigned one."
    )
    severity_label: SeverityLabel
    stride_category: StrideCategory
    pre_fix_commit: str = Field(description="Upstream SHA to check out — the vulnerable state.")
    fix_commit: str = Field(description="Upstream SHA that fixed it.")
    diff_scope_paths: list[str] = Field(
        default_factory=list,
        description=(
            "When set, the orchestrator generates the scenario diff via "
            "`git diff pre_fix_commit fix_commit -- <these paths>` instead of "
            "`git show fix_commit` (the whole commit). Needed when fix_commit is a "
            "squashed commit bundling unrelated changes — scope to just the file(s) "
            "this scenario is about, so the diff Loupe sees isn't polluted by other "
            "fixes that happen to share the same commit."
        ),
    )
    expected_affected_paths: list[str] = Field(default_factory=list)
    expected_element_id: str | None = Field(
        default=None, description="Knowledge-graph element this maps to, if curated."
    )
    description_summary: str

    @classmethod
    def load(cls, path: Path) -> ScenarioManifest:
        with path.open("r") as f:
            return cls.model_validate(_yaml.load(f))


class ExpectedThreat(BaseModel):
    """One entry in `expected-threats.yaml` — what Loupe SHOULD have found."""

    title_keywords: list[str] = Field(
        description="Any one keyword matching (case-insensitive) the threat's title or "
        "description counts as a textual match."
    )
    stride_category: StrideCategory
    severity_min: SeverityLabel
    severity_max: SeverityLabel
    must_reference_paths: list[str] = Field(default_factory=list)

    def severity_in_range(self, severity: SeverityLabel) -> bool:
        return (
            _SEVERITY_ORDER[self.severity_min]
            <= _SEVERITY_ORDER[severity]
            <= _SEVERITY_ORDER[self.severity_max]
        )


class ExpectedThreatsFile(BaseModel):
    """Root of one scenario's `expected-threats.yaml`."""

    expected_threats: list[ExpectedThreat]

    @classmethod
    def load(cls, path: Path) -> ExpectedThreatsFile:
        with path.open("r") as f:
            return cls.model_validate(_yaml.load(f))
