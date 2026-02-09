from __future__ import annotations
from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field
from loupe_core.artifacts.knowledge import KnowledgeGraph
from loupe_core.artifacts.context import ProjectContext


class CodeDiff(BaseModel):
    base_sha: str
    head_sha: str
    changed_paths: list[str]
    added_lines: int
    removed_lines: int
    raw_unified: str


class SBOMDelta(BaseModel):
    before: dict[str, str] = Field(default_factory=dict)
    after: dict[str, str] = Field(default_factory=dict)
    added_packages: list[str] = Field(default_factory=list)
    removed_packages: list[str] = Field(default_factory=list)
    upgraded_packages: list[tuple[str, str, str]] = Field(default_factory=list)


class RelevanceScore(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    reason: str


class LensRunPlan(BaseModel):
    lens_name: str
    relevance: RelevanceScore
    depends_on: list[str] = Field(default_factory=list)
    sub_prompt: str = ""


class Fact(BaseModel):
    id: str
    posted_by: str
    subject: str
    predicate: str
    value: Any
    confidence: Literal["high", "medium", "low"]
    rationale: str
    timestamp: datetime


class PendingDecision(BaseModel):
    id: str
    proposed_by: str
    summary: str
    details_path: str


class ProposedPatch(BaseModel):
    target: str
    location: str
    rationale: str


class RunContext(BaseModel):
    # Immutable for the run
    run_id: str
    mode: Literal["ci", "interactive"]
    started_at: datetime
    user_intent: str
    diff: CodeDiff | None
    sbom_delta: SBOMDelta | None
    project: ProjectContext | None
    plan: list[LensRunPlan] = Field(default_factory=list)
    knowledge: KnowledgeGraph | None

    # Mutable blackboard
    findings: dict[str, dict[str, Any]] = Field(default_factory=dict)
    facts: list[Fact] = Field(default_factory=list)
    pending_decisions: list[PendingDecision] = Field(default_factory=list)
    proposed_patches: list[ProposedPatch] = Field(default_factory=list)

    def record_finding(self, lens: str, key: str, value: Any) -> None:
        self.findings.setdefault(lens, {})[key] = value

    def lookup(self, lens: str, key: str, default: Any = None) -> Any:
        return self.findings.get(lens, {}).get(key, default)

    def post_fact(self, fact: Fact) -> None:
        self.facts.append(fact)

    @classmethod
    def bootstrap(cls, inputs: "BootstrapInputs") -> "RunContext":
        # Local import avoids a circular dependency (diff.py imports CodeDiff).
        from loupe_core.diff import parse_unified_diff

        project = ProjectContext.from_markdown(inputs.loupe_dir / "context.md")
        knowledge = KnowledgeGraph.load_or_empty(inputs.loupe_dir / "knowledge.yaml")
        diff = (
            parse_unified_diff(
                inputs.unified_diff,
                base_sha=inputs.base_sha or "",
                head_sha=inputs.head_sha or "",
            )
            if inputs.unified_diff
            else None
        )
        return cls(
            run_id=inputs.run_id,
            mode=inputs.mode,
            started_at=inputs.started_at,
            user_intent=inputs.user_intent,
            diff=diff,
            sbom_delta=inputs.sbom_delta,
            project=project,
            plan=[],
            knowledge=knowledge,
        )


class BootstrapInputs(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    run_id: str
    mode: Literal["ci", "interactive"]
    started_at: datetime
    user_intent: str
    loupe_dir: Path
    unified_diff: str = ""
    base_sha: str | None = None
    head_sha: str | None = None
    sbom_delta: SBOMDelta | None = None
