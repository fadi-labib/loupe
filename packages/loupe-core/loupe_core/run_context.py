from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from loupe_core.artifacts.context import ProjectContext
from loupe_core.artifacts.knowledge import KnowledgeGraph
from loupe_core.capabilities.protocols import (
    CveResult,
    SbomResult,
    SecretDetectionResult,
    StaticAnalysisResult,
)
from loupe_core.diff import CodeDiff, parse_unified_diff


class UpgradedPackage(BaseModel):
    """A single package whose version changed between two SBOMs.

    Positional tuples (name, before, after) are ambiguous at the call site;
    the named-field model removes the risk of swapping `before` and `after`.
    """

    name: str = Field(min_length=1)
    before: str = Field(min_length=1)
    after: str = Field(min_length=1)


class SBOMDelta(BaseModel):
    before: dict[str, str] = Field(default_factory=dict)
    after: dict[str, str] = Field(default_factory=dict)
    added_packages: list[str] = Field(default_factory=list)
    removed_packages: list[str] = Field(default_factory=list)
    upgraded_packages: list[UpgradedPackage] = Field(default_factory=list)


class RelevanceScore(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    reason: str


class LensRunPlan(BaseModel):
    lens_name: str
    relevance: RelevanceScore
    depends_on: list[str] = Field(default_factory=list)
    sub_prompt: str = ""


class Finding(BaseModel):
    """A lens-emitted blackboard entry with provenance.

    `posted_by` and `timestamp` mirror the provenance fields on `Fact` so
    the run-record + gate logic can audit who wrote what and when. The
    actual payload is intentionally typed as `dict[str, Any]` because
    lenses emit heterogeneous shapes (threats, metrics, error records,
    arbitrary key/value blobs) and we don't want to lose information at
    the boundary; downstream readers can validate against their own
    schemas.
    """

    posted_by: str = Field(min_length=1)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    payload: dict[str, Any] = Field(default_factory=dict)


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


class LensUsage(BaseModel):
    """Per-lens token / cost record captured after the agent run completes.

    Lenses record one entry per invocation. The coordinator and the
    run-record writer aggregate these across lenses to populate the
    workspace-level totals in `RunRecord` (models_used, total_tokens_in,
    total_tokens_out, cost_usd_estimate, cache_hit_rate).

    `cache_read_tokens` are counted SEPARATELY from `input_tokens`
    because Anthropic prompt caching charges them at ~10% — the
    cache_hit_rate metric exists precisely to surface the discount.
    """

    model_id: str
    input_tokens: int = 0           # paid at full input rate
    output_tokens: int = 0          # paid at full output rate
    cache_read_tokens: int = 0      # paid at ~10% input rate (cache hits)
    cache_write_tokens: int = 0     # paid at ~125% input rate (writing to cache)
    cost_usd_estimate: float = 0.0  # populated from a pricing table on record


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
    # D-15: scope of analysis. "diff" is the default and filters lenses by
    # is_relevant() score; "full" runs every enabled lens against the whole
    # repo; "scoped" runs every enabled lens against scope_paths only.
    scope: Literal["diff", "full", "scoped"] = "diff"
    scope_paths: list[str] = Field(default_factory=list)

    # D-18: typed capability results, populated once before lenses run
    # so every lens reads the same cached output (VALUES §4).
    sbom: SbomResult | None = None
    cve_findings: CveResult | None = None
    secrets: SecretDetectionResult | None = None
    static_findings: StaticAnalysisResult | None = None

    # Mutable blackboard. Each finding carries `posted_by` + `timestamp`
    # provenance alongside its payload (see `Finding`). Readers go through
    # `lookup()` which returns the payload dict directly for backward
    # compatibility with existing call sites; iterate over
    # `ctx.findings[lens].items()` (key, Finding) when you need provenance.
    findings: dict[str, dict[str, Finding]] = Field(default_factory=dict)
    facts: list[Fact] = Field(default_factory=list)
    pending_decisions: list[PendingDecision] = Field(default_factory=list)
    proposed_patches: list[ProposedPatch] = Field(default_factory=list)
    # Per-lens token usage, populated after each lens's agent run completes.
    # Aggregated into RunRecord by ci_cmd._write_run_record so the cost-
    # discipline principle (§8) has on-disk evidence per run, not just in
    # the test cassette.
    lens_usage: dict[str, LensUsage] = Field(default_factory=dict)

    def record_finding(self, lens: str, key: str, value: Any) -> None:
        """Record a finding from `lens` under `key` with provenance.

        `value` may be a dict (the common case — preserved as-is on the
        Finding's `payload`), or any scalar / list (wrapped as
        `{"value": <scalar>}` so the payload shape stays uniform). Readers
        that go through `lookup()` get the original `value` back.
        """
        if isinstance(value, dict):
            payload: dict[str, Any] = value
        else:
            payload = {"value": value}
        finding = Finding(posted_by=lens, payload=payload)
        self.findings.setdefault(lens, {})[key] = finding

    def lookup(self, lens: str, key: str, default: Any = None) -> Any:
        """Return the payload originally passed to `record_finding`.

        Scalars that were wrapped in `{"value": ...}` on write are
        unwrapped here so the caller sees what they recorded.
        """
        finding = self.findings.get(lens, {}).get(key)
        if finding is None:
            return default
        payload = finding.payload
        if set(payload.keys()) == {"value"}:
            return payload["value"]
        return payload

    def post_fact(self, fact: Fact) -> None:
        self.facts.append(fact)

    @classmethod
    def bootstrap(cls, inputs: BootstrapInputs) -> RunContext:
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
            scope=inputs.scope,
            scope_paths=list(inputs.scope_paths),
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
    # D-15: defaults preserve the original diff-mode behaviour.
    scope: Literal["diff", "full", "scoped"] = "diff"
    scope_paths: list[str] = []
