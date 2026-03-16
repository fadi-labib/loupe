from __future__ import annotations

from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, Field, model_validator
from ruamel.yaml import YAML

_yaml = YAML()

CompositionModeName = Literal["single", "fallback", "union", "consensus", "pipeline"]

_NO_MULTI_BACKEND_MERGE: frozenset[str] = frozenset({"sbom"})
"""Capabilities whose result types have no findings-list to merge.

SBOM results are CycloneDXDocument-shaped — there is no `findings` list
to dedupe or vote on. Multi-backend merging is therefore meaningless
for SBOM. Operators must pick `single` or `fallback`.
"""


class LensModelConfig(BaseModel):
    """Per-lens model selection. Optional override of `ModelsConfig.default`."""

    primary: str = Field(description="Primary `provider:model` identifier for this lens.")
    fallback: str | None = Field(default=None, description="Fallback `provider:model` if `primary` fails.")
    cheap_for: list[str] = Field(
        default_factory=list,
        description="Task names that should use `cheap_model` instead of `primary`.",
    )
    cheap_model: str | None = Field(
        default=None,
        description="Cheaper `provider:model` for non-critical sub-tasks listed in `cheap_for`.",
    )


class ModelsConfig(BaseModel):
    """Project-wide LLM selection. Identifiers use PydanticAI's `provider:model` form."""

    default: str = Field(description="Default `provider:model` (e.g., `anthropic:claude-opus-4-7`).")
    threatlens: LensModelConfig | None = Field(
        default=None, description="Per-lens override for ThreatLens; falls back to `default`.",
    )


class LimitsConfig(BaseModel):
    """Hard cost and step caps. A run that would exceed any of these stops cleanly."""

    per_run_max_usd: float = Field(
        gt=0, description="Maximum estimated cost per run, in USD. Must be > 0.",
    )
    per_run_max_tokens_in: int = Field(
        gt=0, description="Maximum input-token budget per run. Must be > 0.",
    )
    per_run_max_steps: int = Field(
        gt=0, description="Maximum number of LLM steps per run. Must be > 0.",
    )


class CIConfig(BaseModel):
    """Gate behaviour for the GitHub Action and `loupe ci`."""

    fail_on: list[str] = Field(
        default_factory=list,
        description="Severities that fail the build (exit 1). Bare strings: `critical`, `high`, `medium`, `low`. Empty = report-only.",
    )
    warn_on: list[str] = Field(
        default_factory=list,
        description="Severities that warn but do not fail. Surfaced in the PR comment.",
    )
    ignore_paths: list[str] = Field(
        default_factory=list,
        description="Glob patterns the lenses skip when computing relevance.",
    )


class LensActivation(BaseModel):
    """Operator's opt-in for one installed lens."""

    enabled: bool = Field(
        default=True, description="Run this lens? `false` skips it regardless of relevance.",
    )
    minimum_relevance: float = Field(
        ge=0.0, le=1.0, default=0.3,
        description="Skip the lens when `is_relevant(ctx).score` is below this threshold.",
    )


class CapabilityActivation(BaseModel):
    """D-18 — operator's selection of backends and composition mode per capability.

    `consensus_threshold` is required when ``mode == "consensus"`` and must
    not exceed ``len(backends)``. All other modes ignore the field.
    """

    mode: CompositionModeName = Field(
        default="single",
        description="How to combine backends: `single`, `fallback`, `union`, `consensus`, `pipeline`.",
    )
    backends: list[str] = Field(
        min_length=1,
        description="Backend names in the desired order. Must be non-empty.",
    )
    consensus_threshold: int | None = Field(
        default=None, ge=1,
        description="Required when `mode == 'consensus'`. Must be ≥1 and ≤ `len(backends)`.",
    )

    @model_validator(mode="after")
    def _validate_consensus(self) -> Self:
        if self.mode == "consensus":
            if self.consensus_threshold is None:
                raise ValueError(
                    "consensus_threshold is required when mode='consensus'"
                )
            if self.consensus_threshold > len(self.backends):
                raise ValueError(
                    f"consensus_threshold={self.consensus_threshold} exceeds "
                    f"len(backends)={len(self.backends)}"
                )
        return self


class LoupeConfig(BaseModel):
    """Parsed and validated `.loupe/config.yaml`.

    Authoritative shape for the operator-facing configuration file. Every field
    below carries its description from `Field(description=…)`; the rendered
    Markdown reference at `docs/reference/config.md` reuses these descriptions
    via `mkdocstrings`, so there is no second source of truth to drift.
    """

    schema_version: int = Field(
        default=1, description="Migration marker. v1 today; bumped on a breaking schema change.",
    )
    models: ModelsConfig = Field(
        default=ModelsConfig(default="anthropic:claude-opus-4-7"),
        description="LLM provider/model selection, per lens and overall.",
    )
    limits: LimitsConfig = Field(
        default=LimitsConfig(
            per_run_max_usd=2.5, per_run_max_tokens_in=500_000, per_run_max_steps=30,
        ),
        description="Hard cost and step caps for a single run.",
    )
    ci: CIConfig = Field(
        default=CIConfig(), description="Gate behaviour for CI (severity → fail/warn).",
    )
    agent_writable_paths: list[str] = Field(
        default_factory=list,
        description="Layer 1 allow-list: glob patterns the agent's `write_agent_artifact` tool may write to.",
    )
    lenses: dict[str, LensActivation] = Field(
        default_factory=dict,
        description="Per-lens activation (by lens name). Unknown names are silently ignored.",
    )
    capabilities: dict[str, CapabilityActivation] = Field(
        default_factory=dict,
        description="Per-capability backend selection and composition mode (D-18).",
    )

    @model_validator(mode="after")
    def _validate_composition_compatibility(self) -> Self:
        for cap_name, activation in self.capabilities.items():
            if cap_name in _NO_MULTI_BACKEND_MERGE and activation.mode in ("union", "consensus"):
                raise ValueError(
                    f"capability {cap_name!r}: mode {activation.mode!r} not supported "
                    f"(no merge semantics for {cap_name} results). Use 'single' or 'fallback'."
                )
        return self


def load_config(path: Path) -> LoupeConfig:
    if not path.exists():
        raise FileNotFoundError(f"config not found: {path}")
    with path.open("r") as f:
        data = _yaml.load(f) or {}
    return LoupeConfig.model_validate(data)
