from __future__ import annotations

from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, Field, model_validator
from ruamel.yaml import YAML

_yaml = YAML()

CompositionModeName = Literal["single", "fallback", "union", "consensus", "pipeline"]


class LensModelConfig(BaseModel):
    primary: str
    fallback: str | None = None
    cheap_for: list[str] = Field(default_factory=list)
    cheap_model: str | None = None


class ModelsConfig(BaseModel):
    default: str
    threatlens: LensModelConfig | None = None


class LimitsConfig(BaseModel):
    per_run_max_usd: float = Field(gt=0)
    per_run_max_tokens_in: int = Field(gt=0)
    per_run_max_steps: int = Field(gt=0)


class CIConfig(BaseModel):
    fail_on: list[str] = Field(default_factory=list)
    warn_on: list[str] = Field(default_factory=list)
    ignore_paths: list[str] = Field(default_factory=list)


class LensActivation(BaseModel):
    enabled: bool = True
    minimum_relevance: float = Field(ge=0.0, le=1.0, default=0.3)


class CapabilityActivation(BaseModel):
    """D-18 — operator's selection of backends and composition mode per capability.

    `consensus_threshold` is required when ``mode == "consensus"`` and must
    not exceed ``len(backends)``. All other modes ignore the field.
    """

    mode: CompositionModeName = "single"
    backends: list[str] = Field(min_length=1)
    consensus_threshold: int | None = Field(default=None, ge=1)

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
    schema_version: int = 1
    models: ModelsConfig = ModelsConfig(default="anthropic/claude-opus-4-7")
    limits: LimitsConfig = LimitsConfig(
        per_run_max_usd=2.5, per_run_max_tokens_in=500_000, per_run_max_steps=30,
    )
    ci: CIConfig = CIConfig()
    agent_writable_paths: list[str] = Field(default_factory=list)
    lenses: dict[str, LensActivation] = Field(default_factory=dict)
    capabilities: dict[str, CapabilityActivation] = Field(default_factory=dict)


def load_config(path: Path) -> LoupeConfig:
    if not path.exists():
        raise FileNotFoundError(f"config not found: {path}")
    with path.open("r") as f:
        data = _yaml.load(f) or {}
    return LoupeConfig.model_validate(data)
