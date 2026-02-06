from __future__ import annotations
from pathlib import Path
from pydantic import BaseModel, Field
from ruamel.yaml import YAML

_yaml = YAML()


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


class LoupeConfig(BaseModel):
    schema_version: int = 1
    models: ModelsConfig = ModelsConfig(default="anthropic/claude-opus-4-7")
    limits: LimitsConfig = LimitsConfig(per_run_max_usd=2.5, per_run_max_tokens_in=500_000, per_run_max_steps=30)
    ci: CIConfig = CIConfig()
    agent_writable_paths: list[str] = Field(default_factory=list)
    lenses: dict[str, LensActivation] = Field(default_factory=dict)


def load_config(path: Path) -> LoupeConfig:
    if not path.exists():
        raise FileNotFoundError(f"config not found: {path}")
    with path.open("r") as f:
        data = _yaml.load(f) or {}
    return LoupeConfig.model_validate(data)
