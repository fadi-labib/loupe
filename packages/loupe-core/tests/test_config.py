from pathlib import Path

import pytest
from loupe_core.config import LoupeConfig, load_config
from pydantic import ValidationError

FIXTURES = Path(__file__).parent / "fixtures"


def test_loads_valid_config():
    cfg = load_config(FIXTURES / "valid_config.yaml")
    assert cfg.schema_version == 1
    assert cfg.models.default == "anthropic:claude-opus-4-7"
    assert cfg.limits.per_run_max_usd == 2.50
    assert ".loupe/threats.yaml" in cfg.agent_writable_paths
    assert cfg.lenses["threatlens"].enabled is True
    assert cfg.lenses["threatlens"].minimum_relevance == 0.3


def test_missing_config_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "does_not_exist.yaml")


def test_invalid_relevance_threshold_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "schema_version: 1\n"
        "lenses:\n"
        "  threatlens:\n"
        "    enabled: true\n"
        "    minimum_relevance: 1.5\n"
    )
    with pytest.raises(ValidationError):
        load_config(bad)


def test_sbom_rejects_union_mode():
    with pytest.raises(ValueError, match="union.*sbom|sbom.*union"):
        LoupeConfig.model_validate({
            "models": {"default": "anthropic:claude-opus-4-7"},
            "capabilities": {"sbom": {"mode": "union", "backends": ["syft", "cdxgen"]}},
        })


def test_sbom_rejects_consensus_mode():
    with pytest.raises(ValueError, match="consensus.*sbom|sbom.*consensus"):
        LoupeConfig.model_validate({
            "models": {"default": "anthropic:claude-opus-4-7"},
            "capabilities": {"sbom": {"mode": "consensus", "backends": ["syft", "cdxgen"], "consensus_threshold": 2}},
        })


def test_sbom_accepts_single_mode():
    cfg = LoupeConfig.model_validate({
        "models": {"default": "anthropic:claude-opus-4-7"},
        "capabilities": {"sbom": {"mode": "single", "backends": ["syft"]}},
    })
    assert cfg.capabilities["sbom"].mode == "single"


def test_sbom_accepts_fallback_mode():
    cfg = LoupeConfig.model_validate({
        "models": {"default": "anthropic:claude-opus-4-7"},
        "capabilities": {"sbom": {"mode": "fallback", "backends": ["syft", "cdxgen"]}},
    })
    assert cfg.capabilities["sbom"].mode == "fallback"


def test_unknown_capability_name_rejected_at_validation():
    with pytest.raises(ValueError, match="unknown capability.*'imaginary'"):
        LoupeConfig.model_validate({
            "models": {"default": "anthropic:claude-opus-4-7"},
            "capabilities": {"imaginary": {"mode": "single", "backends": ["whatever"]}},
        })


def test_known_capabilities_accepted():
    for cap in ["sbom", "cve", "secret_detect", "static_analysis"]:
        cfg = LoupeConfig.model_validate({
            "models": {"default": "anthropic:claude-opus-4-7"},
            "capabilities": {cap: {"mode": "single", "backends": ["any"]}},
        })
        assert cap in cfg.capabilities
