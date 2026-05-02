from pathlib import Path

import pytest
from loupe_core.config import LoupeConfig, load_config
from pydantic import ValidationError

FIXTURES = Path(__file__).parent / "fixtures"


def test_loads_valid_config():
    cfg = load_config(FIXTURES / "valid_config.yaml")
    assert cfg.schema_version == 1
    assert cfg.models.default == "anthropic:claude-opus-4-7"
    # D-24 / Resolved 3: per_run_max_usd is per-mode. Scalar 2.50 in the
    # fixture means both ceilings are 2.50 (back-compat path).
    assert cfg.limits.per_run_max_usd.ci == 2.50
    assert cfg.limits.per_run_max_usd.scan == 2.50
    assert ".loupe/threats.yaml" in cfg.agent_writable_paths
    assert cfg.lenses["threatlens"].enabled is True
    assert cfg.lenses["threatlens"].minimum_relevance == 0.3


def test_per_run_max_usd_scalar_back_compat(tmp_path):
    """D-24 Resolved 3: a scalar `per_run_max_usd: 2.50` is treated as
    both ceilings simultaneously (existing config files still load)."""
    cfg_path = tmp_path / "scalar.yaml"
    cfg_path.write_text(
        "schema_version: 1\n"
        "models:\n  default: anthropic:claude-opus-4-7\n"
        "limits:\n"
        "  per_run_max_usd: 1.75\n"
        "  per_run_max_tokens_in: 100000\n"
        "  per_run_max_steps: 5\n"
    )
    cfg = load_config(cfg_path)
    assert cfg.limits.per_run_max_usd.ci == 1.75
    assert cfg.limits.per_run_max_usd.scan == 1.75


def test_per_run_max_usd_nested_form(tmp_path):
    """D-24 Resolved 3: explicit nested form with different defaults for
    ci and scan. Scan-mode bills more because scoped reads cost more."""
    cfg_path = tmp_path / "nested.yaml"
    cfg_path.write_text(
        "schema_version: 1\n"
        "models:\n  default: anthropic:claude-opus-4-7\n"
        "limits:\n"
        "  per_run_max_usd:\n"
        "    ci: 2.50\n"
        "    scan: 5.00\n"
        "  per_run_max_tokens_in: 100000\n"
        "  per_run_max_steps: 5\n"
    )
    cfg = load_config(cfg_path)
    assert cfg.limits.per_run_max_usd.ci == 2.50
    assert cfg.limits.per_run_max_usd.scan == 5.00


def test_per_run_max_usd_partial_nested_form_rejected(tmp_path):
    """Both `ci` and `scan` are required when using the nested form —
    omitting one is a config-error, not a "default to scalar fallback".
    Keeps the semantics explicit."""
    cfg_path = tmp_path / "partial.yaml"
    cfg_path.write_text(
        "schema_version: 1\n"
        "models:\n  default: anthropic:claude-opus-4-7\n"
        "limits:\n"
        "  per_run_max_usd:\n"
        "    ci: 2.50\n"
        "  per_run_max_tokens_in: 100000\n"
        "  per_run_max_steps: 5\n"
    )
    with pytest.raises(ValidationError):
        load_config(cfg_path)


def test_missing_config_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "does_not_exist.yaml")


def test_invalid_relevance_threshold_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "schema_version: 1\nlenses:\n  threatlens:\n    enabled: true\n    minimum_relevance: 1.5\n"
    )
    with pytest.raises(ValidationError):
        load_config(bad)


def test_sbom_rejects_union_mode():
    with pytest.raises(ValueError, match="union.*sbom|sbom.*union"):
        LoupeConfig.model_validate(
            {
                "models": {"default": "anthropic:claude-opus-4-7"},
                "capabilities": {"sbom": {"mode": "union", "backends": ["syft", "cdxgen"]}},
            }
        )


def test_sbom_rejects_consensus_mode():
    with pytest.raises(ValueError, match="consensus.*sbom|sbom.*consensus"):
        LoupeConfig.model_validate(
            {
                "models": {"default": "anthropic:claude-opus-4-7"},
                "capabilities": {
                    "sbom": {
                        "mode": "consensus",
                        "backends": ["syft", "cdxgen"],
                        "consensus_threshold": 2,
                    },
                },
            }
        )


def test_sbom_accepts_single_mode():
    cfg = LoupeConfig.model_validate(
        {
            "models": {"default": "anthropic:claude-opus-4-7"},
            "capabilities": {"sbom": {"mode": "single", "backends": ["syft"]}},
        }
    )
    assert cfg.capabilities["sbom"].mode == "single"


def test_sbom_accepts_fallback_mode():
    cfg = LoupeConfig.model_validate(
        {
            "models": {"default": "anthropic:claude-opus-4-7"},
            "capabilities": {"sbom": {"mode": "fallback", "backends": ["syft", "cdxgen"]}},
        }
    )
    assert cfg.capabilities["sbom"].mode == "fallback"


def test_unknown_capability_name_rejected_at_validation():
    with pytest.raises(ValueError, match="unknown capability.*'imaginary'"):
        LoupeConfig.model_validate(
            {
                "models": {"default": "anthropic:claude-opus-4-7"},
                "capabilities": {"imaginary": {"mode": "single", "backends": ["whatever"]}},
            }
        )


def test_known_capabilities_accepted():
    for cap in ["sbom", "cve", "secret_detect", "static_analysis"]:
        cfg = LoupeConfig.model_validate(
            {
                "models": {"default": "anthropic:claude-opus-4-7"},
                "capabilities": {cap: {"mode": "single", "backends": ["any"]}},
            }
        )
        assert cap in cfg.capabilities


def test_cheap_for_unknown_task_rejected():
    """A typo in `cheap_for` would silently disable cheap-routing.
    Fail fast at load time with a message that lists the known names."""
    with pytest.raises(ValidationError) as exc_info:
        LoupeConfig.model_validate(
            {
                "models": {
                    "default": "anthropic:claude-opus-4-7",
                    "threatlens": {
                        "primary": "anthropic:claude-opus-4-7",
                        "cheap_for": ["doc_polishh"],  # typo
                        "cheap_model": "anthropic:claude-haiku-4-5",
                    },
                },
            }
        )
    assert "unknown task name" in str(exc_info.value)


def test_cheap_for_known_task_accepted():
    cfg = LoupeConfig.model_validate(
        {
            "models": {
                "default": "anthropic:claude-opus-4-7",
                "threatlens": {
                    "primary": "anthropic:claude-opus-4-7",
                    "cheap_for": ["doc_polish", "vex_drafting"],
                    "cheap_model": "anthropic:claude-haiku-4-5",
                },
            },
        }
    )
    assert cfg.models.threatlens is not None
    assert cfg.models.threatlens.cheap_for == ["doc_polish", "vex_drafting"]
