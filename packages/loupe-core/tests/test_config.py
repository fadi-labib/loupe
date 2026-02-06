from pathlib import Path
import pytest
from loupe_core.config import LoupeConfig, load_config

FIXTURES = Path(__file__).parent / "fixtures"


def test_loads_valid_config():
    cfg = load_config(FIXTURES / "valid_config.yaml")
    assert cfg.schema_version == 1
    assert cfg.models.default == "anthropic/claude-opus-4-7"
    assert cfg.limits.per_run_max_usd == 2.50
    assert ".loupe/threats.yaml" in cfg.agent_writable_paths
    assert cfg.lenses["threatlens"].enabled is True
    assert cfg.lenses["threatlens"].minimum_relevance == 0.3


def test_missing_config_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "does_not_exist.yaml")


def test_invalid_relevance_threshold_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("schema_version: 1\nlenses:\n  threatlens:\n    enabled: true\n    minimum_relevance: 1.5\n")
    with pytest.raises(Exception):  # pydantic ValidationError
        load_config(bad)
