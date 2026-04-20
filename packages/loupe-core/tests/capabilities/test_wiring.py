"""Wiring tests for §4: LensCapabilities, RunContext, LoupeConfig extensions.

These assert the *shape* of the new fields. The actual capability
invocation flow is exercised in §5 (bootstrap integration).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from loupe_core.capabilities.protocols import (
    CveFinding,
    CveResult,
    SbomComponent,
    SbomResult,
)
from loupe_core.config import CapabilityActivation, LoupeConfig
from loupe_core.lens_api import LensCapabilities
from loupe_core.run_context import RunContext


def test_lens_capabilities_carries_requires_capabilities():
    caps = LensCapabilities(
        name="threatlens",
        domain="cybersecurity",
        requires_capabilities=["sbom", "cve"],
    )
    assert caps.requires_capabilities == ["sbom", "cve"]


def test_lens_capabilities_defaults_to_empty_capability_list():
    caps = LensCapabilities(name="a", domain="d")
    assert caps.requires_capabilities == []


def test_run_context_holds_typed_capability_results():
    sbom = SbomResult(
        components=[SbomComponent(name="requests", version="2.31.0")],
        backend_name="syft",
    )
    cves = CveResult(
        findings=[
            CveFinding(
                cve_id="CVE-2024-1",
                component_name="requests",
                component_version="2.31.0",
                severity="high",
                summary="x",
            )
        ],
        backend_name="grype",
    )
    ctx = RunContext(
        run_id="r1",
        mode="ci",
        started_at=datetime.now(UTC),
        user_intent="",
        diff=None,
        sbom_delta=None,
        project=None,
        knowledge=None,
        sbom=sbom,
        cve_findings=cves,
    )
    assert ctx.sbom is not None
    assert ctx.sbom.components[0].name == "requests"
    assert ctx.cve_findings is not None
    assert ctx.cve_findings.findings[0].cve_id == "CVE-2024-1"
    # Unused capability slots default to None — lenses must check before reading.
    assert ctx.secrets is None
    assert ctx.static_findings is None


def test_loupe_config_capabilities_section_parses():
    config = LoupeConfig.model_validate(
        {
            "capabilities": {
                "sbom": {"mode": "single", "backends": ["syft"]},
                "cve": {"mode": "fallback", "backends": ["grype", "osv-scanner"]},
                "secret_detect": {
                    "mode": "union",
                    "backends": ["trufflehog", "gitleaks"],
                },
                "static_analysis": {
                    "mode": "consensus",
                    "backends": ["semgrep", "codeql"],
                    "consensus_threshold": 2,
                },
            }
        }
    )
    assert config.capabilities["sbom"].mode == "single"
    assert config.capabilities["cve"].backends == ["grype", "osv-scanner"]
    assert config.capabilities["static_analysis"].consensus_threshold == 2


def test_capability_activation_rejects_unknown_mode():
    with pytest.raises(ValueError):
        CapabilityActivation.model_validate({"mode": "magic_wand", "backends": ["x"]})


def test_consensus_threshold_required_when_mode_is_consensus():
    with pytest.raises(ValueError, match="consensus_threshold"):
        CapabilityActivation.model_validate({"mode": "consensus", "backends": ["a", "b"]})


def test_consensus_threshold_must_not_exceed_backend_count():
    with pytest.raises(ValueError, match="threshold"):
        CapabilityActivation.model_validate(
            {"mode": "consensus", "backends": ["a"], "consensus_threshold": 2}
        )


def test_capability_activation_defaults_keep_minimal_config_valid():
    # User writes just `{backends: [syft]}` — should default to mode=single.
    activation = CapabilityActivation.model_validate({"backends": ["syft"]})
    assert activation.mode == "single"
    assert activation.backends == ["syft"]
