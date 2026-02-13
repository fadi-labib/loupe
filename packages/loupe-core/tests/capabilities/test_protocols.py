from __future__ import annotations

import pytest
from loupe_core.capabilities.protocols import (
    CveCapability,
    CveFinding,
    CveResult,
    SbomCapability,
    SbomComponent,
    SbomResult,
    SecretDetectionCapability,
    SecretDetectionResult,
    SecretFinding,
    StaticAnalysisCapability,
    StaticAnalysisResult,
    StaticFinding,
)


def test_sbom_result_carries_components_and_format():
    component = SbomComponent(name="requests", version="2.31.0", purl="pkg:pypi/requests@2.31.0")
    result = SbomResult(
        components=[component],
        sbom_format="cyclonedx-json",
        raw_document='{"components": []}',
        backend_name="syft",
    )
    assert result.components[0].name == "requests"
    assert result.sbom_format == "cyclonedx-json"
    assert result.backend_name == "syft"


def test_cve_result_groups_findings_by_severity():
    result = CveResult(
        findings=[
            CveFinding(
                cve_id="CVE-2024-12345",
                component_name="requests",
                component_version="2.31.0",
                severity="high",
                summary="HTTP redirect handling",
                source_url="https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
            ),
        ],
        backend_name="grype",
    )
    assert result.by_severity()["high"][0].cve_id == "CVE-2024-12345"
    assert result.by_severity().get("low", []) == []


def test_cve_finding_severity_is_constrained():
    with pytest.raises(ValueError):
        CveFinding(
            cve_id="CVE-1",
            component_name="x",
            component_version="1.0",
            severity="apocalyptic",
            summary="",
        )


def test_secret_detection_result_carries_findings():
    result = SecretDetectionResult(
        findings=[
            SecretFinding(
                file="src/api.py",
                line=42,
                rule_id="aws-access-key-id",
                redacted_match="AKIA****************",
                severity="high",
            ),
        ],
        backend_name="trufflehog",
    )
    assert result.findings[0].rule_id == "aws-access-key-id"


def test_static_analysis_result_carries_findings():
    result = StaticAnalysisResult(
        findings=[
            StaticFinding(
                rule_id="python.lang.security.dangerous-subprocess-use",
                file="src/cmd.py",
                line=10,
                severity="medium",
                message="subprocess call with shell=True",
            ),
        ],
        backend_name="semgrep",
    )
    assert result.findings[0].severity == "medium"


def test_protocols_are_runtime_checkable():
    # The Protocols must be @runtime_checkable so the registry can verify
    # backends fulfil the contract via isinstance() before invoking them.
    assert hasattr(SbomCapability, "_is_runtime_protocol")
    assert hasattr(CveCapability, "_is_runtime_protocol")
    assert hasattr(SecretDetectionCapability, "_is_runtime_protocol")
    assert hasattr(StaticAnalysisCapability, "_is_runtime_protocol")


def test_capability_name_attribute_is_required():
    # Every Capability has a `name` class attribute matching its registry key.
    # We assert this on a concrete implementation to lock the convention in.
    class _DummySbom:
        name = "sbom"

        async def run(self, repo_path):  # pragma: no cover (signature only)
            ...

    assert isinstance(_DummySbom(), SbomCapability)
