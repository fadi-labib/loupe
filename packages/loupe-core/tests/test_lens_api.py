from loupe_core.lens_api import Lens, LensCapabilities


class DummyLens:
    capabilities = LensCapabilities(
        name="dummy",
        domain="test",
        handles_intent_keywords=["foo"],
        artifact_paths=[".loupe/dummy.yaml"],
    )

    def build_agent(self, deps_type):
        return None

    def mcp_tools(self):
        return []

    def mcp_workflows(self):
        return []

    def is_relevant(self, run_ctx):
        from loupe_core.run_context import RelevanceScore

        return RelevanceScore(score=1.0, reason="dummy always relevant")

    async def run(self, ctx, plan_entry, boundary, loupe_dir):
        return None  # placeholder; concrete lenses override


def test_capabilities_basic():
    caps = LensCapabilities(
        name="dummy",
        domain="test",
        handles_intent_keywords=["foo"],
        artifact_paths=[".loupe/dummy.yaml"],
    )
    assert caps.name == "dummy"


def test_dummy_lens_conforms_to_protocol():
    lens: Lens = DummyLens()
    assert lens.capabilities.name == "dummy"
    assert isinstance(lens.mcp_tools(), list)


def test_capabilities_split_required_and_preferred():
    """D-23: lens contract distinguishes hard dependencies (`requires`) from
    soft dependencies (`prefers`). Bootstrap raises on a missing required
    capability; preferred-miss only records a `capability_degraded` entry.
    Both fields default to empty list so existing lens declarations keep
    working without a migration."""
    caps = LensCapabilities(name="dummy", domain="test")
    assert caps.requires_capabilities == []
    assert caps.prefers_capabilities == []

    explicit = LensCapabilities(
        name="future-lens",
        domain="example",
        requires_capabilities=["sbom"],
        prefers_capabilities=["secret_detect", "static_analysis"],
    )
    assert explicit.requires_capabilities == ["sbom"]
    assert explicit.prefers_capabilities == ["secret_detect", "static_analysis"]


def test_threatlens_keeps_requires_capabilities_for_sbom_and_cve():
    """D-23 Resolved 1: ThreatLens does NOT migrate to prefers. sbom and
    cve stay in requires_capabilities. If a future maintainer flips this to
    prefers, the bootstrap policy change is observable in the lens
    declaration where code review can see it."""
    from loupe_threatlens.lens import ThreatLens

    caps = ThreatLens().capabilities
    assert set(caps.requires_capabilities) == {"sbom", "cve"}
    assert caps.prefers_capabilities == []
