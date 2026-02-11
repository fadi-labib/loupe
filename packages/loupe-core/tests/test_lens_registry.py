from unittest.mock import MagicMock, patch

import pytest
from loupe_core.lens_api import LensCapabilities
from loupe_core.lens_registry import LensRegistryError, discover_lenses


class FakeLensA:
    capabilities = LensCapabilities(name="a", domain="d1", artifact_paths=[".loupe/a.yaml"])
    def build_agent(self, t): return None
    def mcp_tools(self): return []
    def mcp_workflows(self): return []
    def is_relevant(self, c):
        from loupe_core.run_context import RelevanceScore
        return RelevanceScore(score=0.5, reason="")
    async def run(self, ctx, p, b, d): return None


class FakeLensB:
    capabilities = LensCapabilities(name="b", domain="d2", artifact_paths=[".loupe/b.yaml"])
    def build_agent(self, t): return None
    def mcp_tools(self): return []
    def mcp_workflows(self): return []
    def is_relevant(self, c):
        from loupe_core.run_context import RelevanceScore
        return RelevanceScore(score=0.5, reason="")
    async def run(self, ctx, p, b, d): return None


def _fake_entry_points(group):
    ep_a, ep_b = MagicMock(), MagicMock()
    ep_a.name = "a"
    ep_a.load.return_value = FakeLensA
    ep_b.name = "b"
    ep_b.load.return_value = FakeLensB
    return [ep_a, ep_b]


def test_discovers_two_lenses():
    with patch("loupe_core.lens_registry._entry_points", _fake_entry_points):
        lenses = discover_lenses()
    assert {lens.capabilities.name for lens in lenses} == {"a", "b"}


def test_rejects_conflicting_artifact_paths():
    class FakeBOverlap:
        capabilities = LensCapabilities(name="b", domain="d2", artifact_paths=[".loupe/a.yaml"])
        def build_agent(self, t): return None
        def mcp_tools(self): return []
        def mcp_workflows(self): return []
        def is_relevant(self, c):
            from loupe_core.run_context import RelevanceScore
            return RelevanceScore(score=0.5, reason="")
        async def run(self, ctx, p, b, d): return None

    def conflicting(group):
        ep_a, ep_b = MagicMock(), MagicMock()
        ep_a.name = "a"
        ep_a.load.return_value = FakeLensA
        ep_b.name = "b"
        ep_b.load.return_value = FakeBOverlap
        return [ep_a, ep_b]

    with patch("loupe_core.lens_registry._entry_points", conflicting):
        with pytest.raises(LensRegistryError):
            discover_lenses()
