from unittest.mock import MagicMock, patch

import pytest
from loupe_core.lens_api import LensCapabilities
from loupe_core.lens_registry import (
    LensRegistryError,
    _check_artifact_path_conflicts,
    discover_lenses,
)


class FakeLensA:
    capabilities = LensCapabilities(name="a", domain="d1", artifact_paths=[".loupe/a.yaml"])

    def build_agent(self, t):
        return None

    def mcp_tools(self):
        return []

    def mcp_workflows(self):
        return []

    def is_relevant(self, c):
        from loupe_core.run_context import RelevanceScore

        return RelevanceScore(score=0.5, reason="")

    async def run(self, ctx, p, b, d):
        return None


class FakeLensB:
    capabilities = LensCapabilities(name="b", domain="d2", artifact_paths=[".loupe/b.yaml"])

    def build_agent(self, t):
        return None

    def mcp_tools(self):
        return []

    def mcp_workflows(self):
        return []

    def is_relevant(self, c):
        from loupe_core.run_context import RelevanceScore

        return RelevanceScore(score=0.5, reason="")

    async def run(self, ctx, p, b, d):
        return None


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

        def build_agent(self, t):
            return None

        def mcp_tools(self):
            return []

        def mcp_workflows(self):
            return []

        def is_relevant(self, c):
            from loupe_core.run_context import RelevanceScore

            return RelevanceScore(score=0.5, reason="")

        async def run(self, ctx, p, b, d):
            return None

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


class _DummyLens:
    def __init__(self, name: str, artifact_paths: list[str]) -> None:
        self.capabilities = LensCapabilities(name=name, domain="d", artifact_paths=artifact_paths)

    def build_agent(self, t):
        return None

    def mcp_tools(self):
        return []

    def mcp_workflows(self):
        return []

    def is_relevant(self, c):
        from loupe_core.run_context import RelevanceScore

        return RelevanceScore(score=0.5, reason="")

    async def run(self, ctx, p, b, d):
        return None


def test_three_way_artifact_path_conflict_detected():
    """A three-way collision must surface all three lens names, not just the first
    pair. The old implementation set seen[path] = name AFTER the raise, so the
    third lens was never compared and its name was silently dropped from the error.
    """
    lens_a = _DummyLens("a", [".loupe/shared.yaml"])
    lens_b = _DummyLens("b", [".loupe/shared.yaml"])
    lens_c = _DummyLens("c", [".loupe/shared.yaml"])

    with pytest.raises(LensRegistryError) as excinfo:
        _check_artifact_path_conflicts([lens_a, lens_b, lens_c])

    message = str(excinfo.value)
    assert "shared.yaml" in message
    # All three claimants must appear so the operator knows which packages
    # to disambiguate, not just two of them.
    assert "'a'" in message
    assert "'b'" in message
    assert "'c'" in message


def test_multiple_conflicting_paths_reported_together():
    """Two independent conflicts must surface in one error, not just the first
    encountered — otherwise the operator has to fix-and-rerun N times.
    """
    lens_a = _DummyLens("a", [".loupe/x.yaml", ".loupe/y.yaml"])
    lens_b = _DummyLens("b", [".loupe/x.yaml"])
    lens_c = _DummyLens("c", [".loupe/y.yaml"])

    with pytest.raises(LensRegistryError) as excinfo:
        _check_artifact_path_conflicts([lens_a, lens_b, lens_c])

    message = str(excinfo.value)
    assert "x.yaml" in message
    assert "y.yaml" in message
