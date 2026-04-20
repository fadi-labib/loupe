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
