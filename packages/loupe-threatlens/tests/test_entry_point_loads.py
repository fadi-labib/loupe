"""Verifies the loupe.lenses entry point for threatlens loads cleanly.

This protects against the failure mode where pyproject.toml registers an
entry point pointing at a module that doesn't exist — `discover_lenses()`
would then fail at import time on every Loupe invocation.
"""
from importlib.metadata import entry_points


def test_threatlens_entry_point_loads():
    eps = list(entry_points(group="loupe.lenses"))
    threatlens_eps = [ep for ep in eps if ep.name == "threatlens"]
    assert len(threatlens_eps) == 1, "threatlens entry point not registered"
    lens_cls = threatlens_eps[0].load()
    instance = lens_cls()
    assert instance.capabilities.name == "threatlens"
    assert instance.capabilities.domain == "security"


def test_threatlens_discoverable_via_registry():
    from loupe_core.lens_registry import discover_lenses
    lenses = discover_lenses()
    names = {l.capabilities.name for l in lenses}
    assert "threatlens" in names
