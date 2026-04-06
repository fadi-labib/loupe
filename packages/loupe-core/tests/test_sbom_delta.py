"""Contract tests for SBOMDelta and UpgradedPackage.

The Phase 7 sweep replaced the positional 3-tuple
`(name, before, after)` with a named-field Pydantic model so that
typos at the call site cannot silently swap version strings.
"""

from __future__ import annotations

import pytest
from loupe_core.run_context import SBOMDelta, UpgradedPackage
from pydantic import ValidationError


def test_upgraded_package_named_fields() -> None:
    up = UpgradedPackage(name="requests", before="2.31.0", after="2.32.0")
    assert up.name == "requests"
    assert up.before == "2.31.0"
    assert up.after == "2.32.0"


def test_upgraded_package_rejects_empty_strings() -> None:
    with pytest.raises(ValidationError):
        UpgradedPackage(name="", before="1.0", after="2.0")
    with pytest.raises(ValidationError):
        UpgradedPackage(name="x", before="", after="2.0")
    with pytest.raises(ValidationError):
        UpgradedPackage(name="x", before="1.0", after="")


def test_sbom_delta_holds_upgraded_packages() -> None:
    delta = SBOMDelta(
        upgraded_packages=[
            UpgradedPackage(name="urllib3", before="2.2.0", after="2.2.1"),
        ],
    )
    assert delta.upgraded_packages[0].name == "urllib3"
    assert delta.upgraded_packages[0].before == "2.2.0"
    assert delta.upgraded_packages[0].after == "2.2.1"


def test_sbom_delta_rejects_positional_tuple() -> None:
    """Guard against regression to the old positional-tuple shape."""
    with pytest.raises(ValidationError):
        SBOMDelta(upgraded_packages=[("requests", "2.31.0", "2.32.0")])  # type: ignore[list-item]
