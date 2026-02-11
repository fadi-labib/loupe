from pathlib import Path

import pytest
from loupe_core.artifacts.context import ContextMdError, ProjectContext

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_valid_context():
    ctx = ProjectContext.from_markdown(FIXTURES / "valid_context.md")
    assert "Payment-processing API" in ctx.product_description
    assert "PAN" in ctx.assets
    assert "Compromised internal service" in ctx.threat_actors


def test_missing_section_raises():
    with pytest.raises(ContextMdError) as exc:
        ProjectContext.from_markdown(FIXTURES / "missing_section_context.md")
    assert "Users and roles" in str(exc.value)
