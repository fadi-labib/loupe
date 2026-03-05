from pathlib import Path

import pytest
from loupe_core.artifacts.context import BulletItem, ContextMdError, ProjectContext

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_valid_context():
    ctx = ProjectContext.from_markdown(FIXTURES / "valid_context.md")
    assert "Payment-processing API" in ctx.product_description
    assert any(a.label == "PAN" for a in ctx.assets)
    assert any(t.label == "Compromised internal service" for t in ctx.threat_actors)


def test_missing_section_raises():
    with pytest.raises(ContextMdError) as exc:
        ProjectContext.from_markdown(FIXTURES / "missing_section_context.md")
    assert "Users and roles" in str(exc.value)


def test_bullet_preserves_note_after_colon():
    """`- Customer: places orders` becomes BulletItem(label='Customer', note='places orders').

    Regression test: an earlier parser silently dropped the note, losing
    security-relevant role descriptions before they reached the agent.
    """
    ctx = ProjectContext.from_markdown(FIXTURES / "valid_context.md")
    by_label = {u.label: u for u in ctx.users}
    assert by_label["internal-service"].note == "callers from our own VPC"
    assert by_label["ops-engineer"].note == "SREs with read-only log access"


def test_bullet_without_colon_has_no_note():
    ctx = ProjectContext.from_markdown(FIXTURES / "valid_context.md")
    pan = next(a for a in ctx.assets if a.label == "PAN")
    assert pan.note is None


def test_bullet_str_roundtrips_for_prompt_assembly():
    """`str(BulletItem)` reproduces the on-disk `label: note` form."""
    assert str(BulletItem(label="Customer", note="places orders")) == "Customer: places orders"
    assert str(BulletItem(label="PAN")) == "PAN"
