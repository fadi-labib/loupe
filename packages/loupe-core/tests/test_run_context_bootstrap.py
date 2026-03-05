import shutil
from datetime import datetime
from pathlib import Path

from loupe_core.run_context import BootstrapInputs, RunContext

FIXTURES = Path(__file__).parent / "fixtures"


def test_bootstrap_reads_context_and_kg(tmp_path):
    loupe_dir = tmp_path / ".loupe"
    loupe_dir.mkdir()
    shutil.copy(FIXTURES / "bootstrap_context.md", loupe_dir / "context.md")
    # No knowledge.yaml on disk → starts empty

    inputs = BootstrapInputs(
        run_id="run-1",
        mode="ci",
        started_at=datetime(2026, 5, 13, 14, 32),
        user_intent="analyze",
        loupe_dir=loupe_dir,
        unified_diff="",
        base_sha=None,
        head_sha=None,
        sbom_delta=None,
    )
    ctx = RunContext.bootstrap(inputs)
    assert ctx.run_id == "run-1"
    assert ctx.project.product_description == "Test product."
    assert any(a.label == "PAN" for a in ctx.project.assets)
    assert ctx.knowledge.assets == []
