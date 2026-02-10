from datetime import datetime
import shutil
from pathlib import Path
import pytest
from loupe_core.run_context import RunContext, RelevanceScore, BootstrapInputs
from loupe_core.lens_api import LensCapabilities
from loupe_core.coordinator import build_run_plan
from loupe_core.dispatcher import dispatch_plan
from loupe_core.config import LoupeConfig, LensActivation
from loupe_core.tools import write_agent_artifact
from loupe_core.enforcement.path_boundary import PathBoundary


FIXTURES = Path(__file__).parent / "fixtures"


class EchoLens:
    capabilities = LensCapabilities(
        name="echo", domain="test",
        artifact_paths=[".loupe/echo.txt"],
    )

    def build_agent(self, t):
        return None

    def mcp_tools(self): return []
    def mcp_workflows(self): return []

    def is_relevant(self, ctx):
        return RelevanceScore(score=0.99, reason="dummy is always interested")

    async def run(self, ctx, plan_entry, boundary, loupe_dir):
        path = loupe_dir / "echo.txt"
        write_agent_artifact(boundary, path, f"hello from echo on {ctx.run_id}")
        ctx.record_finding("echo", "wrote", str(path))


@pytest.mark.asyncio
async def test_dispatch_runs_lens_and_writes_artifact(tmp_path):
    loupe_dir = tmp_path / ".loupe"
    loupe_dir.mkdir()
    shutil.copy(FIXTURES / "bootstrap_context.md", loupe_dir / "context.md")

    ctx = RunContext.bootstrap(BootstrapInputs(
        run_id="r1", mode="ci", started_at=datetime(2026, 5, 13),
        user_intent="echo", loupe_dir=loupe_dir,
    ))

    cfg = LoupeConfig(
        agent_writable_paths=[str(loupe_dir / "echo.txt")],
        lenses={"echo": LensActivation(enabled=True, minimum_relevance=0.3)},
    )
    boundary = PathBoundary(writable_globs=cfg.agent_writable_paths)

    lens = EchoLens()
    plan = build_run_plan(ctx, [lens], cfg)
    ctx.plan = plan

    await dispatch_plan(ctx, [lens], boundary, loupe_dir)

    assert (loupe_dir / "echo.txt").read_text() == "hello from echo on r1"
    assert ctx.lookup("echo", "wrote") == str(loupe_dir / "echo.txt")
