"""Dispatcher error-isolation contract.

A single lens that raises in `run()` must not abort sibling lenses, and the
failure must surface on the run record (via `ctx.findings`) so the operator
sees which lens crashed.
"""
from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path

import pytest
from loupe_core.config import LensActivation, LoupeConfig
from loupe_core.coordinator import build_run_plan
from loupe_core.dispatcher import dispatch_plan
from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.lens_api import LensCapabilities
from loupe_core.run_context import BootstrapInputs, RelevanceScore, RunContext
from loupe_core.tools import write_agent_artifact

FIXTURES = Path(__file__).parent / "fixtures"


class _OkLens:
    capabilities = LensCapabilities(
        name="lens_ok", domain="test",
        artifact_paths=[".loupe/lens_ok.txt"],
    )

    def build_agent(self, t):
        return None

    def mcp_tools(self): return []
    def mcp_workflows(self): return []

    def is_relevant(self, ctx):
        return RelevanceScore(score=0.99, reason="always relevant")

    async def run(self, ctx, plan_entry, boundary, loupe_dir):
        path = loupe_dir / "lens_ok.txt"
        write_agent_artifact(boundary, path, "ok artefact")
        ctx.record_finding("lens_ok", "wrote", str(path))


class _CrashingLens:
    capabilities = LensCapabilities(
        name="lens_bad", domain="test",
        artifact_paths=[".loupe/lens_bad.txt"],
    )

    def build_agent(self, t):
        return None

    def mcp_tools(self): return []
    def mcp_workflows(self): return []

    def is_relevant(self, ctx):
        return RelevanceScore(score=0.99, reason="always relevant")

    async def run(self, ctx, plan_entry, boundary, loupe_dir):
        raise RuntimeError("intentional crash from lens_bad")


def _make_ctx(tmp_path: Path) -> tuple[RunContext, Path]:
    loupe_dir = tmp_path / ".loupe"
    loupe_dir.mkdir()
    shutil.copy(FIXTURES / "bootstrap_context.md", loupe_dir / "context.md")
    ctx = RunContext.bootstrap(BootstrapInputs(
        run_id="r-isolate", mode="ci", started_at=datetime(2026, 5, 15),
        user_intent="isolation test", loupe_dir=loupe_dir,
    ))
    return ctx, loupe_dir


@pytest.mark.asyncio
async def test_dispatch_continues_after_lens_raises(tmp_path):
    """A crashing lens must not abort sibling lenses, and dispatch_plan must
    not propagate the exception. The failure must be recorded on the run
    context under the crashing lens's name so the run record retains visibility.
    """
    ctx, loupe_dir = _make_ctx(tmp_path)

    cfg = LoupeConfig(
        agent_writable_paths=[
            str(loupe_dir / "lens_ok.txt"),
            str(loupe_dir / "lens_bad.txt"),
        ],
        lenses={
            "lens_bad": LensActivation(enabled=True, minimum_relevance=0.3),
            "lens_ok": LensActivation(enabled=True, minimum_relevance=0.3),
        },
    )
    boundary = PathBoundary(writable_globs=cfg.agent_writable_paths)

    bad = _CrashingLens()
    ok = _OkLens()
    # Schedule the crashing lens FIRST so we can prove the sibling still runs.
    plan = build_run_plan(ctx, [bad, ok], cfg)
    ctx.plan = plan

    # MUST NOT raise.
    await dispatch_plan(ctx, [bad, ok], boundary, loupe_dir)

    # Sibling lens still produced its artefact.
    assert (loupe_dir / "lens_ok.txt").read_text() == "ok artefact"
    assert ctx.lookup("lens_ok", "wrote") == str(loupe_dir / "lens_ok.txt")

    # Crashing lens's failure is recorded against its name on the blackboard.
    error_record = ctx.lookup("lens_bad", "lens_error")
    assert error_record is not None, "lens_bad failure must be recorded on ctx.findings"
    assert "intentional crash from lens_bad" in str(error_record)
