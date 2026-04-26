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
        name="lens_ok",
        domain="test",
        artifact_paths=[".loupe/lens_ok.txt"],
    )

    def build_agent(self, t):
        return None

    def mcp_tools(self):
        return []

    def mcp_workflows(self):
        return []

    def is_relevant(self, ctx):
        return RelevanceScore(score=0.99, reason="always relevant")

    async def run(self, ctx, plan_entry, boundary, loupe_dir):
        path = loupe_dir / "lens_ok.txt"
        write_agent_artifact(boundary, path, "ok artefact")
        ctx.record_finding("lens_ok", "wrote", str(path))


class _CrashingLens:
    capabilities = LensCapabilities(
        name="lens_bad",
        domain="test",
        artifact_paths=[".loupe/lens_bad.txt"],
    )

    def build_agent(self, t):
        return None

    def mcp_tools(self):
        return []

    def mcp_workflows(self):
        return []

    def is_relevant(self, ctx):
        return RelevanceScore(score=0.99, reason="always relevant")

    async def run(self, ctx, plan_entry, boundary, loupe_dir):
        raise RuntimeError("intentional crash from lens_bad")


def _make_ctx(tmp_path: Path) -> tuple[RunContext, Path]:
    loupe_dir = tmp_path / ".loupe"
    loupe_dir.mkdir()
    shutil.copy(FIXTURES / "bootstrap_context.md", loupe_dir / "context.md")
    ctx = RunContext.bootstrap(
        BootstrapInputs(
            run_id="r-isolate",
            mode="ci",
            started_at=datetime(2026, 5, 15),
            user_intent="isolation test",
            loupe_dir=loupe_dir,
        )
    )
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


class _UserErrorLens:
    """A lens that raises pydantic_ai.exceptions.UserError, the shape the
    PydanticAI agent emits when the configured provider has no key set."""

    capabilities = LensCapabilities(
        name="lens_user_error",
        domain="test",
        artifact_paths=[".loupe/lens_user_error.txt"],
    )

    def build_agent(self, t):
        return None

    def mcp_tools(self):
        return []

    def mcp_workflows(self):
        return []

    def is_relevant(self, ctx):
        return RelevanceScore(score=0.99, reason="always relevant")

    async def run(self, ctx, plan_entry, boundary, loupe_dir):
        from pydantic_ai.exceptions import UserError

        raise UserError("Set the `ANTHROPIC_API_KEY` env variable")


class _HTTP401Lens:
    """A lens that raises ModelHTTPError with the shape PydanticAI emits
    when the provider rejects the configured key."""

    capabilities = LensCapabilities(
        name="lens_http_401",
        domain="test",
        artifact_paths=[".loupe/lens_http_401.txt"],
    )

    def build_agent(self, t):
        return None

    def mcp_tools(self):
        return []

    def mcp_workflows(self):
        return []

    def is_relevant(self, ctx):
        return RelevanceScore(score=0.99, reason="always relevant")

    async def run(self, ctx, plan_entry, boundary, loupe_dir):
        from pydantic_ai.exceptions import ModelHTTPError

        # PydanticAI's ModelHTTPError constructor turns body into a JSON
        # string when it's parseable; mirror that here so request_id
        # extraction has something to parse.
        raise ModelHTTPError(
            status_code=401,
            model_name="claude-opus-4-7",
            body='{"error": "invalid x-api-key", "request_id": "req_abc123"}',
        )


@pytest.mark.asyncio
async def test_user_error_emits_friendly_message_not_traceback(tmp_path, caplog):
    """A `UserError` (missing key) is a known shape — the lens-loop must
    log a one-line ERROR with actionable instructions, not the 25-line
    Python traceback that was the historical default. The traceback
    still lands in the run record for the auditor."""
    import logging

    ctx, loupe_dir = _make_ctx(tmp_path)
    cfg = LoupeConfig(
        agent_writable_paths=[str(loupe_dir / "lens_user_error.txt")],
        lenses={"lens_user_error": LensActivation(enabled=True, minimum_relevance=0.3)},
    )
    boundary = PathBoundary(writable_globs=cfg.agent_writable_paths)
    lens = _UserErrorLens()
    ctx.plan = build_run_plan(ctx, [lens], cfg)

    with caplog.at_level(logging.ERROR, logger="loupe_core.dispatcher"):
        await dispatch_plan(ctx, [lens], boundary, loupe_dir)

    # ERROR-level log line carries the friendly message; no Python
    # traceback was emitted through the logger.
    error_messages = [r.message for r in caplog.records if r.levelno == logging.ERROR]
    friendly = [m for m in error_messages if "ANTHROPIC_API_KEY" in m]
    assert friendly, f"expected a friendly ERROR message; got: {error_messages}"
    # The full traceback is still present on the run record so an auditor
    # walking .loupe/runs/*.json can recover diagnostics later.
    error_record = ctx.lookup("lens_user_error", "lens_error")
    assert error_record is not None
    assert "UserError" in str(error_record)


@pytest.mark.asyncio
async def test_model_http_401_emits_friendly_and_extracts_request_id(tmp_path, caplog):
    import logging

    ctx, loupe_dir = _make_ctx(tmp_path)
    cfg = LoupeConfig(
        agent_writable_paths=[str(loupe_dir / "lens_http_401.txt")],
        lenses={"lens_http_401": LensActivation(enabled=True, minimum_relevance=0.3)},
    )
    boundary = PathBoundary(writable_globs=cfg.agent_writable_paths)
    lens = _HTTP401Lens()
    ctx.plan = build_run_plan(ctx, [lens], cfg)

    with caplog.at_level(logging.ERROR, logger="loupe_core.dispatcher"):
        await dispatch_plan(ctx, [lens], boundary, loupe_dir)

    error_messages = [r.message for r in caplog.records if r.levelno == logging.ERROR]
    assert any("HTTP 401" in m and "claude-opus-4-7" in m for m in error_messages), (
        f"expected friendly HTTP 401 message; got: {error_messages}"
    )

    error_record = ctx.lookup("lens_http_401", "lens_error")
    assert error_record is not None
    # request_id was pulled out of the body JSON for the audit record.
    # ctx.lookup returns the payload dict directly (not a Finding wrapper).
    assert error_record.get("request_id") == "req_abc123"


@pytest.mark.asyncio
async def test_unknown_exception_shape_still_emits_traceback(tmp_path, caplog):
    """For exception shapes the friendliness pass doesn't recognise,
    behaviour must match the original isolation contract: full
    traceback via _LOG.exception. We can't catch a regression to the
    'silent every error' state otherwise."""
    import logging

    ctx, loupe_dir = _make_ctx(tmp_path)
    cfg = LoupeConfig(
        agent_writable_paths=[str(loupe_dir / "lens_bad.txt")],
        lenses={"lens_bad": LensActivation(enabled=True, minimum_relevance=0.3)},
    )
    boundary = PathBoundary(writable_globs=cfg.agent_writable_paths)
    lens = _CrashingLens()
    ctx.plan = build_run_plan(ctx, [lens], cfg)

    with caplog.at_level(logging.ERROR, logger="loupe_core.dispatcher"):
        await dispatch_plan(ctx, [lens], boundary, loupe_dir)

    # _LOG.exception emits at ERROR with exc_info attached — that's the
    # signature of a full-traceback log line, distinct from _LOG.error.
    records_with_exc_info = [r for r in caplog.records if r.exc_info is not None]
    assert records_with_exc_info, "unknown shapes must keep the full-traceback log"
