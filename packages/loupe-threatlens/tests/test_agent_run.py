"""End-to-end agent test using VCR cassettes.

This test runs the real PydanticAI agent through one threat-modelling pass
against a synthetic diff. The HTTP calls to the LLM provider are recorded
to a cassette on first run (with `ANTHROPIC_API_KEY` set + `--record-mode=once`)
and replayed for every run thereafter (no API key needed).

Until the cassette is recorded, this test is skipped — not failed — so the
CI suite stays green.

To record the cassette for the first time:

    ANTHROPIC_API_KEY=sk-ant-... \\
        uv run pytest packages/loupe-threatlens/tests/test_agent_run.py \\
        --record-mode=once

Then commit the new file under tests/cassettes/.
"""
import shutil
from datetime import datetime
from pathlib import Path

import pytest
from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.run_context import (
    BootstrapInputs,
    LensRunPlan,
    RelevanceScore,
    RunContext,
)
from loupe_threatlens.lens import ThreatLens

CASSETTE_DIR = Path(__file__).parent / "cassettes"
FIXTURES_DIR = (
    Path(__file__).parent.parent.parent
    / "loupe-core"
    / "tests"
    / "artifacts"
    / "fixtures"
)


def _cassette_present() -> bool:
    return (CASSETTE_DIR / "test_threatlens_proposes_threats_on_diff.yaml").exists()


@pytest.mark.skipif(
    not _cassette_present(),
    reason=(
        "VCR cassette not yet recorded. Run with ANTHROPIC_API_KEY set and "
        "--record-mode=once to record. See test docstring."
    ),
)
@pytest.mark.vcr
async def test_threatlens_proposes_threats_on_diff(tmp_path, monkeypatch):
    """Agent receives a synthetic diff, calls propose_threat ≥1 time."""
    monkeypatch.setenv("THREATLENS_MODEL", "anthropic:claude-haiku-4-5")
    # Set a non-empty value so deferred check passes; VCR replays the response.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-for-vcr-replay")

    loupe_dir = tmp_path / ".loupe"
    loupe_dir.mkdir()
    shutil.copy(FIXTURES_DIR / "valid_context.md", loupe_dir / "context.md")

    synthetic_diff = (
        "diff --git a/src/api.py b/src/api.py\n"
        "@@ -0,0 +1,8 @@\n"
        "+from fastapi import APIRouter\n"
        "+router = APIRouter()\n"
        "+\n"
        "+@router.post('/payments/refund')\n"
        "+def refund(txn_id: str):\n"
        "+    # No authorisation check; accepts any caller's txn_id\n"
        "+    return process_refund(txn_id)\n"
    )
    ctx = RunContext.bootstrap(
        BootstrapInputs(
            run_id="r-vcr", mode="ci", started_at=datetime(2026, 5, 14),
            user_intent="analyse new refund endpoint",
            loupe_dir=loupe_dir,
            unified_diff=synthetic_diff,
            base_sha="a", head_sha="b",
        )
    )
    ctx.plan = [
        LensRunPlan(
            lens_name="threatlens",
            relevance=RelevanceScore(score=0.95, reason="code"),
            depends_on=[],
            sub_prompt=(
                "A new /payments/refund endpoint was added with no authorisation "
                "check. Analyse this diff for STRIDE threats and use propose_threat "
                "for each one you identify."
            ),
        )
    ]

    boundary = PathBoundary(writable_globs=[str(loupe_dir / "threats.yaml")])

    lens = ThreatLens()
    await lens.run(ctx, ctx.plan[0], boundary, loupe_dir)

    # Whichever threats the model proposed should have landed in the
    # RunContext findings dict (recorded by propose_threat_impl).
    threat_keys = [
        k for k in ctx.findings.get("threatlens", {}) if k.startswith("threat:")
    ]
    assert len(threat_keys) >= 1, (
        f"Expected ThreatLens to propose at least one threat for an obvious "
        f"E (Elevation of Privilege) diff, got findings: {ctx.findings}"
    )
