"""Tests for `loupe_core.gating` — the shared liveness check used by
`loupe ci` and `loupe scan`.

Pin the small contract here so the frontends can trust it: a crashed
lens is detectable, the first failure wins for messaging, and the
formatter renders a stable user-facing line.
"""

from datetime import UTC, datetime

from loupe_core.gating import (
    LensLivenessFailure,
    check_lens_liveness,
    format_liveness_failure,
)
from loupe_core.run_context import RunContext


def _ctx() -> RunContext:
    return RunContext(
        run_id="r",
        mode="ci",
        started_at=datetime(2026, 5, 16, tzinfo=UTC),
        user_intent="",
        diff=None,
        sbom_delta=None,
        project=None,
        plan=[],
        knowledge=None,
    )


def test_check_lens_liveness_returns_none_when_no_lens_crashed():
    ctx = _ctx()
    ctx.record_finding("threatlens", "threat:T-001", {"severity": "high"})
    assert check_lens_liveness(ctx) is None


def test_check_lens_liveness_detects_crashed_lens():
    ctx = _ctx()
    ctx.record_finding(
        "threatlens",
        "lens_error",
        {"type": "UserError", "message": "missing API key", "traceback": "..."},
    )
    failure = check_lens_liveness(ctx)
    assert failure == LensLivenessFailure(
        lens="threatlens", kind="UserError", message="missing API key"
    )


def test_check_lens_liveness_returns_first_when_multiple_crashed():
    """Multiple crashed lenses → return the first encountered (insertion order).
    The run record's `errors[]` carries the full set; the liveness helper is
    only responsible for short-circuiting the gate."""
    ctx = _ctx()
    ctx.record_finding("alens", "lens_error", {"type": "A", "message": "a", "traceback": ""})
    ctx.record_finding("blens", "lens_error", {"type": "B", "message": "b", "traceback": ""})
    failure = check_lens_liveness(ctx)
    assert failure is not None
    assert failure.lens == "alens"


def test_check_lens_liveness_handles_missing_payload_fields():
    """Defensive: if a lens manages to write a malformed lens_error
    payload, the helper still returns a usable failure rather than
    raising — the alternative would be an unhandled exception in the
    CLI's exit-code path, which would leave the user with no signal."""
    ctx = _ctx()
    ctx.record_finding("threatlens", "lens_error", {})  # no type, no message
    failure = check_lens_liveness(ctx)
    assert failure is not None
    assert failure.kind == "Exception"
    assert failure.message == "unknown"


def test_format_liveness_failure_includes_lens_kind_message():
    failure = LensLivenessFailure(
        lens="threatlens", kind="ModelHTTPError", message="status_code: 401"
    )
    rendered = format_liveness_failure(failure)
    assert "threatlens" in rendered
    assert "ModelHTTPError" in rendered
    assert "401" in rendered
    assert "missing evidence" in rendered.lower()
