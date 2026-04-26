"""Shared gating helpers — lens liveness check, used by `ci` and `scan`.

The dispatcher's error-isolation branch records a `lens_error` finding
on `ctx.findings[<lens>]` when a lens raises in `run()`. Both `loupe ci`
and `loupe scan` must treat that as a hard failure (exit 1) regardless
of the configured `fail_on` severities — missing evidence beats a
false-green. This module is the single source of truth for that check
so the two command paths can't drift.

Kept in `loupe-core` (not `loupe-cli`) so the helper has no typer
dependency and can be called from any frontend — programmatic, the
GitHub Action wrapper, or a future MCP-driven gate.
"""

from __future__ import annotations

from dataclasses import dataclass

from loupe_core.run_context import RunContext


@dataclass(frozen=True)
class LensLivenessFailure:
    """One lens that crashed during dispatch.

    Fields mirror the payload the dispatcher writes for a `lens_error`
    finding; `kind` is the exception class name (e.g., ``"UserError"``),
    `message` is its string form. The CLI layer turns this into a
    user-facing line; the audit layer turns it into a `LensError` on
    the run record (see `extract_lens_errors`).
    """

    lens: str
    kind: str
    message: str


def check_lens_liveness(ctx: RunContext) -> LensLivenessFailure | None:
    """Return the first crashed lens encountered, or None if all alive.

    "First" is deterministic only to the extent that `ctx.findings`'s
    insertion order is — which it is, dicts preserve insertion order on
    Python 3.7+. Callers should treat the first-failure return as the
    representative failure for messaging purposes; the run record's
    `errors` field carries the full crash set for the audit trail.
    """
    for lens_name, lens_findings in ctx.findings.items():
        lens_error = lens_findings.get("lens_error")
        if lens_error is None:
            continue
        payload = lens_error.payload
        return LensLivenessFailure(
            lens=lens_name,
            kind=str(payload.get("type", "Exception")),
            message=str(payload.get("message", "unknown")),
        )
    return None


def format_liveness_failure(failure: LensLivenessFailure) -> str:
    """Render the user-facing "Gate failure" line for a crashed lens.

    Kept here (not at the call sites) so the message reads identically
    across `loupe ci`, `loupe scan`, and any future caller. Wording
    deliberately includes "missing evidence" — the framing matters: a
    crashed lens isn't a soft warning, it's an evidence gap that
    invalidates the CI assertion.
    """
    return (
        f"Gate failure: lens {failure.lens!r} crashed during dispatch "
        f"({failure.kind}: {failure.message}). "
        f"Treating missing evidence as a hard failure."
    )
