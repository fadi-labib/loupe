from __future__ import annotations

import json
import logging
import os
import traceback
from pathlib import Path
from typing import Any

from loupe_core.enforcement.path_boundary import PathBoundary
from loupe_core.lens_api import Lens
from loupe_core.run_context import RunContext

_LOG = logging.getLogger(__name__)

# Set LOUPE_DEBUG=1 to force the full traceback to stderr for every
# crash, including the predictable LLM-config shapes below. Otherwise
# only the friendly one-line summary is shown; the full traceback
# always lands in the run record's `errors[].traceback_excerpt`.
_DEBUG_ENV_VAR = "LOUPE_DEBUG"


async def dispatch_plan(
    ctx: RunContext,
    lenses: list[Lens],
    boundary: PathBoundary,
    loupe_dir: Path,
) -> None:
    """Run every lens in ctx.plan in order.

    Each lens must implement `async def run(self, ctx, plan_entry, boundary, loupe_dir)`.
    Lenses are looked up by name from the provided list.

    Error isolation: a single lens raising in `run()` must not abort sibling
    lenses. The exception is logged, the failure is recorded on
    `ctx.findings[<lens_name>]['lens_error']` (so the run record retains
    visibility), and the loop continues to the next plan entry.

    Friendliness pass: for predictable LLM-configuration shapes
    (`pydantic_ai.exceptions.UserError` for missing keys; `ModelHTTPError`
    with a 401/403 status), suppress the stderr traceback in favour of a
    single actionable line. Set `LOUPE_DEBUG=1` to re-enable the traceback.
    The full traceback always lands in the run record so an auditor never
    loses the diagnostic; this only changes terminal noise.
    """
    by_name = {lens.capabilities.name: lens for lens in lenses}
    debug_mode = os.environ.get(_DEBUG_ENV_VAR) == "1"
    for plan_entry in ctx.plan:
        lens = by_name[plan_entry.lens_name]
        try:
            await lens.run(ctx, plan_entry, boundary, loupe_dir)
        except Exception as exc:  # noqa: BLE001 — deliberate broad catch for isolation
            friendly = _classify_friendly(plan_entry.lens_name, exc)
            if friendly is None or debug_mode:
                # Unknown shape (or debug forced): emit full traceback to
                # stderr per the original isolation contract.
                _LOG.exception(
                    "Lens %r raised; continuing with remaining lenses.",
                    plan_entry.lens_name,
                )
            else:
                # Predictable shape: log the friendly line only. The full
                # traceback still lands in the run record below — the
                # information is preserved, only the *terminal* output
                # is quieter.
                _LOG.error("%s", friendly)

            payload: dict[str, Any] = {
                "type": type(exc).__name__,
                "message": str(exc),
                "traceback": traceback.format_exc(),
            }
            request_id = _extract_request_id(exc)
            if request_id is not None:
                payload["request_id"] = request_id
            ctx.record_finding(
                plan_entry.lens_name,
                "lens_error",
                payload,
            )


def _classify_friendly(lens_name: str, exc: BaseException) -> str | None:
    """Return a user-facing one-liner for a known exception shape, or None.

    Returning None means "this is an unexpected exception; show the full
    traceback per the original contract". The two shapes we recognise:

    - `pydantic_ai.exceptions.UserError`: agent declared its requirements
      weren't met (typically a missing provider key). The message is
      already operator-facing; just prepend lens context.
    - `pydantic_ai.exceptions.ModelHTTPError` with status 401/403: the
      provider rejected the key. The default str(exc) is informative
      but buried under a stack trace; surface it directly.

    PydanticAI is imported lazily so a future lens that does not use
    PydanticAI won't trip an ImportError just because the dispatcher
    tried to classify its crash.
    """
    try:
        from pydantic_ai.exceptions import ModelHTTPError, UserError
    except ImportError:
        return None

    if isinstance(exc, UserError):
        return (
            f"Lens {lens_name!r} failed: {exc}. "
            f"Check `models.default` in .loupe/config.yaml and the matching "
            f"provider key in your environment (e.g., ANTHROPIC_API_KEY)."
        )
    if isinstance(exc, ModelHTTPError) and exc.status_code in (401, 403):
        return (
            f"Lens {lens_name!r} failed: provider rejected the API key "
            f"(HTTP {exc.status_code} from {exc.model_name}). "
            f"Verify the key for `models.default` in .loupe/config.yaml is valid."
        )
    return None


def _extract_request_id(exc: BaseException) -> str | None:
    """Pull a provider request id out of an exception when present.

    Anthropic and OpenAI both surface `request_id` in the JSON error body
    on 4xx responses. PydanticAI carries that body on `ModelHTTPError.body`
    as a JSON-formatted string (per its constructor). Try to parse; on
    any failure, return None — request_id is optional in the audit record.
    """
    body = getattr(exc, "body", None)
    if body is None:
        return None
    if isinstance(body, dict):
        rid = body.get("request_id")
        return str(rid) if rid is not None else None
    if isinstance(body, str):
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            return None
        if isinstance(parsed, dict):
            rid = parsed.get("request_id")
            return str(rid) if rid is not None else None
    return None
