"""`loupe scan` — D-15 full-repo / scoped scan mode.

Unlike `loupe ci` (incremental, diff-driven), `loupe scan` is the
no-diff entry point: the coordinator's relevance filter is bypassed
because the user has explicitly invoked the lens, so the platform must
run it.

Scoped mode (`--paths`) walks the given paths, recursively expands
directories, filters by `CODE_EXTENSIONS`, and reads each file via
`safe_read_under` (Layer-1-equivalent read-side path boundary).
Bytes land on `ctx.scoped_sources` and the user-prompt builder
renders them under a "## Source files under analysis" section so
the agent reasons against actual code, not just `context.md` (D-24).
Files larger than `--max-chars-per-file` (default 50,000) truncate
at the cap with a visible marker.

Full mode (`loupe scan` with no `--paths`) doesn't pre-load source
bytes — the lens runs against `context.md`, the SBOM, and the CVE
findings only. A future `read_source(path)` agent tool (D-24 Option
C, deferred to v1.x) will give the lens dynamic per-file reads for
Tier-2-scale codebases.

Cost note: scoped scans are materially more expensive than diff-mode
runs. The per-mode `per_run_max_usd.scan` ceiling (default $5.00 in
the scaffold) is wider than the `.ci` ceiling for that reason
(D-24 / Resolved 3). A `--budget-usd` override flag is designed in
D-15 but not yet wired.

When to use:
- First-time onboarding to an existing codebase (`loupe scan`)
- Periodic re-baseline (quarterly-ish)
- Architectural review of a specific subsystem (`loupe scan --paths …`)
- Audit kickoff
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import typer
from loupe_core.artifacts.run_record_writer import build_run_record
from loupe_core.capabilities.bootstrap import bootstrap_capabilities
from loupe_core.capabilities.errors import RequiredCapabilityUnavailable
from loupe_core.capabilities.registry import CapabilityRegistry
from loupe_core.config import LoupeConfig, load_config
from loupe_core.coordinator import build_run_plan
from loupe_core.dispatcher import dispatch_plan
from loupe_core.enforcement.path_boundary import (
    PathBoundary,
    safe_read_under,
)
from loupe_core.fs import CODE_EXTENSIONS
from loupe_core.gating import check_lens_liveness, format_liveness_failure
from loupe_core.lens_api import Lens
from loupe_core.lens_registry import discover_lenses
from loupe_core.run_context import BootstrapInputs, RunContext, ScopedSource
from loupe_core.tools import BoundaryViolation

# BSD sysexits.h EX_USAGE — operator-config / usage errors.
USAGE_ERROR = 64


def scan_command(
    paths: list[str],
    config_path: Path,
    max_chars_per_file: int = 50_000,
) -> int:
    cwd = Path.cwd().resolve()
    loupe = cwd / ".loupe"
    if not loupe.exists():
        typer.echo(
            "Error: .loupe/ not found in the current directory.\nRun `loupe init` first.",
            err=True,
        )
        return USAGE_ERROR

    cfg = load_config(config_path)
    boundary = PathBoundary(
        writable_globs=cfg.agent_writable_paths,
        project_root=cwd,
    )
    lenses = discover_lenses()

    scope: Literal["full", "scoped"] = "scoped" if paths else "full"

    # D-24 / B.4: read source files for scoped scans BEFORE bootstrap so
    # an invalid --paths fails fast (exit 64) without paying for capability
    # bootstrap or LLM calls. Empty list when scope=="full" (full-repo
    # scans don't pre-load source; that's Phase B v1.x via Option C —
    # read_source(path) agent tool — when Tier 2 lands).
    scoped_sources: list[ScopedSource] = []
    if scope == "scoped":
        try:
            scoped_sources = _assemble_scoped_sources(
                paths=paths, project_root=cwd, max_chars=max_chars_per_file
            )
        except _ScopeAssemblyError as exc:
            typer.echo(f"Error: {exc}", err=True)
            return USAGE_ERROR

    # Timezone-aware UTC: RunRecord.timestamp rejects naive datetimes
    # because the on-disk filename appends a literal 'Z' (Phase 7).
    started_at = datetime.now(UTC)
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    user_intent = f"scan scoped to {paths}" if paths else "full-repo scan"

    ctx = RunContext.bootstrap(
        BootstrapInputs(
            run_id=run_id,
            mode="ci",  # scan is a non-interactive flow
            started_at=started_at,
            user_intent=user_intent,
            loupe_dir=loupe,
            unified_diff="",  # no diff in scan mode
            base_sha=None,
            head_sha=None,
            scope=scope,
            scope_paths=list(paths),
        )
    )
    ctx.scoped_sources = scoped_sources
    ctx.plan = build_run_plan(ctx, lenses, cfg)

    if not ctx.plan:
        typer.echo("No enabled lenses to run. Check config.yaml.")
        _write_run_record(ctx, loupe, considered=lenses, cfg=cfg, scope=scope)
        return 0

    # Run capability bootstrap ONCE before any lens executes — mirror of
    # ci_cmd. ThreatLens declares requires_capabilities=["sbom", "cve"];
    # under D-23 a required-miss exits 64 (operator must wire Syft/Grype)
    # rather than the silently-degraded run the platform used to produce.
    planned_lenses = _planned_lenses(lenses, ctx)
    needs_caps = any(
        getattr(lens.capabilities, "requires_capabilities", [])
        or getattr(lens.capabilities, "prefers_capabilities", [])
        for lens in planned_lenses
    )
    if needs_caps:
        registry = CapabilityRegistry.discover()
        try:
            degradations = asyncio.run(
                bootstrap_capabilities(
                    ctx=ctx,
                    lenses=planned_lenses,
                    config=cfg,
                    registry=registry,
                    repo_path=cwd,
                )
            )
        except RequiredCapabilityUnavailable as exc:
            typer.echo(
                f"Error: lens '{exc.lens_name}' requires capability '{exc.capability}' "
                f"but no backends are configured. Install the backend binary and "
                f"uncomment the matching block under `capabilities:` in "
                f".loupe/config.yaml. See docs/concepts/capabilities.md.\n"
                f"  underlying: {exc.cause}",
                err=True,
            )
            return USAGE_ERROR
        ctx.capability_degradations = degradations
        for d in degradations:
            typer.echo(
                f"note: lens '{d.lens_name}' preferred capability '{d.capability}' "
                f"unavailable ({d.kind}); running without it. See run record "
                f"capability_degraded entry for details.",
                err=True,
            )

    asyncio.run(dispatch_plan(ctx, lenses, boundary, loupe))
    _write_run_record(ctx, loupe, considered=lenses, cfg=cfg, scope=scope)

    # Mirror loupe ci's liveness contract: a crashed lens (lens_error
    # finding) must trip the gate even though scan has no fail_on/warn_on
    # severity gate of its own. Before this check, scans silently exited 0
    # on crashes — a scheduled scan in CI would never alert the operator
    # that ThreatLens died, the run record on disk being the only trace.
    liveness_failure = check_lens_liveness(ctx)
    if liveness_failure is not None:
        typer.echo(format_liveness_failure(liveness_failure), err=True)
        return 1

    typer.echo(f"Loupe scan complete. Run: {run_id} (scope={scope}).")
    typer.echo(f"Lenses run: {[p.lens_name for p in ctx.plan]}")
    return 0


class _ScopeAssemblyError(ValueError):
    """Raised when --paths input cannot be assembled into ScopedSources.

    Wraps the underlying reason (missing path, outside project root,
    boundary violation, unsupported extension) so scan_cmd can render
    one consistent exit-64 message.
    """


def _assemble_scoped_sources(
    *, paths: list[str], project_root: Path, max_chars: int
) -> list[ScopedSource]:
    """Walk --paths, filter, safe-read, truncate. Returns one ScopedSource per file.

    Per-path semantics:
    - Missing path → _ScopeAssemblyError ("not found under project root")
    - Path outside project_root → _ScopeAssemblyError
    - Single file with unsupported extension → _ScopeAssemblyError
    - Directory → recursively walk; include files whose extension is in
      CODE_EXTENSIONS; skip others silently (mirroring how grep-style
      tools handle directory expansion)

    Per-file semantics:
    - Read via safe_read_under so symlinks and outside-root accesses are
      refused at the syscall layer
    - UTF-8 decode with errors='replace' so binary noise inside a code
      file doesn't crash the whole scan
    - Truncate at max_chars chars with a visible marker; ScopedSource
      carries truncated_at so the prompt can render the marker too
    """
    sources: list[ScopedSource] = []
    # Read up to 4x the char cap from disk to allow for UTF-8 multibyte
    # expansion. The actual cap is applied to the decoded string.
    max_bytes = max(max_chars * 4, max_chars + 1)

    for entry in paths:
        resolved = Path(entry)
        if not resolved.is_absolute():
            resolved = (project_root / resolved).resolve(strict=False)
        else:
            resolved = resolved.resolve(strict=False)

        try:
            resolved.relative_to(project_root)
        except ValueError as exc:
            raise _ScopeAssemblyError(
                f"path {entry!r} resolves outside project root {str(project_root)!r}"
            ) from exc

        if not resolved.exists():
            raise _ScopeAssemblyError(f"path {entry!r} not found under project root")

        if resolved.is_dir():
            for child in sorted(resolved.rglob("*")):
                if not child.is_file():
                    continue
                if not child.name.endswith(CODE_EXTENSIONS):
                    continue
                sources.append(_read_one(child, project_root, max_chars, max_bytes))
        elif resolved.is_file():
            if not resolved.name.endswith(CODE_EXTENSIONS):
                raise _ScopeAssemblyError(
                    f"path {entry!r} has unsupported extension; "
                    f"see CODE_EXTENSIONS in loupe_core.fs for the allow-list"
                )
            sources.append(_read_one(resolved, project_root, max_chars, max_bytes))
        else:
            raise _ScopeAssemblyError(f"path {entry!r} is neither a regular file nor a directory")

    return sources


def _read_one(file_path: Path, project_root: Path, max_chars: int, max_bytes: int) -> ScopedSource:
    """Read one file via safe_read_under (truncate mode), decode, build ScopedSource."""
    try:
        raw = safe_read_under(
            project_root=project_root,
            target=file_path,
            max_bytes=max_bytes,
            on_oversize="truncate",
        )
    except BoundaryViolation as exc:
        raise _ScopeAssemblyError(str(exc)) from exc

    text = raw.decode("utf-8", errors="replace")
    rel_path = file_path.relative_to(project_root).as_posix()
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n\n... [truncated at {max_chars} chars]\n"
        return ScopedSource(path=rel_path, content=text, truncated_at=max_chars)
    return ScopedSource(path=rel_path, content=text, truncated_at=None)


def _planned_lenses(lenses: list[Lens], ctx: RunContext) -> list[Lens]:
    """Filter discovered lenses to those actually in the run plan.

    Mirror of ci_cmd._planned_lenses — kept duplicated for now rather than
    extracted, because there's no third caller yet (D-21: extract on the
    third instance, not the second).
    """
    planned_names = {p.lens_name for p in ctx.plan}
    return [lens for lens in lenses if lens.capabilities.name in planned_names]


def _write_run_record(
    ctx: RunContext,
    loupe_dir: Path,
    *,
    considered: list[Lens],
    cfg: LoupeConfig,
    scope: str,
) -> None:
    """Delegate to `build_run_record` with scan-mode origin parameters.

    `cfg` is unused today; kept in the signature for symmetry with
    `ci_cmd._write_run_record` and for future gate-logic wiring.
    """
    del cfg
    build_run_record(
        ctx=ctx,
        loupe_dir=loupe_dir,
        considered=considered,
        trigger=f"manual_scan_{scope}",
        base_sha=None,
        head_sha=None,
        diff_hash=hashlib.sha256(b"").hexdigest(),
    )
