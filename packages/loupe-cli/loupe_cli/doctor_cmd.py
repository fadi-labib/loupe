"""`loupe doctor` — preflight diagnostics.

Runs a small battery of checks an operator typically discovers the
hard way:

1. `.loupe/` exists.
2. `.loupe/config.yaml` parses through `LoupeConfig`.
3. `.loupe/context.md` exists and has been edited (TODO markers below
   a soft threshold).
4. Provider env var for `models.default` is set.
5. For every configured capability backend, its CLI binary is on PATH.

Each check renders a `[✓]` / `[✗]` row with one-line detail. Exit 0
iff every required check passes; exit 64 otherwise (BSD sysexits.h
EX_USAGE — matches the rest of the CLI). Warnings (unknown provider,
optional binary missing) print `[?]` but do not change the exit code.

The command is intentionally read-only: it never writes to disk and
never invokes a backend's `run()` method, so it stays fast and is
safe to run inside CI as a preflight step.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import typer
from loupe_core.capabilities.registry import CapabilityRegistry
from loupe_core.config import load_config

# BSD sysexits.h EX_USAGE — operator-config / usage errors.
USAGE_ERROR = 64

# Map PydanticAI provider prefixes to the env var the SDK reads. None
# means the provider runs locally and needs no key (e.g., Ollama).
# Unknown providers don't fail the check — they print a `[?]` row.
_PROVIDER_ENV_VARS: dict[str, str | None] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "google-gla": "GOOGLE_API_KEY",
    "google-vertex": "GOOGLE_APPLICATION_CREDENTIALS",
    "groq": "GROQ_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "cohere": "COHERE_API_KEY",
    "ollama": None,
}

# Soft threshold for TODO markers in context.md. The scaffold ships
# with ~6 TODOs (one per required section). A user who has edited
# even a couple of sections is making progress and shouldn't be
# blocked; require the count to drop below this number to pass.
_TODO_THRESHOLD = 3


@dataclass(frozen=True)
class CheckResult:
    """One preflight-check outcome."""

    status: Literal["ok", "fail", "warn"]
    label: str
    detail: str


def doctor_command(loupe_dir: Path | None = None) -> int:
    """Run preflight checks and print a status table.

    Returns 0 if every check has status ``ok`` or ``warn``; returns
    64 (USAGE_ERROR) if any check failed. Warnings don't break the
    exit code — they're advisory ("we couldn't auto-verify this, but
    it might still work").
    """
    loupe = loupe_dir or (Path.cwd() / ".loupe")
    results = _run_checks(loupe)

    _render(results)

    has_failure = any(r.status == "fail" for r in results)
    return USAGE_ERROR if has_failure else 0


def _run_checks(loupe: Path) -> list[CheckResult]:
    """Run the full check battery in order.

    Each check builds on the previous one's invariants (e.g., the
    capability-binary check assumes config.yaml parsed), so a `fail`
    on an early check short-circuits later checks to ``warn`` —
    we can't meaningfully test capability binaries without a parsed
    config.
    """
    results: list[CheckResult] = []

    # Check 1: .loupe/ exists.
    if not loupe.exists():
        results.append(
            CheckResult(
                status="fail",
                label=".loupe/ directory",
                detail=f"{loupe} not found — run `loupe init` first",
            )
        )
        return results
    results.append(CheckResult(status="ok", label=".loupe/ directory", detail=str(loupe)))

    # Check 2: config.yaml parses.
    config_path = loupe / "config.yaml"
    try:
        cfg = load_config(config_path)
    except Exception as exc:  # noqa: BLE001 — config errors come in many shapes
        results.append(
            CheckResult(
                status="fail",
                label="config.yaml parse",
                detail=f"{type(exc).__name__}: {exc}",
            )
        )
        return results
    results.append(
        CheckResult(
            status="ok",
            label="config.yaml parse",
            detail=f"schema_version={cfg.schema_version}",
        )
    )

    # Check 3: context.md edited.
    results.append(_check_context_md(loupe / "context.md"))

    # Check 4: provider env var.
    results.append(_check_provider_env_var(cfg.models.default))

    # Check 5: capability binaries (skipped if no capabilities configured).
    if cfg.capabilities:
        registry = CapabilityRegistry.discover()
        for cap_name, activation in sorted(cfg.capabilities.items()):
            for backend in activation.backends:
                results.append(_check_backend_binary(registry, cap_name, backend))
    else:
        results.append(
            CheckResult(
                status="warn",
                label="capabilities",
                detail="no capabilities wired in config.yaml — see commented skeleton",
            )
        )

    return results


def _check_context_md(path: Path) -> CheckResult:
    """Count remaining TODO: markers; pass when below soft threshold."""
    if not path.exists():
        return CheckResult(
            status="fail",
            label="context.md",
            detail=f"{path} not found — required for agent grounding",
        )
    text = path.read_text()
    # Match the literal "TODO:" markers the init template ships with.
    # A bare "TODO" in product description prose is fine; we only
    # count the structured placeholders init created.
    todo_count = text.count("TODO:")
    if todo_count >= _TODO_THRESHOLD:
        return CheckResult(
            status="fail",
            label="context.md",
            detail=(
                f"{todo_count} TODO marker(s) remaining — fill in product context "
                "before running loupe ci (this is the anti-hallucination anchor)"
            ),
        )
    if todo_count > 0:
        return CheckResult(
            status="warn",
            label="context.md",
            detail=f"{todo_count} TODO marker(s) remaining; not blocking but worth completing",
        )
    return CheckResult(status="ok", label="context.md", detail="all sections filled")


def _check_provider_env_var(default_model: str) -> CheckResult:
    """Look up the env var for the provider prefix, then verify it's set."""
    # PydanticAI `provider:model` form — provider is everything before the first colon.
    provider = default_model.split(":", 1)[0]
    if provider not in _PROVIDER_ENV_VARS:
        return CheckResult(
            status="warn",
            label=f"provider key ({provider})",
            detail=(
                "unknown provider; cannot auto-check env var. "
                "Loupe will pass through whatever PydanticAI requires."
            ),
        )
    env_var = _PROVIDER_ENV_VARS[provider]
    if env_var is None:
        return CheckResult(
            status="ok",
            label=f"provider key ({provider})",
            detail="local provider — no key required",
        )
    if os.environ.get(env_var):
        return CheckResult(
            status="ok",
            label=f"provider key ({provider})",
            detail=f"{env_var} is set",
        )
    return CheckResult(
        status="fail",
        label=f"provider key ({provider})",
        detail=f"{env_var} is not set; `loupe ci` will record a lens_error and exit 1",
    )


def _check_backend_binary(
    registry: CapabilityRegistry, capability: str, backend: str
) -> CheckResult:
    """For each configured backend, confirm its CLI binary is on PATH.

    Convention: every bundled backend uses `shutil.which(backend_name)`
    as its own preflight, where ``backend_name`` is a class attribute
    that matches the entry-point name. We check the same binary here so
    doctor's verdict matches what the backend itself will do at run time.
    """
    label = f"backend {capability}.{backend}"
    try:
        cls = registry.get_backend_class(capability, backend)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            status="fail",
            label=label,
            detail=(
                f"backend not registered ({type(exc).__name__}). "
                f"Install the package providing {backend} or remove from config.yaml."
            ),
        )
    binary = getattr(cls, "backend_name", backend)
    if shutil.which(binary) is None:
        return CheckResult(
            status="fail",
            label=label,
            detail=f"binary {binary!r} not on PATH — install or remove from config.yaml",
        )
    return CheckResult(status="ok", label=label, detail=f"{binary} on PATH")


def _render(results: list[CheckResult]) -> None:
    """Print the results table to stdout.

    Stable, machine-greppable format: `[<sigil>] <label>: <detail>`.
    The sigils (✓/✗/?) are ASCII-only adjacent so a terminal without
    Unicode rendering still reads correctly.
    """
    sigils = {"ok": "✓", "fail": "✗", "warn": "?"}
    for r in results:
        typer.echo(f"[{sigils[r.status]}] {r.label}: {r.detail}")
    # Trailing summary line — distinguishes the failure case from a
    # silent passthrough when no checks ran.
    n_ok = sum(1 for r in results if r.status == "ok")
    n_fail = sum(1 for r in results if r.status == "fail")
    n_warn = sum(1 for r in results if r.status == "warn")
    typer.echo(f"\n{n_ok} ok · {n_warn} warn · {n_fail} fail")
