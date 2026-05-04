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
from loupe_core.config import LoupeConfig, load_config
from loupe_core.lens_registry import discover_lenses

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

    status: Literal["ok", "fail", "warn", "skip"]
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


_DEFAULT_PROVIDER = "anthropic:claude-opus-4-7"


def _run_checks(loupe: Path) -> list[CheckResult]:
    """Run the full check battery, returning one row per check.

    Pre-F-06: a missing `.loupe/` short-circuited the function and the
    operator never learned whether their API key was set or whether
    Syft / Grype were on PATH. The full picture only became visible
    after running `loupe init`, which defeated the point of doctor
    as a preflight tool.

    Post-F-06: every check runs to completion. Checks that depend on
    an earlier check's invariant (e.g. config-yaml-parsed before
    cap-binary-on-PATH) emit a ``skip`` row when the prerequisite
    failed. Exit code is `fail`-driven; `skip` rows are advisory and
    don't change the verdict, but they show up in the table so the
    operator can plan the full remediation in one read.
    """
    results: list[CheckResult] = []

    # Check 1: .loupe/ exists.
    loupe_exists = loupe.exists()
    if loupe_exists:
        results.append(CheckResult(status="ok", label=".loupe/ directory", detail=str(loupe)))
    else:
        results.append(
            CheckResult(
                status="fail",
                label=".loupe/ directory",
                detail=f"{loupe} not found — run `loupe init` first",
            )
        )

    # Check 2: config.yaml parses (skipped if .loupe/ missing).
    cfg = None
    if not loupe_exists:
        results.append(
            CheckResult(
                status="skip",
                label="config.yaml parse",
                detail="skipped — depends on .loupe/ existing",
            )
        )
    else:
        config_path = loupe / "config.yaml"
        try:
            cfg = load_config(config_path)
            results.append(
                CheckResult(
                    status="ok",
                    label="config.yaml parse",
                    detail=f"schema_version={cfg.schema_version}",
                )
            )
        except Exception as exc:  # noqa: BLE001 — config errors come in many shapes
            results.append(
                CheckResult(
                    status="fail",
                    label="config.yaml parse",
                    detail=f"{type(exc).__name__}: {exc}",
                )
            )

    # Check 3: context.md edited (skipped if .loupe/ missing).
    if loupe_exists:
        results.append(_check_context_md(loupe / "context.md"))
    else:
        results.append(
            CheckResult(
                status="skip",
                label="context.md",
                detail="skipped — depends on .loupe/ existing",
            )
        )

    # Check 4: provider env var. Falls back to the scaffold default
    # model id when config didn't parse, so the user still sees
    # whether their ANTHROPIC_API_KEY (or equivalent) is set —
    # F-06's whole point is that an unparsed config doesn't blind
    # the rest of the preflight.
    default_model = cfg.models.default if cfg is not None else _DEFAULT_PROVIDER
    results.append(_check_provider_env_var(default_model))

    # Check 5: required capabilities wired (D-23 / A.10).
    # Skipped if we don't have a parsed config to read lens activations from.
    if cfg is None:
        results.append(
            CheckResult(
                status="skip",
                label="required capabilities",
                detail="skipped — config.yaml didn't parse",
            )
        )
    else:
        results.extend(_check_required_capabilities_wired(cfg))

    # Check 6: capability binaries on PATH (skipped if no capabilities configured).
    if cfg is not None and cfg.capabilities:
        registry = CapabilityRegistry.discover()
        for cap_name, activation in sorted(cfg.capabilities.items()):
            for backend in activation.backends:
                results.append(_check_backend_binary(registry, cap_name, backend))

    return results


def _check_required_capabilities_wired(cfg: LoupeConfig) -> list[CheckResult]:
    """Match every enabled lens's requires_capabilities against cfg.capabilities.

    Returns one CheckResult per unwired required cap (each a `fail`), or a
    single `ok` row when every required cap has a non-empty backends list.
    Returns nothing when no enabled lens has any required capabilities —
    Check 6 will then handle whatever the operator wired anyway.
    """
    enabled_lens_names = {name for name, lc in cfg.lenses.items() if lc.enabled}
    if not enabled_lens_names:
        return []

    discovered = discover_lenses()
    planned_lenses = [lens for lens in discovered if lens.capabilities.name in enabled_lens_names]

    required_pairs: list[tuple[str, str]] = []
    for lens in planned_lenses:
        for cap in lens.capabilities.requires_capabilities:
            required_pairs.append((lens.capabilities.name, cap))

    if not required_pairs:
        return []

    unwired: list[CheckResult] = []
    for lens_name, cap in required_pairs:
        activation = cfg.capabilities.get(cap)
        if activation is None or not activation.backends:
            unwired.append(
                CheckResult(
                    status="fail",
                    label=f"capabilities[{cap}]",
                    detail=(
                        f"lens '{lens_name}' requires '{cap}' but no backends are wired "
                        f"in config.yaml. Uncomment the `capabilities:` block in "
                        f"`.loupe/config.yaml` and install the backend; `loupe ci` exits "
                        f"64 otherwise."
                    ),
                )
            )
    if unwired:
        return unwired
    # All required caps are wired — emit a single happy-path row so the
    # output explicitly shows the check ran and passed (avoid silent green).
    return [
        CheckResult(
            status="ok",
            label="required capabilities",
            detail=f"{len(required_pairs)} required cap(s) wired across enabled lenses",
        )
    ]


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
    sigils = {"ok": "✓", "fail": "✗", "warn": "?", "skip": "-"}
    for r in results:
        typer.echo(f"[{sigils[r.status]}] {r.label}: {r.detail}")
    # Trailing summary line — distinguishes the failure case from a
    # silent passthrough when no checks ran.
    n_ok = sum(1 for r in results if r.status == "ok")
    n_fail = sum(1 for r in results if r.status == "fail")
    n_warn = sum(1 for r in results if r.status == "warn")
    n_skip = sum(1 for r in results if r.status == "skip")
    typer.echo(f"\n{n_ok} ok · {n_warn} warn · {n_skip} skip · {n_fail} fail")
