"""`loupe lens list` / `loupe cap list` — discovery subcommands.

Both enumerate Python entry points the workspace exposes:
- `loupe.lenses` — installed lens classes (one per package)
- `loupe.capabilities` — installed capability backend classes

Useful for operators verifying their install before running `loupe ci`,
and for the `loupe verify --strict` Layer-3 check that warns when a lens
the config references is not actually installed.
"""
from __future__ import annotations

import typer
from loupe_core.capabilities.registry import CapabilityRegistry
from loupe_core.lens_registry import discover_lenses


def lens_list_command() -> int:
    """Print one line per installed lens: `<name>  <domain>  [requires_capabilities]`."""
    lenses = discover_lenses()
    if not lenses:
        typer.echo("No lenses installed.")
        typer.echo(
            "Install one with: `uv pip install loupe-threatlens` "
            "(or any package that exposes a `loupe.lenses` entry point).",
            err=True,
        )
        return 0

    typer.echo(f"{'NAME':<16}{'DOMAIN':<12}REQUIRES")
    for lens in lenses:
        caps = lens.capabilities
        requires = ", ".join(getattr(caps, "requires_capabilities", []) or []) or "—"
        typer.echo(f"{caps.name:<16}{caps.domain:<12}{requires}")
    return 0


def cap_list_command() -> int:
    """Print backends grouped by capability category.

    Format: each capability gets a heading; backends list as one per line
    with the registered entry-point name and the Python dotted-path.
    """
    registry = CapabilityRegistry.discover()
    pairs = registry.list_all()

    if not pairs:
        typer.echo("No capability backends installed.")
        typer.echo(
            "Install one with: `uv pip install loupe-capabilities-essential` "
            "(or any package that exposes a `loupe.capabilities` entry point).",
            err=True,
        )
        return 0

    current_capability: str | None = None
    for capability, backend in pairs:
        if capability != current_capability:
            typer.echo(f"\n{capability}")
            current_capability = capability
        cls = registry.get_backend_class(capability, backend)
        dotted = f"{cls.__module__}:{cls.__qualname__}"
        typer.echo(f"  {backend:<16}{dotted}")
    return 0
