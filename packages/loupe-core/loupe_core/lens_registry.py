from __future__ import annotations
from importlib.metadata import entry_points
from loupe_core.lens_api import Lens


class LensRegistryError(RuntimeError):
    pass


def _entry_points(group: str):
    return entry_points(group=group)


def discover_lenses() -> list[Lens]:
    lenses: list[Lens] = []
    for ep in _entry_points(group="loupe.lenses"):
        cls = ep.load()
        instance = cls()
        lenses.append(instance)
    _check_artifact_path_conflicts(lenses)
    return lenses


def _check_artifact_path_conflicts(lenses: list[Lens]) -> None:
    seen: dict[str, str] = {}
    for lens in lenses:
        for path in lens.capabilities.artifact_paths:
            if path in seen and seen[path] != lens.capabilities.name:
                raise LensRegistryError(
                    f"Lens conflict: '{lens.capabilities.name}' and '{seen[path]}' "
                    f"both claim artifact path '{path}'. Uninstall one."
                )
            seen[path] = lens.capabilities.name
