from __future__ import annotations

from collections import defaultdict
from importlib.metadata import EntryPoints, entry_points

from loupe_core.lens_api import Lens


class LensRegistryError(RuntimeError):
    pass


def _entry_points(group: str) -> EntryPoints:
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
    """Raise if two or more lenses claim ownership of the same artefact path.

    Accumulates ALL conflicts before raising so the operator sees every
    triple/N-way collision in one error, not just the first pair that trips
    the check. The previous implementation set `seen[path] = name` AFTER the
    raise, leaving the side-effect dead and silently masking three-way
    conflicts (the 2nd lens raised; the 3rd was never compared).
    """
    owners: dict[str, list[str]] = defaultdict(list)
    for lens in lenses:
        for path in lens.capabilities.artifact_paths:
            owners[path].append(lens.capabilities.name)
    conflicts = {
        path: names for path, names in owners.items() if len(set(names)) > 1
    }
    if conflicts:
        rendered = "; ".join(
            f"{path!r} claimed by {sorted(set(names))}"
            for path, names in sorted(conflicts.items())
        )
        raise LensRegistryError(
            f"artefact-path conflicts: {rendered}. Uninstall all but one."
        )
