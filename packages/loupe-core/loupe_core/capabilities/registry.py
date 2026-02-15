from __future__ import annotations

from collections import defaultdict
from importlib.metadata import EntryPoints, entry_points
from typing import Any

from loupe_core.capabilities.errors import (
    CapabilityNotFoundError,
    NoBackendsConfiguredError,
)

_GROUP = "loupe.capabilities"


def _entry_points(group: str) -> EntryPoints:
    return entry_points(group=group)


class CapabilityRegistry:
    """Holds the (capability, backend_name) -> backend class index.

    The registry never imports a specific backend by name; it only
    knows what got registered via entry points. That's what makes
    Loupe genuinely tool-agnostic — adding a new SBOM tool means
    publishing a package and declaring its entry point, never
    editing core.
    """

    def __init__(self, backends: dict[str, dict[str, type]]) -> None:
        self._backends = backends

    @classmethod
    def discover(cls) -> CapabilityRegistry:
        backends: dict[str, dict[str, type]] = defaultdict(dict)
        for ep in _entry_points(group=_GROUP):
            cls_ref = ep.load()
            # The entry-point name IS the backend name (e.g., "syft", "trivy").
            # The class's `name` attribute carries the capability category
            # (e.g., "sbom", "cve"). This dual-axis keying lets multiple
            # backends register under the same capability name.
            capability = getattr(cls_ref, "name", None)
            if capability is None:
                raise CapabilityNotFoundError(
                    f"entry-point '{ep.name}' loaded a class without a `name` attribute"
                )
            backends[capability][ep.name] = cls_ref
        return cls(dict(backends))

    def list_backends(self, capability: str) -> list[str]:
        return sorted(self._backends.get(capability, {}).keys())

    def resolve(self, *, capability: str, backend_names: list[str]) -> list[Any]:
        """Return instantiated backends in the order requested.

        Raises:
            NoBackendsConfiguredError: ``backend_names`` is empty.
            CapabilityNotFoundError: the capability or a named backend is unknown.
        """
        if not backend_names:
            raise NoBackendsConfiguredError(capability=capability)
        if capability not in self._backends:
            raise CapabilityNotFoundError(capability=capability)
        instances: list[Any] = []
        registered = self._backends[capability]
        for name in backend_names:
            if name not in registered:
                raise CapabilityNotFoundError(
                    f"capability '{capability}' has no backend named '{name}' "
                    f"(registered: {sorted(registered)})"
                )
            instance = registered[name]()
            # Annotate the instance with its registry name so callers can
            # tell which backend produced a given result.
            if not hasattr(instance, "backend_name") or not instance.backend_name:
                instance.backend_name = name
            instances.append(instance)
        return instances
