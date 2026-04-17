from __future__ import annotations

from collections import defaultdict
from importlib.metadata import EntryPoints, entry_points
from typing import Any

from loupe_core.capabilities.errors import (
    CapabilityNotFoundError,
    EntryPointMalformedError,
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
                # A class registered under loupe.capabilities MUST carry a
                # `name` attribute identifying its capability category
                # (sbom, cve, ...). That this loaded class lacks one is a
                # packaging defect — not a missing-backend condition — so
                # surface a distinct error type. Loadable entry-points
                # without `name` are bugs, not misconfiguration.
                raise EntryPointMalformedError(
                    entry_point_name=ep.name,
                    reason="loaded class is missing required `name` attribute",
                )
            backends[capability][ep.name] = cls_ref
        return cls(dict(backends))

    def list_backends(self, capability: str) -> list[str]:
        return sorted(self._backends.get(capability, {}).keys())

    def list_all(self) -> list[tuple[str, str]]:
        """Return every registered (capability, backend) pair, sorted.

        Public read-only enumeration helper for discovery surfaces (CLI
        `loupe cap list`, the `verify --strict` install-vs-config check).
        Returns capability-first ordering: all sbom backends, then all
        cve backends, etc. Both inner orderings are alphabetical so the
        output is stable across runs.
        """
        pairs: list[tuple[str, str]] = []
        for capability in sorted(self._backends):
            for backend in sorted(self._backends[capability]):
                pairs.append((capability, backend))
        return pairs

    def get_backend_class(self, capability: str, backend: str) -> type:
        """Return the registered backend class for display / introspection.

        Read-only counterpart to ``resolve()`` — does NOT instantiate. Used
        by ``loupe cap list`` to surface the Python dotted path so operators
        can debug imports without running the backend.

        Raises:
            CapabilityNotFoundError: capability or backend is unknown.
        """
        if capability not in self._backends:
            raise CapabilityNotFoundError(capability=capability)
        registered = self._backends[capability]
        if backend not in registered:
            raise CapabilityNotFoundError(
                f"capability '{capability}' has no backend named '{backend}' "
                f"(registered: {sorted(registered)})"
            )
        return registered[backend]

    def resolve(
        self,
        *,
        capability: str,
        backend_names: list[str],
        options: dict[str, str] | None = None,
    ) -> list[Any]:
        """Return instantiated backends in the order requested.

        ``options`` (from ``CapabilityActivation.options``) is attached to
        each instance as ``.options`` so backend implementations that opt
        into typed configuration (e.g., CodeQL's ``database_path``) can
        read it without consulting environment variables.

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
            # Hand the operator's per-capability options to the instance.
            # Backends that don't care silently ignore the attribute.
            instance.options = dict(options) if options else {}
            instances.append(instance)
        return instances
