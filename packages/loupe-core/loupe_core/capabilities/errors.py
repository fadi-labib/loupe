from __future__ import annotations


class CapabilityError(RuntimeError):
    """Base for everything that can go wrong in the capability layer."""


class CapabilityNotFoundError(CapabilityError):
    def __init__(self, capability: str) -> None:
        super().__init__(f"No backend registered for capability '{capability}'")
        self.capability = capability


class NoBackendsConfiguredError(CapabilityError):
    def __init__(self, capability: str) -> None:
        super().__init__(
            f"Capability '{capability}' is required but no backends are configured "
            f"in config.yaml under `capabilities.{capability}.backends`."
        )
        self.capability = capability


class BackendError(CapabilityError):
    def __init__(self, *, backend_name: str, message: str) -> None:
        super().__init__(f"backend '{backend_name}' failed: {message}")
        self.backend_name = backend_name
        self.message = message
