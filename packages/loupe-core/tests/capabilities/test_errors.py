from __future__ import annotations

import pytest
from loupe_core.capabilities.errors import (
    BackendError,
    CapabilityError,
    CapabilityNotFoundError,
    NoBackendsConfiguredError,
)


def test_all_errors_inherit_from_capability_error():
    assert issubclass(CapabilityNotFoundError, CapabilityError)
    assert issubclass(BackendError, CapabilityError)
    assert issubclass(NoBackendsConfiguredError, CapabilityError)


def test_capability_error_inherits_from_runtime_error():
    # Caller can `except RuntimeError` and catch any capability failure
    # without knowing the hierarchy. Same convention as LensRegistryError.
    assert issubclass(CapabilityError, RuntimeError)


def test_backend_error_carries_backend_name():
    err = BackendError(backend_name="syft", message="binary not on PATH")
    assert err.backend_name == "syft"
    assert "syft" in str(err)
    assert "binary not on PATH" in str(err)


def test_capability_not_found_error_carries_name():
    err = CapabilityNotFoundError(capability="sbom")
    assert "sbom" in str(err)


def test_no_backends_configured_error_carries_capability():
    err = NoBackendsConfiguredError(capability="cve")
    assert "cve" in str(err)


def test_raising_and_catching_via_runtime_error():
    with pytest.raises(RuntimeError):
        raise CapabilityNotFoundError(capability="anything")
