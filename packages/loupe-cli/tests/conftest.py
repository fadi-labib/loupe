"""Shared fixtures for loupe-cli tests.

CLI tests exercise the command boundary (argv → ci_command → run record),
not the dispatch + lens layer. The dispatcher is exercised separately in
loupe-core's own test suite, and lens internals are covered by VCR-based
integration tests in each lens package. Patching dispatch_plan to a no-op
keeps CLI tests fast and focussed on coordination logic.
"""

from __future__ import annotations

import pytest


async def _noop_dispatch(ctx, lenses, boundary, loupe_dir):  # noqa: ANN001 — matches dispatch_plan signature
    """Stand-in for `loupe_core.dispatcher.dispatch_plan` used by CLI tests."""
    return None


async def _noop_bootstrap(**kwargs):  # noqa: ANN003 — matches bootstrap_capabilities signature
    """Stand-in for `loupe_core.capabilities.bootstrap.bootstrap_capabilities`.

    Returns empty degradation list so the post-D-23 CLI flow proceeds as
    if every capability bootstrapped successfully. Tests that exercise
    the capability policy (required-miss → exit 64, preferred-miss →
    record degradation) override this with the real implementation.
    """
    return []


@pytest.fixture(autouse=True)
def stub_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch every CLI module's reference to `dispatch_plan` to a no-op.

    Both `ci_cmd` and `scan_cmd` do `from loupe_core.dispatcher import dispatch_plan`,
    binding the symbol locally — so the test must patch each binding rather
    than the source module. The list grows when a new command-module imports
    the dispatcher.
    """
    for target in (
        "loupe_cli.ci_cmd.dispatch_plan",
        "loupe_cli.scan_cmd.dispatch_plan",
    ):
        monkeypatch.setattr(target, _noop_dispatch)


@pytest.fixture(autouse=True)
def stub_bootstrap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch CLI bindings of `bootstrap_capabilities` to a no-op.

    Existing CLI tests use minimal configs without a `capabilities:`
    block — under D-23 enforcement, the real bootstrap would raise
    RequiredCapabilityUnavailable (ThreatLens requires sbom + cve) and
    the CLI would exit 64. The tests in this package don't exercise
    capability bootstrap; they test coordination logic around it.
    Stubbing the call to return an empty degradation list lets those
    tests stay focussed.

    Tests in test_ci_capability_policy.py (and test_scan_capability_policy.py)
    override this with the real implementation to exercise the policy
    itself.
    """
    for target in (
        "loupe_cli.ci_cmd.bootstrap_capabilities",
        "loupe_cli.scan_cmd.bootstrap_capabilities",
    ):
        monkeypatch.setattr(target, _noop_bootstrap)


# ---------------------------------------------------------------------------
# Shared minimal-config builders
# ---------------------------------------------------------------------------


_BASE_CONFIG = (
    "schema_version: 1\n"
    "models:\n  default: anthropic:claude-opus-4-7\n"
    "limits:\n"
    "  per_run_max_usd: 1.0\n"
    "  per_run_max_tokens_in: 100000\n"
    "  per_run_max_steps: 5\n"
)


def minimal_config_yaml(
    *,
    agent_writable_paths: list[str] | None = None,
    threatlens_enabled: bool = True,
    threatlens_min_relevance: float = 0.3,
) -> str:
    """Build a minimal but valid `config.yaml` body for CLI tests.

    Parameters mirror the small handful of knobs that tests actually vary —
    everything else is held at sensible defaults. Adding a new test that
    needs a config shape outside these levers should NOT extend this
    function; write the YAML inline in that test instead. Configuration
    matrix expansion is what makes shared builders rot.
    """
    paths = agent_writable_paths or [".loupe/threats.yaml", ".loupe/runs/**"]
    paths_yaml = "[" + ", ".join(paths) + "]"
    return (
        _BASE_CONFIG
        + f"agent_writable_paths: {paths_yaml}\n"
        + "lenses:\n"
        + "  threatlens:\n"
        + f"    enabled: {'true' if threatlens_enabled else 'false'}\n"
        + f"    minimum_relevance: {threatlens_min_relevance}\n"
    )
