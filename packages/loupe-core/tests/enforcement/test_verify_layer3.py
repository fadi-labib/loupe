"""Tests for the Phase-7.3 Layer 3 verify checks.

Schema consistency, threats-to-mitigations cross-references, protected-
path authorship — each has its own test. Hash-chain has separate
existing coverage in test_verify.py.
"""
from __future__ import annotations

import subprocess
from datetime import date
from pathlib import Path

from loupe_core.artifacts.mitigation import Evidence, Mitigation, MitigationsFile
from loupe_core.artifacts.threat import Threat, ThreatsFile
from loupe_core.artifacts.types import (
    MitigationStatus,
    Severity,
    StrideCategory,
    ThreatStatus,
)
from loupe_core.enforcement.verify import (
    check_artefact_schemas,
    check_protected_path_authorship,
    check_threats_mitigations_cross_refs,
    verify_repo,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_loupe_dir(tmp_path: Path) -> Path:
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    (loupe / "runs").mkdir()
    return loupe


def _threat(id_: str = "T-001", mitigation_ids: list[str] | None = None) -> Threat:
    return Threat(
        id=id_, element_id="E-001",
        stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        title="Sample", description="Sample description.",
        severity=Severity.HIGH, status=ThreatStatus.PROPOSED,
        mitigation_ids=mitigation_ids or [], cwe_refs=[],
        introduced_in_pr=None, last_reviewed=date(2026, 5, 15),
        rationale="Sample rationale.", proposed_by="test",
    )


def _mitigation(id_: str = "M-001", threats_addressed: list[str] | None = None) -> Mitigation:
    return Mitigation(
        id=id_, title="Sample mitigation",
        description="Sample description.",
        threats_addressed=threats_addressed or [],
        status=MitigationStatus.PLANNED,
        evidence=[Evidence(kind="code", location="src/x.py")],
    )


# ---------------------------------------------------------------------------
# Schema consistency
# ---------------------------------------------------------------------------


def test_schema_check_passes_on_valid_artefacts(tmp_path):
    loupe = _make_loupe_dir(tmp_path)
    ThreatsFile(threats=[_threat()]).save(loupe / "threats.yaml")
    MitigationsFile(mitigations=[_mitigation()]).save(loupe / "mitigations.yaml")
    assert check_artefact_schemas(loupe) == []


def test_schema_check_skips_missing_files(tmp_path):
    """If neither artefact exists yet, the schema check passes."""
    loupe = _make_loupe_dir(tmp_path)
    assert check_artefact_schemas(loupe) == []


def test_schema_check_fails_on_broken_threats_yaml(tmp_path):
    loupe = _make_loupe_dir(tmp_path)
    (loupe / "threats.yaml").write_text(
        "schema_version: 1\nthreats:\n  - id: NOT_VALID_ID_FORMAT\n"
    )
    failures = check_artefact_schemas(loupe)
    assert len(failures) == 1
    assert failures[0].kind == "schema_invalid"
    assert "threats.yaml" in failures[0].detail


def test_schema_check_fails_on_broken_mitigations_yaml(tmp_path):
    loupe = _make_loupe_dir(tmp_path)
    (loupe / "mitigations.yaml").write_text(
        "schema_version: 1\nmitigations:\n  - this is garbage\n"
    )
    failures = check_artefact_schemas(loupe)
    assert any(f.kind == "schema_invalid" and "mitigations" in f.detail for f in failures)


# ---------------------------------------------------------------------------
# Threats <-> mitigations cross-references
# ---------------------------------------------------------------------------


def test_xref_check_passes_when_all_references_resolve(tmp_path):
    loupe = _make_loupe_dir(tmp_path)
    ThreatsFile(threats=[_threat(mitigation_ids=["M-001"])]).save(
        loupe / "threats.yaml"
    )
    MitigationsFile(mitigations=[_mitigation(threats_addressed=["T-001"])]).save(
        loupe / "mitigations.yaml"
    )
    assert check_threats_mitigations_cross_refs(loupe) == []


def test_xref_check_skips_if_files_absent(tmp_path):
    loupe = _make_loupe_dir(tmp_path)
    assert check_threats_mitigations_cross_refs(loupe) == []


def test_xref_check_catches_dangling_mitigation_id_on_threat(tmp_path):
    # The dangling ID must be valid `M-NNN` format (enforced at parse time);
    # the Layer 3 check separately confirms the referenced mitigation exists.
    loupe = _make_loupe_dir(tmp_path)
    ThreatsFile(threats=[_threat(mitigation_ids=["M-999"])]).save(
        loupe / "threats.yaml"
    )
    MitigationsFile(mitigations=[_mitigation()]).save(loupe / "mitigations.yaml")
    failures = check_threats_mitigations_cross_refs(loupe)
    assert len(failures) == 1
    assert failures[0].kind == "dangling_mitigation_ref"
    assert "M-999" in failures[0].detail


def test_xref_check_catches_dangling_threat_id_on_mitigation(tmp_path):
    # The dangling ID must be valid `T-NNN` format (enforced at parse time);
    # the Layer 3 check separately confirms the referenced threat exists.
    loupe = _make_loupe_dir(tmp_path)
    ThreatsFile(threats=[_threat()]).save(loupe / "threats.yaml")
    MitigationsFile(
        mitigations=[_mitigation(threats_addressed=["T-999"])]
    ).save(loupe / "mitigations.yaml")
    failures = check_threats_mitigations_cross_refs(loupe)
    assert len(failures) == 1
    assert failures[0].kind == "dangling_threat_ref"
    assert "T-999" in failures[0].detail


# ---------------------------------------------------------------------------
# Strict-only: protected-path authorship
# ---------------------------------------------------------------------------


def _init_git_repo(tmp_path: Path, author_name: str, author_email: str) -> None:
    """Initialise a throwaway git repo for authorship tests."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", author_email], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", author_name], cwd=tmp_path, check=True)


def _commit_file(repo: Path, rel_path: str, content: str, message: str) -> None:
    (repo / rel_path).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel_path).write_text(content)
    subprocess.run(["git", "add", rel_path], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", message, "--no-gpg-sign"],
        cwd=repo, check=True,
    )


def test_authorship_check_passes_for_human_author(tmp_path):
    _init_git_repo(tmp_path, "Alice", "alice@example.com")
    _make_loupe_dir(tmp_path)
    _commit_file(tmp_path, ".loupe/context.md", "# context", "init context")
    assert check_protected_path_authorship(tmp_path) == []


def test_authorship_check_flags_bot_author(tmp_path):
    """An author email ending in @bots.local trips the conservative pattern."""
    _init_git_repo(tmp_path, "Bot", "ci-bot@bots.local")
    _make_loupe_dir(tmp_path)
    _commit_file(tmp_path, ".loupe/context.md", "# context", "agent wrote this")
    failures = check_protected_path_authorship(tmp_path)
    assert len(failures) == 1
    assert failures[0].kind == "protected_path_agent_author"
    assert "context.md" in failures[0].detail


def test_authorship_check_flags_loupe_prefixed_author(tmp_path):
    """Author name starting with 'loupe-' is treated as agent."""
    _init_git_repo(tmp_path, "loupe-agent", "agent@example.com")
    _make_loupe_dir(tmp_path)
    _commit_file(tmp_path, ".loupe/config.yaml", "schema_version: 1\n", "agent edit")
    failures = check_protected_path_authorship(tmp_path)
    assert any(f.kind == "protected_path_agent_author" for f in failures)


def test_authorship_check_skips_uncommitted_files(tmp_path):
    """Files that exist on disk but have no git history are skipped silently."""
    _init_git_repo(tmp_path, "Alice", "alice@example.com")
    loupe = _make_loupe_dir(tmp_path)
    (loupe / "context.md").write_text("# uncommitted")
    # No commit — git log returns nothing → check returns no failures.
    assert check_protected_path_authorship(tmp_path) == []


def test_authorship_check_inspects_decisions_directory(tmp_path):
    _init_git_repo(tmp_path, "Bot", "ci-bot@bots.local")
    _make_loupe_dir(tmp_path)
    _commit_file(
        tmp_path,
        ".loupe/decisions/D-2026-05-15-test.md",
        "# decision",
        "agent wrote decision",
    )
    failures = check_protected_path_authorship(tmp_path)
    assert any("decisions/D-" in f.detail for f in failures)


# ---------------------------------------------------------------------------
# Top-level verify_repo composition
# ---------------------------------------------------------------------------


def test_verify_repo_runs_strict_checks_only_when_requested(tmp_path):
    """The default invocation skips protected-path authorship (needs git)."""
    _init_git_repo(tmp_path, "Bot", "ci-bot@bots.local")
    _make_loupe_dir(tmp_path)
    _commit_file(tmp_path, ".loupe/context.md", "# c", "agent wrote")

    # Default: no authorship check, so this passes despite the bot author.
    default_failures = verify_repo(tmp_path, strict=False)
    assert all(f.kind != "protected_path_agent_author" for f in default_failures)

    # Strict: authorship check fires.
    strict_failures = verify_repo(tmp_path, strict=True)
    assert any(f.kind == "protected_path_agent_author" for f in strict_failures)
