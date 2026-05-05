"""Tests for the Phase-7.3 Layer 3 verify checks.

Schema consistency, threats-to-mitigations cross-references, protected-
path authorship — each has its own test. Hash-chain has separate
existing coverage in test_verify.py.
"""

from __future__ import annotations

import os
import subprocess
from datetime import date
from pathlib import Path

from loupe_core.artifacts.mitigation import Evidence, Mitigation, MitigationsFile
from loupe_core.artifacts.run_record import RunRecord
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


def _git_isolated_env(repo: Path) -> dict[str, str]:
    """Build a `git` env that ignores the operator's global / system config.

    Layer-3 authorship checks read author identity from `git log`. If the
    operator's `~/.gitconfig` sets `commit.gpgsign=true`, an `includeIf` block,
    a global `user.email`, or a non-empty `core.hooksPath`, those side-channels
    leak into our test commits and produce mysterious failures only on certain
    workstations. Isolate `git` from every external config source.

    `GIT_CONFIG_GLOBAL=/dev/null` and `GIT_CONFIG_SYSTEM=/dev/null` cover
    explicit config files; redirecting `HOME` and `XDG_CONFIG_HOME` under
    the temp tree neutralises any path-aware include resolution.
    """
    env = os.environ.copy()
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    env["GIT_CONFIG_SYSTEM"] = "/dev/null"
    # Deterministic timestamps make the authorship checks read the same
    # commit metadata everywhere this test runs.
    env["GIT_AUTHOR_DATE"] = "2026-05-15T12:00:00+00:00"
    env["GIT_COMMITTER_DATE"] = "2026-05-15T12:00:00+00:00"
    fake_home = repo / "_test_home"
    fake_home.mkdir(parents=True, exist_ok=True)
    env["HOME"] = str(fake_home)
    env["XDG_CONFIG_HOME"] = str(fake_home / ".config")
    return env


def _make_loupe_dir(tmp_path: Path) -> Path:
    loupe = tmp_path / ".loupe"
    loupe.mkdir()
    (loupe / "runs").mkdir()
    return loupe


def _threat(id_: str = "T-001", mitigation_ids: list[str] | None = None) -> Threat:
    return Threat(
        id=id_,
        element_id="E-001",
        stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        title="Sample",
        description="Sample description.",
        severity=Severity.HIGH,
        status=ThreatStatus.PROPOSED,
        mitigation_ids=mitigation_ids or [],
        cwe_refs=[],
        introduced_in_pr=None,
        last_reviewed=date(2026, 5, 15),
        rationale="Sample rationale.",
        proposed_by="test",
    )


def _mitigation(id_: str = "M-001", threats_addressed: list[str] | None = None) -> Mitigation:
    return Mitigation(
        id=id_,
        title="Sample mitigation",
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
    ThreatsFile(threats=[_threat(mitigation_ids=["M-001"])]).save(loupe / "threats.yaml")
    MitigationsFile(mitigations=[_mitigation(threats_addressed=["T-001"])]).save(
        loupe / "mitigations.yaml"
    )
    assert check_threats_mitigations_cross_refs(loupe) == []


def test_xref_check_skips_if_files_absent(tmp_path):
    loupe = _make_loupe_dir(tmp_path)
    assert check_threats_mitigations_cross_refs(loupe) == []


def test_xref_check_silently_skips_on_corrupt_yaml(tmp_path):
    """The schema check is responsible for surfacing parse / schema
    failures; the cross-ref check must not double-report — but it also
    must not swallow programming errors that happen to look like
    BaseException. Phase 7 narrowed the broad `except Exception` to
    `except (YAMLError, ValidationError)`."""
    loupe = _make_loupe_dir(tmp_path)
    (loupe / "threats.yaml").write_text("threats: [\n  - id: 'unterminated")
    MitigationsFile(mitigations=[_mitigation()]).save(loupe / "mitigations.yaml")
    # Corrupt YAML → cross-ref returns empty (schema check will report it).
    assert check_threats_mitigations_cross_refs(loupe) == []


def test_xref_check_catches_dangling_mitigation_id_on_threat(tmp_path):
    # The dangling ID must be valid `M-NNN` format (enforced at parse time);
    # the Layer 3 check separately confirms the referenced mitigation exists.
    loupe = _make_loupe_dir(tmp_path)
    ThreatsFile(threats=[_threat(mitigation_ids=["M-999"])]).save(loupe / "threats.yaml")
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
    MitigationsFile(mitigations=[_mitigation(threats_addressed=["T-999"])]).save(
        loupe / "mitigations.yaml"
    )
    failures = check_threats_mitigations_cross_refs(loupe)
    assert len(failures) == 1
    assert failures[0].kind == "dangling_threat_ref"
    assert "T-999" in failures[0].detail


# ---------------------------------------------------------------------------
# Strict-only: protected-path authorship
# ---------------------------------------------------------------------------


def _init_git_repo(tmp_path: Path, author_name: str, author_email: str) -> None:
    """Initialise a throwaway git repo for authorship tests, isolated from operator config."""
    env = _git_isolated_env(tmp_path)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True, env=env)
    subprocess.run(
        ["git", "config", "user.email", author_email],
        cwd=tmp_path,
        check=True,
        env=env,
    )
    subprocess.run(
        ["git", "config", "user.name", author_name],
        cwd=tmp_path,
        check=True,
        env=env,
    )
    # GPG signing is the most common operator-config leak: a global
    # `commit.gpgsign=true` would force `git commit` to attempt signing
    # even with `--no-gpg-sign` if signingkey is missing in some configs.
    # Override at the repo level too.
    subprocess.run(
        ["git", "config", "commit.gpgsign", "false"],
        cwd=tmp_path,
        check=True,
        env=env,
    )


def _commit_file(repo: Path, rel_path: str, content: str, message: str) -> None:
    (repo / rel_path).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel_path).write_text(content)
    env = _git_isolated_env(repo)
    subprocess.run(["git", "add", rel_path], cwd=repo, check=True, env=env)
    subprocess.run(
        ["git", "commit", "-q", "-m", message, "--no-gpg-sign"],
        cwd=repo,
        check=True,
        env=env,
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


# ---------------------------------------------------------------------------
# Merkle root consistency (D-25)
# ---------------------------------------------------------------------------


class TestCheckArtefactsMerkleRoot:
    """Layer-3 default check added in D-25: stored artifacts_merkle_root
    must equal the root recomputed from artifact_hashes. Records with
    empty hashes / null root are skipped (legacy or no-artefact runs)."""

    def _record_with_hashes(self, hashes: dict[str, str], *, prev: str | None = None) -> RunRecord:
        """Build a record carrying the given artefact hashes."""
        from datetime import UTC, datetime

        return RunRecord(
            run_id=f"run-merkle-{len(hashes)}-{prev or 'first'}",
            timestamp=datetime.now(UTC),
            mode="ci",
            invoked_by="test@example.com",
            trigger="manual_ci",
            base_sha=None,
            head_sha=None,
            diff_hash="0" * 64,
            context_md_hash="0" * 64,
            lenses_considered=[],
            lenses_run=[],
            models_used={},
            total_tokens_in=0,
            total_tokens_out=0,
            cost_usd_estimate=0.0,
            cache_hit_rate=None,
            artifacts_changed=sorted(hashes),
            proposed_patches=[],
            pending_decisions=[],
            prev_run_hash=prev,
            self_hash="",
            artifact_hashes=hashes,
        )

    def test_matching_root_passes(self, tmp_path):
        from loupe_core.artifacts.run_record import save_run_record
        from loupe_core.enforcement.verify import check_artefacts_merkle_root

        runs = tmp_path / "runs"
        save_run_record(runs, self._record_with_hashes({"x.json": "a" * 64}))
        assert check_artefacts_merkle_root(runs) == []

    def test_empty_hashes_skipped(self, tmp_path):
        from loupe_core.artifacts.run_record import save_run_record
        from loupe_core.enforcement.verify import check_artefacts_merkle_root

        runs = tmp_path / "runs"
        save_run_record(runs, self._record_with_hashes({}))
        assert check_artefacts_merkle_root(runs) == []

    def test_tampered_root_is_detected(self, tmp_path):
        import json as _json

        from loupe_core.artifacts.run_record import save_run_record
        from loupe_core.enforcement.verify import check_artefacts_merkle_root

        runs = tmp_path / "runs"
        saved = save_run_record(runs, self._record_with_hashes({"x.json": "a" * 64}))

        # Tamper: overwrite the stored root with a wrong value AND recompute
        # self_hash so the chain check would still pass. This simulates an
        # attacker who knew about the chain but not about the Merkle check.
        files = sorted(runs.glob("*.json"))
        assert len(files) == 1
        tampered = saved.model_copy(update={"artifacts_merkle_root": "0" * 64})
        tampered.self_hash = tampered.compute_self_hash()
        files[0].write_text(_json.dumps(tampered.model_dump(mode="json"), indent=2, sort_keys=True))

        failures = check_artefacts_merkle_root(runs)
        assert len(failures) == 1
        assert failures[0].kind == "artefacts_merkle_root_mismatch"
        assert failures[0].run_id == tampered.run_id

    def test_tampered_hash_value_is_detected(self, tmp_path):
        """If an attacker swaps a leaf hash but leaves the stored root
        unchanged, the recompute catches it."""
        import json as _json

        from loupe_core.artifacts.run_record import save_run_record
        from loupe_core.enforcement.verify import check_artefacts_merkle_root

        runs = tmp_path / "runs"
        saved = save_run_record(runs, self._record_with_hashes({"x.json": "a" * 64}))

        files = sorted(runs.glob("*.json"))
        tampered = saved.model_copy(update={"artifact_hashes": {"x.json": "b" * 64}})
        tampered.self_hash = tampered.compute_self_hash()
        files[0].write_text(_json.dumps(tampered.model_dump(mode="json"), indent=2, sort_keys=True))

        failures = check_artefacts_merkle_root(runs)
        assert len(failures) == 1
        assert failures[0].kind == "artefacts_merkle_root_mismatch"

    def test_runs_by_default_in_verify_repo(self, tmp_path):
        import json as _json

        from loupe_core.artifacts.run_record import save_run_record
        from loupe_core.enforcement.verify import verify_repo

        loupe = tmp_path / ".loupe"
        runs = loupe / "runs"
        runs.mkdir(parents=True)
        # context.md is required by some downstream checks; create empty.
        (loupe / "context.md").write_text("")

        saved = save_run_record(runs, self._record_with_hashes({"x.json": "a" * 64}))
        files = sorted(runs.glob("*.json"))
        tampered = saved.model_copy(update={"artifacts_merkle_root": "0" * 64})
        tampered.self_hash = tampered.compute_self_hash()
        files[0].write_text(_json.dumps(tampered.model_dump(mode="json"), indent=2, sort_keys=True))

        kinds = {f.kind for f in verify_repo(tmp_path)}
        assert "artefacts_merkle_root_mismatch" in kinds

    def test_empty_hashes_with_non_null_root_is_detected(self, tmp_path):
        """Writer invariant: empty artifact_hashes always pairs with
        artifacts_merkle_root=None. An attacker who hand-rewrites a
        record to claim 'no artefacts' but leaves a non-null stored
        root creates a contradiction the verifier must surface."""
        import json as _json

        from loupe_core.artifacts.run_record import save_run_record
        from loupe_core.enforcement.verify import check_artefacts_merkle_root

        runs = tmp_path / "runs"
        saved = save_run_record(runs, self._record_with_hashes({}))
        assert saved.artifacts_merkle_root is None  # confirms writer invariant

        # Tamper: keep artifact_hashes={} but set artifacts_merkle_root
        # to a plausible-looking hex string, then reroll self_hash so the
        # chain check still passes.
        files = sorted(runs.glob("*.json"))
        assert len(files) == 1
        tampered = saved.model_copy(update={"artifacts_merkle_root": "0" * 64})
        tampered.self_hash = tampered.compute_self_hash()
        files[0].write_text(_json.dumps(tampered.model_dump(mode="json"), indent=2, sort_keys=True))

        failures = check_artefacts_merkle_root(runs)
        assert len(failures) == 1
        assert failures[0].kind == "artefacts_merkle_root_mismatch"
        assert failures[0].run_id == tampered.run_id

    def test_per_record_failure_in_multi_record_dir(self, tmp_path):
        """Multiple records in one runs/ dir — the verifier must report
        per-record failures, not short-circuit on first."""
        import json as _json

        from loupe_core.artifacts.run_record import save_run_record
        from loupe_core.enforcement.verify import check_artefacts_merkle_root

        runs = tmp_path / "runs"
        clean = save_run_record(runs, self._record_with_hashes({"clean.json": "a" * 64}))
        # Chain: second record's prev_run_hash is the first's self_hash.
        bad = save_run_record(
            runs,
            self._record_with_hashes({"bad.json": "b" * 64}, prev=clean.self_hash),
        )

        # Tamper only the second record.
        files = sorted(runs.glob("*.json"))
        assert len(files) == 2
        bad_file = files[-1]  # microsecond filename sorts second
        tampered = bad.model_copy(update={"artifacts_merkle_root": "0" * 64})
        tampered.self_hash = tampered.compute_self_hash()
        bad_file.write_text(_json.dumps(tampered.model_dump(mode="json"), indent=2, sort_keys=True))

        failures = check_artefacts_merkle_root(runs)
        assert len(failures) == 1
        assert failures[0].run_id == tampered.run_id
        assert failures[0].kind == "artefacts_merkle_root_mismatch"
