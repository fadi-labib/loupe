"""Layer 3 enforcement — `loupe verify` implementation.

Independent of the CLI; can be invoked from any context (pre-commit hook,
CI step, programmatic use) to validate the integrity of `.loupe/`.

Default checks (every run of `loupe verify`):
- Run-record hash chain: every record's prev_run_hash must equal the
  previous record's self_hash, and every record's self_hash must equal
  the SHA-256 of its own content (excluding self_hash).
- Artefact schema consistency: every YAML/JSON artefact under `.loupe/`
  must parse with its Pydantic model.
- Threats-to-mitigations cross-reference integrity: every mitigation_id
  named on a Threat must exist in `mitigations.yaml`, and every
  threats_addressed entry on a Mitigation must exist in `threats.yaml`.

Strict checks (`loupe verify --strict` only):
- Authorship: protected paths (`context.md`, `decisions/**`,
  `config.yaml`, `knowledge.yaml`) must have their most recent git
  commit authored by a human identity. Strict checks need git or
  filesystem access beyond `.loupe/`, so opt-in keeps the default fast.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError
from ruamel.yaml.error import YAMLError

from loupe_core.artifacts.merkle import compute_artefact_merkle_root
from loupe_core.artifacts.mitigation import MitigationsFile
from loupe_core.artifacts.run_record import load_run_records
from loupe_core.artifacts.threat import ThreatsFile

# Paths protected by Layer 1 (`agent_writable_paths` excludes them) plus
# the artefacts agents may draft but humans review per [D-08]. The strict
# authorship check ensures no agent identity authored the most recent
# commit to these paths.
_HUMAN_OWNED = (
    "context.md",
    "config.yaml",
    "knowledge.yaml",
)
_HUMAN_OWNED_DIRS = ("decisions",)

# A commit author is treated as a bot/agent identity when ANY of these
# match. Conservative — better to false-positive (require manual review)
# than to silently accept an agent-authored commit on a protected path.
_AGENT_AUTHOR_PATTERNS = (
    "@bots.local",
    "bot+",
    "[bot]",
    "loupe-",
)


@dataclass
class VerifyFailure:
    kind: str
    detail: str
    run_id: str | None = None


# ---------------------------------------------------------------------------
# Hash-chain check (was the only check pre-Phase-7.3)
# ---------------------------------------------------------------------------


def check_run_record_chain(runs_dir: Path) -> list[VerifyFailure]:
    """Walk the run-record chain; report breaks in prev_run_hash or self_hash."""
    records = load_run_records(runs_dir)
    failures: list[VerifyFailure] = []
    expected_prev: str | None = None
    for r in records:
        if r.prev_run_hash != expected_prev:
            failures.append(
                VerifyFailure(
                    kind="run_chain_broken",
                    run_id=r.run_id,
                    detail=f"prev_run_hash={r.prev_run_hash} but expected {expected_prev}",
                )
            )
        if r.self_hash != r.compute_self_hash():
            failures.append(
                VerifyFailure(
                    kind="run_self_hash_mismatch",
                    run_id=r.run_id,
                    detail="content does not match self_hash",
                )
            )
        expected_prev = r.self_hash
    return failures


# ---------------------------------------------------------------------------
# Merkle root consistency
# ---------------------------------------------------------------------------


def check_artefacts_merkle_root(runs_dir: Path) -> list[VerifyFailure]:
    """Each run's stored `artifacts_merkle_root` must equal the recomputed root.

    `compute_artefact_merkle_root` returns the empty string for an empty
    hash dict; the stored root is `None` in the same case (see
    `save_run_record`'s `root or None` writer invariant). Coercing the
    stored value via `or ""` makes the no-artefacts case a logical
    no-op (`"" == ""`) without an early-skip, which means a malformed
    record where `artifact_hashes={}` but `artifacts_merkle_root` is a
    non-None hex string is now caught — the contradiction inside the
    record is exactly what `loupe verify` should surface.

    We do NOT rehash the on-disk artefact files — they legitimately
    change between runs. This check only proves the run record's
    internal commitment is consistent: the stored root matches the
    leaves the record itself names.
    """
    records = load_run_records(runs_dir)
    failures: list[VerifyFailure] = []
    for r in records:
        expected = compute_artefact_merkle_root(r.artifact_hashes)
        stored = r.artifacts_merkle_root or ""
        if stored != expected:
            failures.append(
                VerifyFailure(
                    kind="artefacts_merkle_root_mismatch",
                    run_id=r.run_id,
                    detail=(
                        f"stored artifacts_merkle_root={r.artifacts_merkle_root!r} "
                        f"but recomputed={expected!r}"
                    ),
                )
            )
    return failures


# ---------------------------------------------------------------------------
# Schema consistency
# ---------------------------------------------------------------------------


def check_artefact_schemas(loupe_dir: Path) -> list[VerifyFailure]:
    """Every artefact present on disk must parse with its Pydantic model.

    Run records are already covered by the chain check (their schema is
    validated implicitly during load). This check focuses on the two
    machine-readable artefacts ThreatLens owns: threats.yaml and
    mitigations.yaml. SBOM and VEX use their own standard validators
    (CycloneDX, OpenVEX); we don't re-implement those here.
    """
    failures: list[VerifyFailure] = []
    threats_path = loupe_dir / "threats.yaml"
    if threats_path.exists():
        try:
            ThreatsFile.load(threats_path)
        except Exception as exc:
            failures.append(
                VerifyFailure(
                    kind="schema_invalid",
                    detail=f"threats.yaml does not parse as ThreatsFile: {exc}",
                )
            )
    mitigations_path = loupe_dir / "mitigations.yaml"
    if mitigations_path.exists():
        try:
            MitigationsFile.load(mitigations_path)
        except Exception as exc:
            failures.append(
                VerifyFailure(
                    kind="schema_invalid",
                    detail=f"mitigations.yaml does not parse as MitigationsFile: {exc}",
                )
            )
    return failures


# ---------------------------------------------------------------------------
# Threats <-> mitigations cross-reference integrity
# ---------------------------------------------------------------------------


def check_threats_mitigations_cross_refs(loupe_dir: Path) -> list[VerifyFailure]:
    """Bidirectional referential integrity between threats and mitigations.

    - Every mitigation_id referenced from a Threat must exist in
      mitigations.yaml.
    - Every threat_id referenced from a Mitigation's threats_addressed
      must exist in threats.yaml.

    Files are loaded lazily: if either doesn't exist on disk, we skip
    silently (the schema check has already complained if the file is
    present but malformed).
    """
    threats_path = loupe_dir / "threats.yaml"
    mitigations_path = loupe_dir / "mitigations.yaml"
    if not threats_path.exists() or not mitigations_path.exists():
        return []

    try:
        threats = ThreatsFile.load(threats_path)
        mitigations = MitigationsFile.load(mitigations_path)
    except (YAMLError, ValidationError):
        # Schema check (check_artifact_schemas) will surface the load
        # error; don't double-report. Anything else — IOError, programming
        # errors — must propagate so the operator sees the real bug
        # rather than a confusingly empty cross-ref result.
        return []

    threat_ids = {t.id for t in threats.threats}
    mitigation_ids = {m.id for m in mitigations.mitigations}

    failures: list[VerifyFailure] = []

    for threat in threats.threats:
        for mid in threat.mitigation_ids:
            if mid not in mitigation_ids:
                failures.append(
                    VerifyFailure(
                        kind="dangling_mitigation_ref",
                        detail=(
                            f"threat {threat.id} references mitigation '{mid}', "
                            f"but no such ID exists in mitigations.yaml"
                        ),
                    )
                )

    for mitigation in mitigations.mitigations:
        for tid in mitigation.threats_addressed:
            if tid not in threat_ids:
                failures.append(
                    VerifyFailure(
                        kind="dangling_threat_ref",
                        detail=(
                            f"mitigation {mitigation.id} addresses threat '{tid}', "
                            f"but no such ID exists in threats.yaml"
                        ),
                    )
                )

    return failures


# ---------------------------------------------------------------------------
# Strict-only: authorship of protected paths
# ---------------------------------------------------------------------------


def check_protected_path_authorship(repo_root: Path) -> list[VerifyFailure]:
    """Strict-only. Most-recent git commit to any protected path must be human.

    Uses `git log -1 --format=%ae|%an` to read the latest authorship of
    each protected path. If git itself isn't available or the file has
    never been committed, the check is skipped (no failure).
    """
    failures: list[VerifyFailure] = []
    loupe = repo_root / ".loupe"

    protected_files: list[Path] = []
    for name in _HUMAN_OWNED:
        path = loupe / name
        if path.exists():
            protected_files.append(path)
    for dirname in _HUMAN_OWNED_DIRS:
        directory = loupe / dirname
        if directory.exists():
            protected_files.extend(p for p in directory.glob("**/*") if p.is_file())

    for path in protected_files:
        identity = _last_commit_identity(path, repo_root=repo_root)
        if identity is None:
            continue  # file never committed or git unavailable — silent skip
        if _looks_like_agent(identity):
            rel = path.relative_to(repo_root)
            failures.append(
                VerifyFailure(
                    kind="protected_path_agent_author",
                    detail=(
                        f"protected path '{rel}' was last touched by an "
                        f"agent-identity commit ({identity}). A human must "
                        f"author changes to this file."
                    ),
                )
            )
    return failures


def _last_commit_identity(path: Path, *, repo_root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%ae|%an", "--", str(path)],
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, OSError):
        return None
    if result.returncode != 0:
        return None
    line = result.stdout.strip()
    return line or None


def _looks_like_agent(identity: str) -> bool:
    haystack = identity.lower()
    return any(p in haystack for p in _AGENT_AUTHOR_PATTERNS)


# ---------------------------------------------------------------------------
# VCR cassette auth-header defence-in-depth
# ---------------------------------------------------------------------------

# Header names that, if present in any VCR cassette, indicate an auth-token
# leak the conftest.py `filter_headers` should have scrubbed. The check is
# header-name-only (not value-based) — even a placeholder value means the
# header survived the filter, which is the bug we're catching.
_AUTH_HEADER_NAMES_LOWERCASE = frozenset(
    {
        "authorization",
        "x-api-key",
        "anthropic-version",
        "openai-api-key",
        "api-key",
    }
)


def check_cassette_auth_headers(repo_root: Path) -> list[VerifyFailure]:
    """Walk every VCR cassette under `repo_root` and refuse any with auth headers.

    The conftest.py `filter_headers` strips these before write, so any header
    surviving into a committed cassette is the bug this check catches. Returns
    one VerifyFailure per offending cassette.

    No-op (empty list) when no cassettes directory exists yet.
    """
    failures: list[VerifyFailure] = []
    for cassette_path in sorted(repo_root.rglob("cassettes/**/*.yaml")):
        text = cassette_path.read_text()
        if "headers:" not in text.lower():
            continue
        offending = _scan_for_auth_header_lines(text)
        if offending:
            joined = ", ".join(sorted(offending))
            failures.append(
                VerifyFailure(
                    kind="cassette_auth_header",
                    detail=(
                        f"{cassette_path} contains auth header(s): {joined}. "
                        "conftest.py filter_headers should have stripped them; "
                        "re-record the cassette."
                    ),
                )
            )
    return failures


def _scan_for_auth_header_lines(yaml_text: str) -> set[str]:
    """Return the set of auth-header names that appear as keys in the YAML text."""
    found: set[str] = set()
    for line in yaml_text.splitlines():
        stripped = line.strip()
        if not stripped or ":" not in stripped:
            continue
        key = stripped.split(":", 1)[0].strip().strip("'\"")
        if key.lower() in _AUTH_HEADER_NAMES_LOWERCASE:
            found.add(key)
    return found


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def verify_repo(repo_root: Path, *, strict: bool = False) -> list[VerifyFailure]:
    """Run every Layer 3 check; return combined failures.

    Default checks run on every invocation. The strict-only set (today:
    protected-path authorship) runs when `--strict` is passed to the
    CLI. Strict checks tend to need git or filesystem access beyond the
    `.loupe/` directory, so opt-in keeps the default fast and pure.
    """
    loupe = repo_root / ".loupe"
    failures: list[VerifyFailure] = []
    failures.extend(check_run_record_chain(loupe / "runs"))
    failures.extend(check_artefacts_merkle_root(loupe / "runs"))
    failures.extend(check_artefact_schemas(loupe))
    failures.extend(check_threats_mitigations_cross_refs(loupe))
    failures.extend(check_cassette_auth_headers(repo_root))
    if strict:
        failures.extend(check_protected_path_authorship(repo_root))
    return failures
