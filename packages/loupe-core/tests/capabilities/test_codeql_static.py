"""Tests for the CodeQL static-analysis backend."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from loupe_core.capabilities.backends.codeql_static import (
    CodeQLStaticBackend,
    _locate_database,
    _parse_sarif,
    _read_database_language,
    _resolve_query,
    _sarif_result_to_finding,
)
from loupe_core.capabilities.errors import BackendError


def _sarif(*results: dict) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "CodeQL"}},
                    "results": list(results),
                }
            ],
        }
    )


def _result(
    *,
    rule_id: str = "py/sql-injection",
    message: str = "SQL injection detected.",
    level: str = "error",
    file: str = "src/db.py",
    line: int = 42,
) -> dict:
    return {
        "ruleId": rule_id,
        "message": {"text": message},
        "level": level,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file},
                    "region": {"startLine": line},
                },
            }
        ],
    }


# ---------------------------------------------------------------------------
# _locate_database
# ---------------------------------------------------------------------------


def test_locate_database_typed_option_wins(tmp_path, monkeypatch):
    """Typed `database_path` overrides env var and default-path discovery."""
    import warnings

    typed_db = tmp_path / "typed-db"
    typed_db.mkdir()
    env_db = tmp_path / "env-db"
    env_db.mkdir()
    repo_db = tmp_path / "repo" / ".codeql-db"
    repo_db.mkdir(parents=True)
    monkeypatch.setenv("LOUPE_CODEQL_DB", str(env_db))
    # The typed option should win, and we should NOT emit DeprecationWarning
    # because the env var is never consulted.
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        assert (
            _locate_database(
                tmp_path / "repo",
                database_path=str(typed_db),
            )
            == typed_db
        )


def test_locate_database_env_var_emits_deprecation_warning(tmp_path, monkeypatch):
    """LOUPE_CODEQL_DB still works but is deprecated."""
    env_db = tmp_path / "explicit-db"
    env_db.mkdir()
    repo_db = tmp_path / "repo" / ".codeql-db"
    repo_db.mkdir(parents=True)
    monkeypatch.setenv("LOUPE_CODEQL_DB", str(env_db))
    with pytest.warns(DeprecationWarning, match="LOUPE_CODEQL_DB is deprecated"):
        result = _locate_database(tmp_path / "repo")
    assert result == env_db


def test_locate_database_falls_back_to_default(tmp_path, monkeypatch):
    """Without typed option or env override, .codeql-db/ in the repo is picked up."""
    monkeypatch.delenv("LOUPE_CODEQL_DB", raising=False)
    repo_db = tmp_path / ".codeql-db"
    repo_db.mkdir()
    assert _locate_database(tmp_path) == repo_db


def test_locate_database_returns_none_when_nothing_present(tmp_path, monkeypatch):
    monkeypatch.delenv("LOUPE_CODEQL_DB", raising=False)
    assert _locate_database(tmp_path) is None


def test_locate_database_ignores_env_when_path_missing(tmp_path, monkeypatch):
    """A stale LOUPE_CODEQL_DB pointing at a nonexistent path should not crash."""
    monkeypatch.setenv("LOUPE_CODEQL_DB", str(tmp_path / "does-not-exist"))
    with pytest.warns(DeprecationWarning):
        assert _locate_database(tmp_path) is None


def test_locate_database_ignores_typed_option_when_path_missing(tmp_path, monkeypatch):
    """A stale typed `database_path` falls through to env-var / default."""
    monkeypatch.delenv("LOUPE_CODEQL_DB", raising=False)
    assert (
        _locate_database(
            tmp_path,
            database_path=str(tmp_path / "does-not-exist"),
        )
        is None
    )


@pytest.mark.asyncio
async def test_backend_reads_database_path_from_options(tmp_path, monkeypatch):
    """The backend instance's ``options['database_path']`` is honoured and does NOT
    consult LOUPE_CODEQL_DB (no DeprecationWarning emitted)."""
    import warnings

    typed_db = tmp_path / "typed-db"
    typed_db.mkdir()
    (typed_db / "codeql-database.yml").write_text("primaryLanguage: python\n")
    monkeypatch.delenv("LOUPE_CODEQL_DB", raising=False)

    backend = CodeQLStaticBackend()
    backend.options = {"database_path": str(typed_db)}

    sarif_payload = _sarif(_result(file="src/typed.py", line=99))
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = ""

    captured_cmd: list[str] = []

    def _fake_run(cmd, **_kwargs):
        captured_cmd.extend(cmd)
        for arg in cmd:
            if isinstance(arg, str) and arg.startswith("--output="):
                Path(arg.split("=", 1)[1]).write_text(sarif_payload)
                break
        return mock_proc

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        with (
            patch("shutil.which", return_value="/usr/bin/codeql"),
            patch("subprocess.run", side_effect=_fake_run),
        ):
            result = await backend.run(tmp_path)

    # The typed db path should be the one passed to `codeql database analyze`.
    assert str(typed_db) in captured_cmd
    assert result.findings[0].file == "src/typed.py"


# ---------------------------------------------------------------------------
# _parse_sarif
# ---------------------------------------------------------------------------


def test_parse_sarif_empty_string_returns_empty():
    assert _parse_sarif("") == []
    assert _parse_sarif("  \n") == []


def test_parse_sarif_no_results_returns_empty():
    assert _parse_sarif(_sarif()) == []


def test_parse_sarif_extracts_basic_finding():
    findings = _parse_sarif(_sarif(_result()))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "py/sql-injection"
    assert f.message == "SQL injection detected."
    assert f.file == "src/db.py"
    assert f.line == 42
    assert f.severity == "high"


@pytest.mark.parametrize(
    "sarif_level, expected",
    [
        ("error", "high"),
        ("warning", "medium"),
        ("note", "low"),
        ("none", "informational"),
        ("UNKNOWN", "informational"),  # graceful fallback
        ("ERROR", "high"),  # case-insensitive
    ],
)
def test_parse_sarif_severity_mapping(sarif_level, expected):
    findings = _parse_sarif(_sarif(_result(level=sarif_level)))
    assert findings[0].severity == expected


def test_parse_sarif_handles_missing_locations():
    """A result without `locations` should produce a finding with line=None
    (the protocol sentinel for whole-file / unknown location)."""
    bare = {"ruleId": "x", "message": {"text": "y"}, "level": "warning"}
    findings = _parse_sarif(_sarif(bare))
    assert len(findings) == 1
    assert findings[0].file == ""
    assert findings[0].line is None


def test_parse_sarif_handles_missing_message():
    result = _result()
    result["message"]["text"] = ""
    findings = _parse_sarif(_sarif(result))
    assert findings[0].message == "(no message)"


def test_parse_sarif_walks_multiple_runs():
    """SARIF allows multiple runs per document; we should walk all of them."""
    doc = json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {"results": [_result(file="a.py")]},
                {"results": [_result(file="b.py")]},
            ],
        }
    )
    findings = _parse_sarif(doc)
    assert {f.file for f in findings} == {"a.py", "b.py"}


def test_parse_sarif_malformed_raises():
    with pytest.raises(BackendError) as exc_info:
        _parse_sarif("totally not sarif")
    assert "codeql" in str(exc_info.value).lower()


def test_sarif_result_to_finding_single_helper():
    """Direct helper test for the per-result conversion."""
    finding = _sarif_result_to_finding(_result(rule_id="zz", line=7))
    assert finding.rule_id == "zz"
    assert finding.line == 7


# ---------------------------------------------------------------------------
# CodeQLStaticBackend.run — mocked subprocess + filesystem
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_backend_returns_typed_result(tmp_path, monkeypatch):
    # Set up a fake database directory so _locate_database succeeds.
    db = tmp_path / ".codeql-db"
    db.mkdir()
    (db / "codeql-database.yml").write_text("primaryLanguage: python\n")
    monkeypatch.delenv("LOUPE_CODEQL_DB", raising=False)

    sarif_payload = _sarif(_result(file="src/x.py", line=10))
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = ""

    # CodeQL writes SARIF to the --output path; emulate by writing the
    # payload at the same path subprocess.run was invoked with.
    def _fake_run(cmd, **_kwargs):
        # The --output=<path> arg is one of the cli args; find it.
        for arg in cmd:
            if isinstance(arg, str) and arg.startswith("--output="):
                Path(arg.split("=", 1)[1]).write_text(sarif_payload)
                break
        return mock_proc

    with (
        patch("shutil.which", return_value="/usr/bin/codeql"),
        patch("subprocess.run", side_effect=_fake_run),
    ):
        result = await CodeQLStaticBackend().run(tmp_path)

    assert result.backend_name == "codeql"
    assert len(result.findings) == 1
    assert result.findings[0].file == "src/x.py"
    assert result.findings[0].line == 10


@pytest.mark.asyncio
async def test_backend_raises_when_binary_missing(tmp_path):
    with patch("shutil.which", return_value=None):
        with pytest.raises(BackendError) as exc_info:
            await CodeQLStaticBackend().run(tmp_path)
    assert "codeql" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_backend_raises_when_database_missing(tmp_path, monkeypatch):
    monkeypatch.delenv("LOUPE_CODEQL_DB", raising=False)
    with patch("shutil.which", return_value="/usr/bin/codeql"):
        with pytest.raises(BackendError) as exc_info:
            await CodeQLStaticBackend().run(tmp_path)
    # Error message should guide the operator toward `database create`.
    msg = str(exc_info.value).lower()
    assert "database" in msg
    assert "create" in msg


@pytest.mark.asyncio
async def test_backend_raises_on_subprocess_failure(tmp_path, monkeypatch):
    db = tmp_path / ".codeql-db"
    db.mkdir()
    (db / "codeql-database.yml").write_text("primaryLanguage: python\n")
    monkeypatch.delenv("LOUPE_CODEQL_DB", raising=False)

    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = ""
    mock_proc.stderr = "query pack version incompatible"

    with (
        patch("shutil.which", return_value="/usr/bin/codeql"),
        patch("subprocess.run", return_value=mock_proc),
    ):
        with pytest.raises(BackendError) as exc_info:
            await CodeQLStaticBackend().run(tmp_path)
    assert "incompatible" in str(exc_info.value)


def test_backend_registered_under_static_analysis_capability():
    assert CodeQLStaticBackend.name == "static_analysis"
    assert CodeQLStaticBackend.backend_name == "codeql"


# ---------------------------------------------------------------------------
# Query-suite resolution — `codeql database analyze` REQUIRES a query arg
# ---------------------------------------------------------------------------


def test_resolve_query_uses_operator_override(tmp_path):
    """Operator-provided `options.query` wins, no need to read the DB metadata."""
    # Note: db_path doesn't need codeql-database.yml when override is set.
    db = tmp_path / "db"
    db.mkdir()
    assert (
        _resolve_query({"query": "codeql/python-queries:custom.qls"}, db)
        == "codeql/python-queries:custom.qls"
    )


def test_resolve_query_defaults_from_database_language(tmp_path):
    """Without override, read primaryLanguage from codeql-database.yml and
    pick the standard pack for that language."""
    db = tmp_path / "db"
    db.mkdir()
    (db / "codeql-database.yml").write_text("primaryLanguage: python\n")
    assert _resolve_query({}, db) == "codeql/python-queries"


def test_resolve_query_raises_when_metadata_missing(tmp_path):
    """No metadata file AND no override → BackendError pointing at the fix."""
    db = tmp_path / "db"
    db.mkdir()
    with pytest.raises(BackendError) as exc_info:
        _resolve_query({}, db)
    msg = str(exc_info.value).lower()
    assert "codeql-database.yml" in msg or "query" in msg


def test_resolve_query_raises_for_unknown_language(tmp_path):
    """A language with no shipped default pack must raise rather than silently
    running the analyzer with no query (which produces empty SARIF)."""
    db = tmp_path / "db"
    db.mkdir()
    (db / "codeql-database.yml").write_text("primaryLanguage: brainfuck\n")
    with pytest.raises(BackendError) as exc_info:
        _resolve_query({}, db)
    assert "brainfuck" in str(exc_info.value)


def test_read_database_language_strips_quotes_and_comments(tmp_path):
    """codeql-database.yml may quote or annotate the language — be robust."""
    db = tmp_path / "db"
    db.mkdir()
    (db / "codeql-database.yml").write_text(
        'primaryLanguage: "javascript"  # set by codeql database create\n'
    )
    assert _read_database_language(db) == "javascript"


def test_read_database_language_returns_none_when_file_absent(tmp_path):
    assert _read_database_language(tmp_path) is None


@pytest.mark.asyncio
async def test_backend_passes_query_argument_to_codeql(tmp_path, monkeypatch):
    """The subprocess invocation MUST include a query/suite/pack arg per the
    CodeQL CLI manual — this is the regression this commit fixes."""
    db = tmp_path / ".codeql-db"
    db.mkdir()
    (db / "codeql-database.yml").write_text("primaryLanguage: python\n")
    monkeypatch.delenv("LOUPE_CODEQL_DB", raising=False)

    sarif_payload = _sarif(_result())
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = ""

    captured_cmd: list[str] = []

    def _fake_run(cmd, **_kwargs):
        captured_cmd.extend(cmd)
        for arg in cmd:
            if isinstance(arg, str) and arg.startswith("--output="):
                Path(arg.split("=", 1)[1]).write_text(sarif_payload)
                break
        return mock_proc

    with (
        patch("shutil.which", return_value="/usr/bin/codeql"),
        patch("subprocess.run", side_effect=_fake_run),
    ):
        await CodeQLStaticBackend().run(tmp_path)

    # The default Python pack must appear BEFORE the --format flag, because
    # `codeql database analyze` is positional: <db> <query> --format ...
    assert "codeql/python-queries" in captured_cmd
    db_idx = captured_cmd.index(str(db))
    query_idx = captured_cmd.index("codeql/python-queries")
    format_idx = next(
        i for i, a in enumerate(captured_cmd) if isinstance(a, str) and a.startswith("--format=")
    )
    assert db_idx < query_idx < format_idx


@pytest.mark.asyncio
async def test_backend_honours_operator_query_override(tmp_path, monkeypatch):
    """`options.query` lets operators substitute a non-default suite."""
    db = tmp_path / ".codeql-db"
    db.mkdir()
    # No codeql-database.yml — proving the override skips metadata lookup.
    monkeypatch.delenv("LOUPE_CODEQL_DB", raising=False)

    sarif_payload = _sarif(_result())
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = ""

    captured_cmd: list[str] = []

    def _fake_run(cmd, **_kwargs):
        captured_cmd.extend(cmd)
        for arg in cmd:
            if isinstance(arg, str) and arg.startswith("--output="):
                Path(arg.split("=", 1)[1]).write_text(sarif_payload)
                break
        return mock_proc

    backend = CodeQLStaticBackend()
    backend.options = {"query": "my-org/custom-queries:audit.qls"}

    with (
        patch("shutil.which", return_value="/usr/bin/codeql"),
        patch("subprocess.run", side_effect=_fake_run),
    ):
        await backend.run(tmp_path)

    assert "my-org/custom-queries:audit.qls" in captured_cmd
    # The default pack MUST NOT leak through when an override is set.
    assert "codeql/python-queries" not in captured_cmd
