"""Tests for `check_cassette_auth_headers` — defence-in-depth against VCR cassette
auth-token leakage. The conftest.py `filter_headers` is the primary defence;
this check is the safety net that runs at `loupe verify` time."""

from pathlib import Path

from loupe_core.enforcement.verify import VerifyFailure, check_cassette_auth_headers


def _write_cassette(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_no_failures_when_cassettes_clean(tmp_path):
    """A cassette with only allow-listed headers produces zero failures."""
    cassette = tmp_path / "cassettes" / "test_foo.yaml"
    _write_cassette(
        cassette,
        """interactions:
- request:
    body: '{}'
    headers:
      Accept: ['application/json']
      Content-Type: ['application/json']
""",
    )
    failures = check_cassette_auth_headers(tmp_path)
    assert failures == []


def test_failure_when_authorization_header_present(tmp_path):
    """If any cassette contains an Authorization header (request or response),
    the check returns a VerifyFailure with the cassette path."""
    cassette = tmp_path / "cassettes" / "test_leak.yaml"
    _write_cassette(
        cassette,
        """interactions:
- request:
    body: '{}'
    headers:
      Authorization: ['Bearer sk-ant-leaked-token']
      Accept: ['application/json']
""",
    )
    failures = check_cassette_auth_headers(tmp_path)
    assert len(failures) == 1
    assert failures[0].kind == "cassette_auth_header"
    assert "test_leak.yaml" in failures[0].detail
    assert "Authorization" in failures[0].detail


def test_failure_when_x_api_key_present(tmp_path):
    """x-api-key is the same threat — many providers use it instead of Authorization.
    The check covers both."""
    cassette = tmp_path / "cassettes" / "test_apikey.yaml"
    _write_cassette(
        cassette,
        """interactions:
- request:
    body: '{}'
    headers:
      x-api-key: ['sk-ant-leaked-key']
""",
    )
    failures = check_cassette_auth_headers(tmp_path)
    assert len(failures) == 1
    assert "x-api-key" in failures[0].detail.lower()


def test_recursive_walk_finds_nested_cassettes(tmp_path):
    """Cassettes can live in subdirectories. The walk is recursive."""
    nested = tmp_path / "cassettes" / "deep" / "nested.yaml"
    _write_cassette(
        nested,
        """interactions:
- request:
    body: '{}'
    headers:
      Authorization: ['Bearer leaked']
""",
    )
    failures = check_cassette_auth_headers(tmp_path)
    assert len(failures) == 1
    assert "nested.yaml" in failures[0].detail


def test_no_failures_when_no_cassettes_exist(tmp_path):
    """If the cassettes directory doesn't exist (e.g., before any tests have
    been recorded), the check is a no-op — not a failure."""
    failures = check_cassette_auth_headers(tmp_path)
    assert failures == []
