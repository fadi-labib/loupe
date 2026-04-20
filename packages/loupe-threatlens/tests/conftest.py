"""pytest configuration for the loupe-threatlens test suite.

Configures VCR (via pytest-vcr) so that:
- API keys never land in committed cassette files
- Cassettes are stored next to the tests that use them
- The matcher includes method + URI + body so prompt changes invalidate
  the cassette deliberately (re-recording becomes necessary, not silent)
"""

import pytest


@pytest.fixture(scope="module")
def vcr_config():
    return {
        # Strip credentials from every recording — these must NEVER appear in
        # a committed cassette. Keep this list paranoid: any header that an
        # LLM provider might use for auth.
        "filter_headers": [
            "authorization",
            "x-api-key",
            "anthropic-version",  # not secret, but version-coupled; safer to omit
            "x-stainless-arch",
            "x-stainless-os",
            "x-stainless-package-version",
            "x-stainless-runtime",
            "x-stainless-runtime-version",
            "user-agent",
            "openai-organization",
            "openai-project",
        ],
        # Match on method + scheme + host + path + body. Including body means
        # a prompt change forces a re-recording rather than silently replaying
        # a stale response — which is exactly what we want for prompt iteration.
        "match_on": ["method", "scheme", "host", "path", "body"],
        # Record once: if a cassette exists, replay; if not, record on first
        # run with --record-mode=once. The default mode prevents accidental
        # re-recording in CI.
        "record_mode": "once",
        # Decode binary response bodies to text where possible (LLM responses
        # are JSON, so this makes the cassette diff-readable).
        "decode_compressed_response": True,
    }
