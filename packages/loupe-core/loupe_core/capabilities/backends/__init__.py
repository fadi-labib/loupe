"""Bundled default backends.

Each backend implements one capability Protocol and registers under the
``loupe.capabilities`` entry-point group in ``loupe-core/pyproject.toml``.
Third-party backends register the same way from their own packages.
"""

from __future__ import annotations

import subprocess

# Cap on stdout fallback to keep BackendError messages survivable in logs.
# 200 bytes is enough to surface a JSON parse error or a usage hint; tools
# that emit megabytes of progress chatter to stdout (e.g., grype downloading
# its DB) won't blow up the log line.
_STDOUT_SNIPPET_LIMIT = 200


def format_subprocess_failure(proc: subprocess.CompletedProcess[str]) -> str:
    """Build a non-empty failure detail from a CompletedProcess.

    Prefers stderr (where well-behaved CLIs put diagnostics), falls back to a
    truncated stdout snippet (some tools print errors to stdout when format=
    json is requested), then to the exit code as a last resort. Returning the
    empty string from the previous implementation produced `backend 'X' failed:`
    messages with nothing after the colon — actively unhelpful to operators
    triaging a CI failure.
    """
    stderr_msg = proc.stderr.strip() if proc.stderr else ""
    if stderr_msg:
        return stderr_msg
    stdout_msg = proc.stdout.strip() if proc.stdout else ""
    if stdout_msg:
        return stdout_msg[:_STDOUT_SNIPPET_LIMIT]
    return f"exited {proc.returncode} with no output"
