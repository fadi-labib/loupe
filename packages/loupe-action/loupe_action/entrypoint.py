"""GitHub Action entrypoint — orchestrates one PR analysis run.

Top-level flow:

1. Parse inputs from environment (``parse_inputs``).
2. Fetch the PR's base SHA, head SHA, and unified diff via the API
   (``PRFetcher``) — works regardless of runner-side checkout depth.
3. Invoke ``loupe ci`` as an in-process function call, passing the diff
   and SHAs. Lenses run; run record + threat artefacts get written.
4. Load the freshly-written run record + threats from ``.loupe/``.
5. Format the Markdown comment (``format_pr_comment``).
6. Post sticky comment (unless ``comment_mode == "none"``).
7. Write ``GITHUB_OUTPUT`` k=v lines for downstream steps.
8. Exit with a semantic code:

   - ``0``  — clean (no findings at or above ``ci.fail_on`` severities).
   - ``1``  — findings present at ``ci.fail_on`` severities (the gate).
   - ``64`` — usage/config error (already validated upstream where
              possible; raised only by ``loupe ci`` returning non-zero
              for non-finding reasons).
"""

from __future__ import annotations

import asyncio
import os
import sys
import traceback
from collections import Counter
from pathlib import Path
from typing import Any

import httpx
from loupe_cli.ci_cmd import ci_command
from loupe_core.artifacts.run_record import RunRecord
from loupe_core.artifacts.threat import Threat, ThreatsFile
from loupe_core.artifacts.types import Severity
from loupe_core.config import load_config
from ruamel.yaml import YAML

from loupe_action.comment_poster import (
    FreshCommentPoster,
    GitHubAPIError,
    StickyCommentPoster,
)
from loupe_action.formatter import format_pr_comment
from loupe_action.inputs import ActionInputs, InputError, parse_inputs
from loupe_action.pr_fetcher import PRFetcher, PRFetchError

_yaml = YAML()


async def run(*, env: dict[str, str], client: httpx.AsyncClient, cwd: Path) -> int:
    inputs = parse_inputs(env)
    workspace = Path(inputs.github_workspace or cwd)

    pr = await PRFetcher(
        client=client,
        repo_owner=inputs.repo_owner,
        repo_name=inputs.repo_name,
        pr_number=inputs.pr_number,
        token=inputs.github_token,
        api_url=inputs.github_api_url,
    ).fetch()

    ci_exit = await asyncio.to_thread(
        ci_command,
        pr.unified_diff,
        pr.base_sha,
        pr.head_sha,
        workspace / inputs.config_path,
    )

    record = _latest_run_record(workspace / ".loupe" / "runs")
    threats = _load_threats(workspace / ".loupe" / "threats.yaml")
    body = format_pr_comment(record=record, threats=threats)

    # action.yml documents three modes; pick the matching poster.
    # "new" historically fell through to StickyCommentPoster and silently
    # behaved like sticky — that's the bug this branch fixes.
    if inputs.comment_mode == "new":
        poster_cls: type[StickyCommentPoster] = FreshCommentPoster
    elif inputs.comment_mode == "sticky":
        poster_cls = StickyCommentPoster
    else:  # "none"
        poster_cls = None  # type: ignore[assignment]

    if poster_cls is not None:
        await poster_cls(
            client=client,
            repo_owner=inputs.repo_owner,
            repo_name=inputs.repo_name,
            pr_number=inputs.pr_number,
            token=inputs.github_token,
            api_url=inputs.github_api_url,
        ).post(body=body)

    # Trust the in-memory gate verdict from ``loupe ci``. The on-disk gate
    # is only used as a sanity check when ``ci_command`` reports clean.
    # Without this ordering, a pessimistic OR between in-memory and on-disk
    # verdicts can surface exit codes that ``action.yml`` doesn't document
    # (e.g. 64 OR 1 → 65) and obscures the user-facing failure reason.
    if ci_exit == 64:
        final_exit = 64  # usage/config error — surface directly
    elif ci_exit != 0:
        final_exit = ci_exit  # gate failure or other ci-mode failure
    else:
        config = load_config(workspace / inputs.config_path)
        final_exit = _gate_exit_code(threats=threats, fail_on=config.ci.fail_on)

    _write_outputs(
        inputs=inputs,
        record=record,
        threats=threats,
        exit_code=final_exit,
    )
    return final_exit


def _latest_run_record(runs_dir: Path) -> RunRecord:
    if not runs_dir.exists():
        raise RuntimeError(f"no .loupe/runs/ directory at {runs_dir} after ci_command")
    files = sorted(runs_dir.glob("*.json"))
    if not files:
        raise RuntimeError(f"no run records in {runs_dir} after ci_command")
    # Microsecond-precision filenames sort chronologically (see save_run_record).
    return RunRecord.model_validate_json(files[-1].read_text())


def _load_threats(path: Path) -> list[Threat]:
    if not path.exists():
        return []
    data = _yaml.load(path.read_text())
    if not data:
        return []
    return ThreatsFile.model_validate(data).threats


def _gate_exit_code(*, threats: list[Threat], fail_on: list[str]) -> int:
    if not fail_on:
        return 0
    fail_severities = {Severity(s) for s in fail_on if s in Severity._value2member_map_}
    if any(t.severity in fail_severities for t in threats):
        return 1
    return 0


def _write_outputs(
    *,
    inputs: ActionInputs,
    record: RunRecord,
    threats: list[Threat],
    exit_code: int,
) -> None:
    if inputs.github_output_path is None:
        return
    counts = Counter(t.severity.value for t in threats)
    pairs: dict[str, Any] = {
        "findings_count": str(len(threats)),
        "findings_critical": str(counts.get("critical", 0)),
        "findings_high": str(counts.get("high", 0)),
        "findings_medium": str(counts.get("medium", 0)),
        "findings_low": str(counts.get("low", 0)),
        "run_id": record.run_id,
        "run_hash": record.self_hash,
        "exit_code": str(exit_code),
    }
    with Path(inputs.github_output_path).open("a", encoding="utf-8") as f:
        for key, value in pairs.items():
            f.write(f"{key}={value}\n")


def main() -> int:
    async def _main() -> int:
        async with httpx.AsyncClient(timeout=30.0) as client:
            return await run(env=dict(os.environ), client=client, cwd=Path.cwd())

    try:
        return asyncio.run(_main())
    except (InputError, PRFetchError, GitHubAPIError) as exc:
        # Known/expected failure modes: report cleanly with the documented
        # 64 (EX_USAGE) exit code rather than a raw Python traceback.
        print(f"::error::{exc}", file=sys.stderr)
        return 64
    except KeyboardInterrupt:
        return 130
    except Exception:
        # Unexpected: still surface the full traceback for debuggability,
        # but settle on exit 1 (generic failure) per action.yml.
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
