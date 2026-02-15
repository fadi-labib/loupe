from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from loupe_action import entrypoint
from loupe_action.formatter import COMMENT_SENTINEL


def _env(workspace: Path, output: Path) -> dict[str, str]:
    return {
        "INPUT_PR": "42",
        "INPUT_CONFIG": "config.yaml",
        "INPUT_COMMENT_MODE": "sticky",
        "GITHUB_TOKEN": "ghp_test",
        "GITHUB_REPOSITORY": "acme/widgets",
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_OUTPUT": str(output),
        "GITHUB_WORKSPACE": str(workspace),
    }


def _seed_workspace(workspace: Path) -> None:
    loupe = workspace / ".loupe"
    (loupe / "runs").mkdir(parents=True)
    (workspace / "config.yaml").write_text(
        "schema_version: 1\n"
        "ci:\n"
        "  fail_on: [critical, high]\n"
    )
    record = {
        "run_id": "run-fixture",
        "timestamp": datetime.now(UTC).isoformat(),
        "mode": "ci",
        "invoked_by": "loupe-action",
        "trigger": "github_pr",
        "base_sha": "b" * 40,
        "head_sha": "h" * 40,
        "diff_hash": "d" * 64,
        "context_md_hash": "c" * 64,
        "lenses_considered": [],
        "lenses_run": ["threatlens"],
        "models_used": {},
        "total_tokens_in": 0,
        "total_tokens_out": 0,
        "cost_usd_estimate": 0.05,
        "cache_hit_rate": 0.5,
        "artifacts_changed": [],
        "proposed_patches": [],
        "pending_decisions": [],
        "prev_run_hash": None,
        "self_hash": "fixturehash",
    }
    (loupe / "runs" / "2026-05-15T00-00-00-000000Z-run-fixture.json").write_text(
        json.dumps(record)
    )


def _seed_threats(workspace: Path, severities: list[str]) -> None:
    threats = []
    for i, sev in enumerate(severities):
        threats.append(
            {
                "id": f"T-00{i+1}",
                "element_id": "E-001",
                "stride_category": "S",
                "title": f"Threat {i+1}",
                "description": "test description",
                "severity": sev,
                "status": "proposed",
                "mitigation_ids": [],
                "cwe_refs": [],
                "attack_pattern_refs": [],
                "last_reviewed": "2026-05-15",
                "rationale": "x",
                "proposed_by": "threatlens",
            }
        )
    (workspace / ".loupe" / "threats.yaml").write_text(
        "schema_version: 1\nthreats:\n"
        + "\n".join(
            [
                f"  - id: {t['id']}\n"
                f"    element_id: {t['element_id']}\n"
                f"    stride_category: {t['stride_category']}\n"
                f"    title: \"{t['title']}\"\n"
                f"    description: \"{t['description']}\"\n"
                f"    severity: {t['severity']}\n"
                f"    status: {t['status']}\n"
                f"    last_reviewed: {t['last_reviewed']}\n"
                f"    rationale: \"{t['rationale']}\"\n"
                f"    proposed_by: {t['proposed_by']}\n"
                for t in threats
            ]
        )
    )


def _api_handler(*, posted_bodies: list[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        accept = request.headers.get("accept", "")
        if "/pulls/42" in url and "diff" in accept:
            return httpx.Response(200, text="diff --git a/x b/x\n+x\n")
        if "/pulls/42" in url:
            return httpx.Response(
                200,
                json={"base": {"sha": "b" * 40}, "head": {"sha": "h" * 40}},
            )
        if "/comments" in url and request.method == "GET":
            return httpx.Response(200, json=[])
        if "/comments" in url and request.method == "POST":
            posted_bodies.append(request.content.decode())
            return httpx.Response(201, json={"id": 1})
        raise AssertionError(f"unexpected: {request.method} {url}")

    return handler


@pytest.mark.asyncio
async def test_entrypoint_runs_end_to_end_and_posts_comment(tmp_path: Path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    _seed_workspace(workspace)
    output = tmp_path / "gh_output"
    posted: list[str] = []
    handler = _api_handler(posted_bodies=posted)

    # ci_command writes to the workspace's .loupe/; we pre-seeded the run
    # record so we don't need the real lens pipeline here. The patch
    # returns 0 (clean ci exit) without touching the filesystem.
    with patch("loupe_action.entrypoint.ci_command", return_value=0):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            exit_code = await entrypoint.run(
                env=_env(workspace, output), client=client, cwd=workspace
            )

    assert exit_code == 0
    assert posted and posted[0].startswith('{"body":') and COMMENT_SENTINEL in posted[0]
    output_text = output.read_text()
    assert "findings_count=0" in output_text
    assert "run_id=run-fixture" in output_text
    assert "exit_code=0" in output_text


@pytest.mark.asyncio
async def test_entrypoint_exits_nonzero_when_fail_on_severity_present(tmp_path: Path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    _seed_workspace(workspace)
    _seed_threats(workspace, ["high"])
    output = tmp_path / "gh_output"
    handler = _api_handler(posted_bodies=[])

    with patch("loupe_action.entrypoint.ci_command", return_value=0):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            exit_code = await entrypoint.run(
                env=_env(workspace, output), client=client, cwd=workspace
            )

    assert exit_code == 1
    assert "exit_code=1" in output.read_text()


@pytest.mark.asyncio
async def test_entrypoint_skips_comment_when_mode_is_none(tmp_path: Path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    _seed_workspace(workspace)
    output = tmp_path / "gh_output"
    env = _env(workspace, output)
    env["INPUT_COMMENT_MODE"] = "none"

    posted: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if "/comments" in str(request.url):
            posted.append("LEAK")
            return httpx.Response(500)  # would fail if reached
        url = str(request.url)
        accept = request.headers.get("accept", "")
        if "/pulls/42" in url and "diff" in accept:
            return httpx.Response(200, text="diff --git a/x b/x\n+x\n")
        if "/pulls/42" in url:
            return httpx.Response(
                200,
                json={"base": {"sha": "b" * 40}, "head": {"sha": "h" * 40}},
            )
        raise AssertionError(f"unexpected: {request.method} {url}")

    with patch("loupe_action.entrypoint.ci_command", return_value=0):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            exit_code = await entrypoint.run(env=env, client=client, cwd=workspace)

    assert exit_code == 0
    assert posted == []  # comment_mode=none honoured


@pytest.mark.asyncio
async def test_entrypoint_writes_severity_counts_to_outputs(tmp_path: Path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    _seed_workspace(workspace)
    _seed_threats(workspace, ["critical", "high", "high", "medium"])
    output = tmp_path / "gh_output"
    handler = _api_handler(posted_bodies=[])

    with patch("loupe_action.entrypoint.ci_command", return_value=0):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await entrypoint.run(
                env=_env(workspace, output), client=client, cwd=workspace
            )

    output_text = output.read_text()
    assert "findings_count=4" in output_text
    assert "findings_critical=1" in output_text
    assert "findings_high=2" in output_text
    assert "findings_medium=1" in output_text
    assert "findings_low=0" in output_text
