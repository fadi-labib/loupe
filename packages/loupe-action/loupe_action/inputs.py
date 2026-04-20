"""GitHub Action input parsing.

Reads ``INPUT_*`` environment variables (the GitHub Actions convention)
plus the standard ``GITHUB_*`` runner env, validates them, and returns
a typed ``ActionInputs`` object. Every entrypoint code path goes through
``parse_inputs()`` — direct env access is prohibited downstream so the
validation layer can't be bypassed.

The validation here is a *defence in depth* layer over the bash-side
checks already in ``action.yml`` (VALUES §3): the Action's shell step
rejects shell metacharacters before the Python process even starts, and
this module rejects them again so the entrypoint stays safe if anyone
ever invokes it directly without the shell wrapper.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

CommentMode = Literal["sticky", "new", "none"]
_VALID_COMMENT_MODES = ("sticky", "new", "none")
_HOSTILE_PATH_FRAGMENTS = ("\n", "\0", ";", "|", "&", "`", "$(", "$\\")


class InputError(ValueError):
    """Raised when an Action input fails validation."""


class ActionInputs(BaseModel):
    pr_number: int = Field(gt=0)
    config_path: str
    comment_mode: CommentMode = "sticky"
    repo_owner: str
    repo_name: str
    github_token: str
    github_api_url: str = "https://api.github.com"
    github_output_path: str | None = None
    github_workspace: str | None = None


def parse_inputs(env: dict[str, str]) -> ActionInputs:
    pr_raw = env.get("INPUT_PR", "").strip()
    if not pr_raw.isdigit():
        raise InputError(f"pr input must be digits only, got: {pr_raw!r}")
    pr_number = int(pr_raw)
    if pr_number <= 0:
        raise InputError(f"pr input must be positive, got: {pr_number}")

    config_path = env.get("INPUT_CONFIG", ".loupe/config.yaml").strip()
    _validate_config_path(config_path)

    mode_raw = env.get("INPUT_COMMENT_MODE", "sticky").strip() or "sticky"
    if mode_raw not in _VALID_COMMENT_MODES:
        raise InputError(f"comment_mode must be one of {_VALID_COMMENT_MODES}, got: {mode_raw!r}")

    token = env.get("GITHUB_TOKEN", "").strip()
    if not token:
        raise InputError(
            "GITHUB_TOKEN is required (pass via env: GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }})"
        )

    repo = env.get("GITHUB_REPOSITORY", "").strip()
    if "/" not in repo or repo.count("/") != 1:
        raise InputError(f"GITHUB_REPOSITORY must be 'owner/repo', got: {repo!r}")
    owner, name = repo.split("/", 1)
    if not owner or not name:
        raise InputError(f"GITHUB_REPOSITORY must be 'owner/repo', got: {repo!r}")

    return ActionInputs(
        pr_number=pr_number,
        config_path=config_path,
        comment_mode=mode_raw,  # type: ignore[arg-type]  # validated above
        repo_owner=owner,
        repo_name=name,
        github_token=token,
        github_api_url=env.get("GITHUB_API_URL", "https://api.github.com").strip()
        or "https://api.github.com",
        github_output_path=env.get("GITHUB_OUTPUT") or None,
        github_workspace=env.get("GITHUB_WORKSPACE") or None,
    )


def _validate_config_path(path: str) -> None:
    for fragment in _HOSTILE_PATH_FRAGMENTS:
        if fragment in path:
            raise InputError(f"config input contains disallowed character {fragment!r}")
    if path.startswith("/"):
        raise InputError(f"config path must be relative to the workspace, got absolute: {path!r}")
    if ".." in path.split("/"):
        raise InputError(f"config path must not contain parent-directory traversal, got: {path!r}")
