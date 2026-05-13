from __future__ import annotations

import pytest
from loupe_action.inputs import ActionInputs, InputError, parse_inputs


def _env(**overrides: str) -> dict[str, str]:
    base = {
        "INPUT_PR": "42",
        "INPUT_CONFIG": ".loupe/config.yaml",
        "INPUT_COMMENT_MODE": "sticky",
        "GITHUB_TOKEN": "ghp_token",
        "GITHUB_REPOSITORY": "acme/widgets",
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_OUTPUT": "/tmp/gh_output",
        "GITHUB_WORKSPACE": "/runner/_work/widgets/widgets",
    }
    base.update(overrides)
    return base


def test_parse_returns_typed_inputs_for_happy_path():
    inputs = parse_inputs(_env())
    assert isinstance(inputs, ActionInputs)
    assert inputs.pr_number == 42
    assert inputs.config_path == ".loupe/config.yaml"
    assert inputs.comment_mode == "sticky"
    assert inputs.repo_owner == "acme"
    assert inputs.repo_name == "widgets"
    assert inputs.github_token == "ghp_token"


def test_pr_must_be_digits_only():
    with pytest.raises(InputError, match="pr"):
        parse_inputs(_env(INPUT_PR="abc"))


def test_pr_must_be_positive():
    with pytest.raises(InputError, match="positive"):
        parse_inputs(_env(INPUT_PR="0"))


def test_comment_mode_must_be_known_value():
    with pytest.raises(InputError, match="comment_mode"):
        parse_inputs(_env(INPUT_COMMENT_MODE="loud"))


def test_comment_mode_defaults_to_sticky_when_absent():
    env = _env()
    env.pop("INPUT_COMMENT_MODE")
    inputs = parse_inputs(env)
    assert inputs.comment_mode == "sticky"


def test_github_token_required():
    env = _env()
    env.pop("GITHUB_TOKEN")
    with pytest.raises(InputError, match="GITHUB_TOKEN"):
        parse_inputs(env)


def test_github_repository_must_have_owner_and_name():
    with pytest.raises(InputError, match="owner/repo"):
        parse_inputs(_env(GITHUB_REPOSITORY="just-a-name"))


def test_config_path_rejects_shell_metacharacters():
    # Layered defence: action.yml already rejects these in bash, but
    # python-side validation prevents the entrypoint from being driven
    # directly with a hostile env in local-dev or future invocations.
    for hostile in (".loupe;rm -rf /", ".loupe`whoami`", ".loupe$(id)"):
        with pytest.raises(InputError, match="config"):
            parse_inputs(_env(INPUT_CONFIG=hostile))


def test_config_path_rejects_absolute_outside_workspace():
    with pytest.raises(InputError, match="absolute"):
        parse_inputs(_env(INPUT_CONFIG="/etc/passwd"))


def test_config_path_rejects_parent_traversal():
    with pytest.raises(InputError, match="traversal"):
        parse_inputs(_env(INPUT_CONFIG="../../etc/passwd"))


def test_api_url_defaults_for_github_dotcom():
    env = _env()
    env.pop("GITHUB_API_URL")
    inputs = parse_inputs(env)
    assert inputs.github_api_url == "https://api.github.com"


def test_api_url_used_for_github_enterprise():
    inputs = parse_inputs(_env(GITHUB_API_URL="https://ghe.acme.internal/api/v3"))
    assert inputs.github_api_url == "https://ghe.acme.internal/api/v3"


def test_action_inputs_accepts_new_auto_commit_fields():
    """New v0.1 fields: auto_commit_loupe_dir, commit_author, loupe_pat."""
    env = _env(INPUT_AUTO_COMMIT_LOUPE_DIR="false")
    result = parse_inputs(env)
    assert result.auto_commit_loupe_dir is False
    assert result.commit_author == "loupe-agent <noreply@loupe.security>"
    assert result.loupe_pat is None


def test_action_inputs_auto_commit_loupe_dir_parses_true():
    env = _env(
        INPUT_AUTO_COMMIT_LOUPE_DIR="true",
        INPUT_LOUPE_PAT="github_pat_xxx",
    )
    result = parse_inputs(env)
    assert result.auto_commit_loupe_dir is True
    assert result.loupe_pat == "github_pat_xxx"


def test_action_inputs_opt_in_without_pat_raises():
    """auto_commit_loupe_dir=true MUST have a PAT supplied via input or env."""
    env = _env(INPUT_AUTO_COMMIT_LOUPE_DIR="true")
    with pytest.raises(InputError, match="requires LOUPE_PAT"):
        parse_inputs(env)


def test_action_inputs_opt_in_with_env_pat_only_succeeds():
    """LOUPE_PAT env var is sufficient (no Action input needed)."""
    env = _env(INPUT_AUTO_COMMIT_LOUPE_DIR="true", LOUPE_PAT="github_pat_from_env")
    result = parse_inputs(env)
    assert result.loupe_pat == "github_pat_from_env"


def test_action_inputs_opt_in_input_pat_takes_precedence():
    """When both INPUT_LOUPE_PAT and LOUPE_PAT are set, input wins."""
    env = _env(
        INPUT_AUTO_COMMIT_LOUPE_DIR="true",
        INPUT_LOUPE_PAT="github_pat_from_input",
        LOUPE_PAT="github_pat_from_env",
    )
    result = parse_inputs(env)
    assert result.loupe_pat == "github_pat_from_input"


def test_action_inputs_opt_out_no_pat_ok():
    """opt-out + no PAT is fine; loupe_pat stays None."""
    env = _env()
    env.pop("INPUT_COMMENT_MODE")  # remove optional field
    result = parse_inputs(env)
    assert result.auto_commit_loupe_dir is False
    assert result.loupe_pat is None
