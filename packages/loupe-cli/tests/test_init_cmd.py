from loupe_cli.__main__ import app
from typer.testing import CliRunner

runner = CliRunner()


def test_init_creates_loupe_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0, result.stdout
    assert (tmp_path / ".loupe").is_dir()
    assert (tmp_path / ".loupe" / "context.md").exists()
    assert (tmp_path / ".loupe" / "config.yaml").exists()
    assert (tmp_path / ".loupe" / "knowledge.yaml").exists()
    assert (tmp_path / ".loupe" / "runs").is_dir()
    assert (tmp_path / ".loupe" / "decisions").is_dir()


def test_init_knowledge_loads(tmp_path, monkeypatch):
    """The scaffolded knowledge.yaml must round-trip through KnowledgeGraph.load."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    from loupe_core.artifacts.knowledge import KnowledgeGraph

    kg = KnowledgeGraph.load(tmp_path / ".loupe" / "knowledge.yaml")
    assert kg.schema_version == 1
    assert kg.assets == []
    assert kg.elements == []
    assert kg.decisions == []
    text = (tmp_path / ".loupe" / "knowledge.yaml").read_text()
    assert text.startswith("# .loupe/knowledge.yaml"), "expected leading banner comment"


def test_init_refuses_if_already_initialized(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".loupe").mkdir()
    result = runner.invoke(app, ["init"])
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "already exists" in combined.lower()


def test_init_context_has_required_sections(tmp_path, monkeypatch):
    """The scaffolded context.md must parse with ProjectContext.from_markdown."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    # The bare scaffold has TODO placeholders but the section headers must be
    # all present so ProjectContext doesn't error out later.
    text = (tmp_path / ".loupe" / "context.md").read_text()
    for required in [
        "## Product description",
        "## Critical assets",
        "## Users and roles",
        "## Deployment",
        "## Threat actors of concern",
        "## Out of scope",
    ]:
        assert required in text, f"scaffold missing section: {required}"


def test_init_config_loads(tmp_path, monkeypatch):
    """The scaffolded config.yaml must round-trip through LoupeConfig."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    from loupe_core.config import load_config

    cfg = load_config(tmp_path / ".loupe" / "config.yaml")
    assert cfg.schema_version == 1
    assert "threatlens" in cfg.lenses
    assert ".loupe/threats.yaml" in cfg.agent_writable_paths


def test_init_ships_commented_capabilities_skeleton(tmp_path, monkeypatch):
    """The scaffolded config.yaml ships with a commented-out `capabilities:`
    block. Without it, `loupe ci` warned "capability bootstrap failed" on
    every fresh install because ThreatLens declares `requires: [sbom, cve]`
    but no backend was bound. With the skeleton in place, the user has a
    copy-paste template — uncomment, edit, capabilities resolve."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    text = (tmp_path / ".loupe" / "config.yaml").read_text()
    # The block exists and is commented out (so it doesn't activate
    # backends without operator opt-in).
    assert "# capabilities:" in text
    assert "#   sbom:" in text
    assert "#     backends: [syft]" in text
    assert "#   cve:" in text
    # Round-trip: with everything commented, the config still parses.
    from loupe_core.config import load_config

    cfg = load_config(tmp_path / ".loupe" / "config.yaml")
    assert cfg.schema_version == 1


def test_init_dry_run_makes_no_filesystem_changes(tmp_path, monkeypatch):
    """`--dry-run` lists actions but writes nothing — useful for previewing
    a regeneration without committing."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init", "--dry-run"])
    assert result.exit_code == 0, result.stdout
    assert not (tmp_path / ".loupe").exists()
    assert "Dry run" in result.stdout
    assert "create" in result.stdout


def test_init_force_regenerates_scaffold_in_existing_loupe(tmp_path, monkeypatch):
    """`--force` over an existing .loupe/ regenerates config.yaml and
    knowledge.yaml from the template (handles the case where the operator
    upgraded loupe-cli and wants the latest defaults)."""
    monkeypatch.chdir(tmp_path)
    # First init.
    runner.invoke(app, ["init"])
    # Mutate the config so we can detect regeneration.
    config_path = tmp_path / ".loupe" / "config.yaml"
    config_path.write_text("schema_version: 1\nstale: yes\n")

    result = runner.invoke(app, ["init", "--force"])
    assert result.exit_code == 0, result.stdout
    # Regenerated content includes the threatlens block from _DEFAULT_CONFIG.
    text = config_path.read_text()
    assert "threatlens:" in text
    assert "stale: yes" not in text


def test_init_force_preserves_edited_context(tmp_path, monkeypatch):
    """`--force` must NOT clobber a context.md the user has filled in.
    The whole point of context.md is operator-authored product context;
    silently regenerating it from template would destroy that work."""
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])
    context_path = tmp_path / ".loupe" / "context.md"
    edited = "# Product Context\n\nOur SaaS handles payment cards.\n"
    context_path.write_text(edited)

    result = runner.invoke(app, ["init", "--force"])
    assert result.exit_code == 0, result.stdout
    assert context_path.read_text() == edited
    assert "preserved" in result.stdout.lower() or "preserved" in (result.stderr or "").lower()


def test_init_without_force_refuses_when_loupe_exists(tmp_path, monkeypatch):
    """Without --force, init must still refuse on an existing .loupe/ —
    no behaviour change for users who relied on the old guard."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".loupe").mkdir()
    result = runner.invoke(app, ["init"])
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    # Hint about --force is part of the new message.
    assert "--force" in combined


def test_init_scaffolds_knowledge_in_writable_paths(tmp_path, monkeypatch):
    """knowledge.yaml MUST be agent-writable from the scaffold — the lens
    layer promotes facts there on first run; without this entry, the very
    first lens run hits PathBoundaryViolation."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0, result.stdout
    from loupe_core.config import load_config

    cfg = load_config(tmp_path / ".loupe" / "config.yaml")
    assert ".loupe/knowledge.yaml" in cfg.agent_writable_paths
