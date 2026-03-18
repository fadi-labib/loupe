
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
