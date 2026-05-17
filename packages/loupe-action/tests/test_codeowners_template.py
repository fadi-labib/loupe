"""Drift guard: .github/CODEOWNERS and docs/templates/CODEOWNERS.example
must be byte-identical. The template is what downstream repos copy; the
.github/ file is Loupe's dogfood. Drift between them means downstream
repos receive a different policy than Loupe self-applies."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_codeowners_dogfood_matches_template():
    dogfood = (REPO_ROOT / ".github" / "CODEOWNERS").read_text()
    template = (REPO_ROOT / "docs" / "templates" / "CODEOWNERS.example").read_text()
    assert dogfood == template, "CODEOWNERS files diverged — re-sync or update both."
