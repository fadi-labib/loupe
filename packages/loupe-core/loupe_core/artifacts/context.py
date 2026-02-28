from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

_REQUIRED_SECTIONS = [
    "Product description",
    "Critical assets",
    "Users and roles",
    "Deployment",
    "Threat actors of concern",
    "Out of scope",
]


class ContextMdError(ValueError):
    """Raised when `.loupe/context.md` is missing a required section or fails to parse."""


class ProjectContext(BaseModel):
    """Parsed representation of `.loupe/context.md`, the human-authored product brief.

    Anti-hallucination anchor: every run reads it so the LLM knows what the product
    actually does. The agent cannot edit it directly; it can only propose patches.
    `from_markdown(path)` parses the Markdown file and raises `ContextMdError` on
    a missing required section.
    """

    product_description: str = Field(description="Two or three sentences describing the product.")
    assets: list[str] = Field(description="Critical assets (data, keys, signing material).")
    users: list[str] = Field(description="User types and what each can do.")
    deployment: str = Field(description="Where the product runs; trust-boundary topology.")
    threat_actors: list[str] = Field(description="Who you worry about (insider, supply chain).")
    out_of_scope: list[str] = Field(description="Threats you deliberately do not address.")

    @classmethod
    def from_markdown(cls, path: Path) -> ProjectContext:
        text = path.read_text()
        body = _strip_frontmatter(text)
        sections = _split_sections(body)
        for required in _REQUIRED_SECTIONS:
            if required not in sections:
                raise ContextMdError(f"context.md missing required section: '{required}'")
        return cls(
            product_description=sections["Product description"].strip(),
            assets=_parse_bullets(sections["Critical assets"]),
            users=_parse_bullets(sections["Users and roles"]),
            deployment=sections["Deployment"].strip(),
            threat_actors=_parse_bullets(sections["Threat actors of concern"]),
            out_of_scope=_parse_bullets(sections["Out of scope"]),
        )


def _strip_frontmatter(text: str) -> str:
    if text.startswith("---"):
        _, _frontmatter, body = text.split("---", 2)
        return body
    return text


def _split_sections(body: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current_name: str | None = None
    current_lines: list[str] = []
    for line in body.splitlines():
        m = re.match(r"^##\s+(.+)$", line)
        if m:
            if current_name is not None:
                sections[current_name] = "\n".join(current_lines)
            current_name = m.group(1).strip()
            current_lines = []
        elif current_name is not None:
            current_lines.append(line)
    if current_name is not None:
        sections[current_name] = "\n".join(current_lines)
    return sections


def _parse_bullets(section_body: str) -> list[str]:
    items: list[str] = []
    for line in section_body.splitlines():
        stripped = line.strip()
        if stripped.startswith("- "):
            items.append(stripped[2:].split(":", 1)[0].strip())
        elif stripped.startswith("* "):
            items.append(stripped[2:].split(":", 1)[0].strip())
    return items
