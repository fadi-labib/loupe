from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class PromptParts(BaseModel):
    # STABLE — cached
    common_framing: str
    project_context: str
    diff_summary: str
    sbom_delta_summary: str
    relevant_artifacts: str
    # VARIABLE — not cached
    lens_system_prompt: str
    lens_task: str
    prior_findings_handover: str


def assemble_messages(parts: PromptParts) -> list[dict[str, Any]]:
    """Build provider-agnostic messages with stable prefix in system, variable in user.

    The system message is marked `cache_control: {type: 'ephemeral'}` so Anthropic
    prompt caching applies; providers that don't recognise the field ignore it.
    """
    system_content = "\n\n".join(filter(None, [
        parts.common_framing,
        f"## Project context\n{parts.project_context}" if parts.project_context else "",
        f"## Diff summary\n{parts.diff_summary}" if parts.diff_summary else "",
        f"## SBOM delta\n{parts.sbom_delta_summary}" if parts.sbom_delta_summary else "",
        (f"## Relevant existing artifacts\n{parts.relevant_artifacts}"
         if parts.relevant_artifacts else ""),
        f"## Lens framing\n{parts.lens_system_prompt}" if parts.lens_system_prompt else "",
    ]))
    user_content = parts.lens_task
    if parts.prior_findings_handover:
        user_content += f"\n\n## Prior findings\n{parts.prior_findings_handover}"

    return [
        {"role": "system", "content": system_content, "cache_control": {"type": "ephemeral"}},
        {"role": "user", "content": user_content},
    ]
