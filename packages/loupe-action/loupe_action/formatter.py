"""Render a RunRecord + threat list as a sticky PR comment.

The output is plain GitHub-flavoured Markdown with one machine-readable
detail: ``COMMENT_SENTINEL`` is the first line. The sticky-comment poster
greps for that marker to find a prior Loupe comment and edit it instead
of creating a duplicate. Users never see the sentinel because it's an
HTML comment.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable

from loupe_core.artifacts.run_record import RunRecord
from loupe_core.artifacts.threat import Threat
from loupe_core.artifacts.types import Severity, StrideCategory

COMMENT_SENTINEL = "<!-- loupe-action:sticky-comment v1 -->"

_MD_SPECIAL = re.compile(r"([\\*_`\[\]<>])")


def markdown_escape(text: str) -> str:
    """Escape Markdown special characters AND strip HTML-comment end-marker.

    Agent-supplied text (threat titles, descriptions) gets interpolated into
    the sticky-comment body. An attacker controlling the threat title could
    otherwise break sticky-comment formatting (``**``, ``[`` ``]``) or — more
    seriously — close the ``COMMENT_SENTINEL`` HTML-comment marker with
    ``-->``, which would change what the find-or-create loop matches on.

    The end-marker is stripped rather than escaped because backslash-escaping
    has no effect inside HTML comments; deletion is the only safe move.
    """
    return _MD_SPECIAL.sub(r"\\\1", text).replace("-->", "")

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
)

_SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
}

_STRIDE_LABEL: dict[StrideCategory, str] = {
    StrideCategory.SPOOFING: "Spoofing",
    StrideCategory.TAMPERING: "Tampering",
    StrideCategory.REPUDIATION: "Repudiation",
    StrideCategory.INFORMATION_DISCLOSURE: "Information disclosure",
    StrideCategory.DENIAL_OF_SERVICE: "Denial of service",
    StrideCategory.ELEVATION_OF_PRIVILEGE: "Elevation of privilege",
}


def format_pr_comment(*, record: RunRecord, threats: Iterable[Threat]) -> str:
    threats_list = list(threats)
    parts: list[str] = [
        COMMENT_SENTINEL,
        "## Loupe analysis",
        "",
        _summary_line(threats_list),
        "",
        _findings_section(threats_list),
        "",
        _run_metadata_section(record),
    ]
    return "\n".join(parts).rstrip() + "\n"


def _summary_line(threats: list[Threat]) -> str:
    if not threats:
        return "No threats identified in this change."
    counts = Counter(t.severity for t in threats)
    summary_parts = [
        f"{counts[sev]} {sev.value}" for sev in _SEVERITY_ORDER if counts[sev]
    ]
    return f"**Findings:** {', '.join(summary_parts)}."


def _findings_section(threats: list[Threat]) -> str:
    if not threats:
        return "<sub>No threats identified — clean run.</sub>"
    by_severity: dict[Severity, list[Threat]] = {s: [] for s in _SEVERITY_ORDER}
    for t in threats:
        by_severity[t.severity].append(t)
    lines: list[str] = []
    for sev in _SEVERITY_ORDER:
        bucket = by_severity[sev]
        if not bucket:
            continue
        emoji = _SEVERITY_EMOJI[sev]
        lines.append(f"### {emoji} {sev.value.title()} ({len(bucket)})")
        lines.append("")
        for t in bucket:
            stride = _STRIDE_LABEL.get(t.stride_category, t.stride_category.value)
            safe_title = markdown_escape(t.title)
            safe_first_line = markdown_escape(t.description.splitlines()[0])
            lines.append(f"- **{t.id} — {safe_title}**  ({stride})")
            lines.append(f"  {safe_first_line}")
            if t.mitigation_ids:
                lines.append(f"  Mitigations: {', '.join(t.mitigation_ids)}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _run_metadata_section(record: RunRecord) -> str:
    cost = f"${record.cost_usd_estimate:.2f}" if record.cost_usd_estimate else "$0.00"
    cache = (
        f"{record.cache_hit_rate * 100:.0f}%" if record.cache_hit_rate is not None else "n/a"
    )
    lenses = ", ".join(record.lenses_run) if record.lenses_run else "(none)"
    lines = [
        "<details>",
        "<summary>Run details</summary>",
        "",
        f"- **Run:** `{record.run_id}`",
        f"- **Lenses run:** {lenses}",
        f"- **Cost (estimate):** {cost}",
        f"- **Prompt-cache hit rate:** {cache}",
        f"- **Run hash:** `{record.self_hash}`",
    ]
    if record.proposed_patches:
        patches = "\n".join(f"  - `{p}`" for p in record.proposed_patches)
        lines.append("- **Proposed patches (awaiting review):**")
        lines.append(patches)
    if record.pending_decisions:
        decisions = ", ".join(f"`{d}`" for d in record.pending_decisions)
        lines.append(f"- **Pending decisions:** {decisions}")
    lines.extend(
        [
            "",
            "</details>",
        ]
    )
    return "\n".join(lines)
