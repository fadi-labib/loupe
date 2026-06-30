"""Build the per-run user prompt for the ThreatLens agent.

The system prompt (loaded from prompts/system.md at agent-construction time)
carries the stable framing: role, STRIDE definitions, severity rubric, output
discipline. That portion is cached across lens calls by Anthropic prompt
caching — it pays roughly 10% per call after the first.

The USER prompt — built here — is the variable per-run portion: the diff
under analysis, the human-authored project context, the SBOM and CVE
findings populated by the capability bootstrap, and any known
architectural elements the agent should reference with stable IDs.

See [principles.md §8 "Cost discipline"] and [decisions.md D-10] for the
prompt-assembly cost-lever rationale.
"""

from __future__ import annotations

from loupe_core.artifacts.context import BulletItem, ProjectContext
from loupe_core.capabilities.protocols import CveResult, SbomResult
from loupe_core.run_context import LensRunPlan, RunContext, ScopedSource

_DEFAULT_FOCUS = (
    "Analyse the diff below for STRIDE threats. Call `propose_threat` "
    "exactly once per threat. Cite assets from the project context in your "
    "rationale — do not invent assets that are not listed."
)

_NO_PROJECT_NOTICE = (
    "No project context loaded. Operate cautiously and call out missing "
    "context.md sections in the rationale of any threat you propose."
)

_NO_DIFF_NOTICE = (
    "No diff provided. Operating in full-repo or scoped mode; reason about the project as a whole."
)

_NO_ELEMENTS_NOTICE = (
    "No elements are defined in `knowledge.yaml` yet. Use `E-001`, "
    "`E-002`, ... in your `propose_threat` calls and describe each element "
    "in the threat description so a human can add them to the knowledge "
    "graph later."
)

# Maximum number of items rendered inline before truncation. The agent
# doesn't benefit from seeing all 500 SBOM components or all 80 CVE
# findings — the top N gives signal; the bottom is noise.
_MAX_SBOM_COMPONENTS = 30
_MAX_CVES_PER_SEVERITY = 10
_MAX_CHANGED_PATHS_IN_SUMMARY = 8


def build_user_prompt(ctx: RunContext, plan_entry: LensRunPlan) -> str:
    """Compose the user message for one ThreatLens agent run.

    The prompt is laid out as a STABLE PREFIX followed by a VARIABLE SUFFIX
    so Anthropic prompt caching can pin a breakpoint at the boundary
    [principle §8 — cost discipline; D-10]. The stable prefix carries the
    project context (anti-hallucination anchor), the diff under analysis,
    SBOM components, CVE findings, and known architectural elements — all
    of which are identical across plan entries within the same `run()`
    call. The variable suffix carries the per-plan-entry `sub_prompt`
    under a `## Focus for this run` header so two plan entries that differ
    only in `sub_prompt` share an identical prefix byte-for-byte.

    Empty sections render a short notice rather than disappearing so the
    agent knows what information is missing and can flag the gap.
    """
    # Stable prefix: identical across plan entries when ctx is unchanged.
    sections: list[str] = [
        _project_section(ctx.project),
        _diff_section(ctx),
    ]

    # D-24: scoped source files (from `loupe scan --paths …`). Empty
    # in diff-mode and full-repo scans — the section is omitted entirely
    # so ci-mode prompts stay byte-identical to pre-B.5 prompts (cache
    # breakpoint invariant). Placement between diff and SBOM keeps the
    # "what code are we looking at" content clustered.
    if ctx.scoped_sources:
        sections.append(_sources_section(ctx.scoped_sources))

    if ctx.sbom is not None and ctx.sbom.components:
        sections.append(_sbom_section(ctx.sbom))

    if ctx.cve_findings is not None and ctx.cve_findings.findings:
        sections.append(_cve_section(ctx.cve_findings))

    sections.append(_elements_section(ctx))

    # Variable suffix: per-plan-entry focus / sub_prompt. Goes LAST so the
    # prefix above can be cached by the model provider.
    sections.append(_focus_section(plan_entry))

    return "\n\n".join(sections)


def _focus_section(plan_entry: LensRunPlan) -> str:
    body = plan_entry.sub_prompt.strip() if plan_entry.sub_prompt else _DEFAULT_FOCUS
    return f"## Focus for this run\n\n{body}"


def _project_section(project: ProjectContext | None) -> str:
    if project is None:
        return f"## Project context\n\n{_NO_PROJECT_NOTICE}"
    return "\n\n".join(
        [
            "## Project context (from .loupe/context.md)",
            f"**Product:** {project.product_description}",
            f"**Critical assets:** {_render_bullets(project.assets)}",
            f"**Users and roles:** {_render_bullets(project.users)}",
            f"**Deployment:** {project.deployment}",
            f"**Threat actors of concern:** {_render_bullets(project.threat_actors)}",
            f"**Out of scope:** {_render_bullets(project.out_of_scope)}",
        ]
    )


def _diff_section(ctx: RunContext) -> str:
    if ctx.diff is None or not ctx.diff.raw_unified.strip():
        return f"## Code changes\n\n{_NO_DIFF_NOTICE}"
    path_count = len(ctx.diff.changed_paths)
    visible = ctx.diff.changed_paths[:_MAX_CHANGED_PATHS_IN_SUMMARY]
    files_summary = ", ".join(visible)
    if path_count > _MAX_CHANGED_PATHS_IN_SUMMARY:
        files_summary += f", … (+{path_count - _MAX_CHANGED_PATHS_IN_SUMMARY} more)"
    plural = "s" if path_count != 1 else ""
    return (
        f"## Code changes ({path_count} file{plural}: {files_summary})\n\n"
        f"```diff\n{ctx.diff.raw_unified}\n```"
    )


def _sources_section(scoped_sources: list[ScopedSource]) -> str:
    """D-24 — render scoped source files for `loupe scan --paths`.

    Each file becomes a fenced code block with the path as a header.
    Files that hit the per-file char cap carry a visible "(truncated
    at N chars)" subheader so the agent knows the content is partial
    and can flag findings as needing follow-up beyond the cut.

    Language hint on the fence is derived from the file extension —
    `.c`/`.cpp` -> c, `.py` -> python, etc. Falls back to plain text
    for unknown extensions (shouldn't happen given the CODE_EXTENSIONS
    filter in scan_cmd, but defensive).
    """
    blocks: list[str] = []
    for src in scoped_sources:
        ext = src.path.rsplit(".", 1)[-1].lower() if "." in src.path else ""
        lang = _EXT_TO_FENCE_LANG.get(ext, "")
        header = f"### {src.path}"
        if src.truncated_at is not None:
            header += f"\n_(truncated at {src.truncated_at} chars)_"
        fence = f"```{lang}\n{src.content}\n```"
        blocks.append(f"{header}\n\n{fence}")
    body = "\n\n".join(blocks)
    return f"## Source files under analysis\n\n{body}"


# Language-fence hints keyed on file extension. The loupe_core.fs
# CODE_EXTENSIONS list drives which files we read; this map only
# affects the fenced-code-block's syntax-highlighting hint.
_EXT_TO_FENCE_LANG: dict[str, str] = {
    "c": "c",
    "cpp": "cpp",
    "cs": "csharp",
    "go": "go",
    "java": "java",
    "js": "javascript",
    "jsx": "jsx",
    "kt": "kotlin",
    "py": "python",
    "rb": "ruby",
    "rs": "rust",
    "swift": "swift",
    "ts": "typescript",
    "tsx": "tsx",
}


def _sbom_section(sbom: SbomResult) -> str:
    visible = sbom.components[:_MAX_SBOM_COMPONENTS]
    component_lines = "\n".join(f"- {c.name}@{c.version}" for c in visible)
    note = ""
    if len(sbom.components) > _MAX_SBOM_COMPONENTS:
        note = f"\n\n_(showing first {_MAX_SBOM_COMPONENTS} of {len(sbom.components)} components)_"
    backend = sbom.backend_name or "unknown"
    return f"## SBOM components (backend: {backend})\n\n{component_lines}{note}"


def _cve_section(cves: CveResult) -> str:
    grouped = cves.by_severity()
    blocks: list[str] = []
    # Render severities in descending order so the agent reads critical first.
    for severity in ("critical", "high", "medium", "low", "informational"):
        items = grouped.get(severity, [])
        if not items:
            continue
        visible = items[:_MAX_CVES_PER_SEVERITY]
        lines = "\n".join(
            f"- **{f.cve_id}** in `{f.component_name}@{f.component_version}`: {f.summary}"
            for f in visible
        )
        overflow = len(items) - _MAX_CVES_PER_SEVERITY
        more = f" _(+{overflow} more)_" if overflow > 0 else ""
        blocks.append(f"### {severity.capitalize()}{more}\n\n{lines}")
    if not blocks:
        return ""
    backend = cves.backend_name or "unknown"
    return f"## CVE findings (backend: {backend})\n\n" + "\n\n".join(blocks)


def _elements_section(ctx: RunContext) -> str:
    if ctx.knowledge is None or not ctx.knowledge.elements:
        return f"## Known architectural elements\n\n{_NO_ELEMENTS_NOTICE}"
    lines = "\n".join(
        f"- **{e.id}** — {e.name} ({e.type}): "
        f"interfaces={', '.join(e.interfaces) if e.interfaces else 'none'}"
        for e in ctx.knowledge.elements
    )
    next_id = f"E-{len(ctx.knowledge.elements) + 1:03d}"
    return (
        "## Known architectural elements\n\n"
        f"Reference these element IDs in your `element_id` field. If a "
        f"threat targets an element not listed below, use `{next_id}` and "
        f"describe the new element in the threat's rationale so a human can "
        f"add it to `knowledge.yaml`.\n\n"
        f"{lines}"
    )


def _render_bullets(items: list[BulletItem]) -> str:
    """Render a list of BulletItems as a semicolon-separated line.

    BulletItem.__str__ rejoins `label: note` so descriptions survive — the
    parser at `context.py` deliberately preserved this round-trip.
    """
    if not items:
        return "(none listed)"
    return "; ".join(str(i) for i in items)
