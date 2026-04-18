"""Unit tests for the ThreatLens user-prompt builder.

No LLM call, no API key, no network. Verifies that the structured user
message passed to PydanticAI's `Agent.run(...)` contains the diff, the
project context, the SBOM, CVE findings, and known elements — and that
empty sections degrade gracefully with explicit "no X provided" notices.
"""
from datetime import datetime

from loupe_core.artifacts.context import BulletItem, ProjectContext
from loupe_core.artifacts.knowledge import Element, KnowledgeGraph
from loupe_core.capabilities.protocols import (
    CveFinding,
    CveResult,
    SbomComponent,
    SbomResult,
)
from loupe_core.run_context import (
    CodeDiff,
    LensRunPlan,
    RelevanceScore,
    RunContext,
)
from loupe_threatlens.user_prompt import build_user_prompt


def _project() -> ProjectContext:
    return ProjectContext(
        product_description="Payment processing API.",
        assets=[
            BulletItem(label="PAN", note="card numbers"),
            BulletItem(label="API keys"),
        ],
        users=[BulletItem(label="Customer", note="places orders")],
        deployment="Containerised on ECS Fargate.",
        threat_actors=[BulletItem(label="Compromised internal service")],
        out_of_scope=[BulletItem(label="Mobile app")],
    )


_DEFAULT_RAW_DIFF = (
    "diff --git a/src/api/refund.py b/src/api/refund.py\n"
    "+def refund(): pass"
)


def _diff(raw: str = _DEFAULT_RAW_DIFF) -> CodeDiff:
    return CodeDiff(
        base_sha="a", head_sha="b",
        changed_paths=["src/api/refund.py"],
        added_lines=1, removed_lines=0,
        raw_unified=raw,
    )


def _ctx(**overrides) -> RunContext:
    base = dict(
        run_id="r-1", mode="ci", started_at=datetime(2026, 5, 15),
        user_intent="test",
        diff=_diff(),
        sbom_delta=None, project=_project(), plan=[],
        knowledge=KnowledgeGraph(last_updated=datetime(2026, 5, 15)),
    )
    base.update(overrides)
    return RunContext(**base)


def _plan(sub_prompt: str = "Look for STRIDE-E in the new refund endpoint.") -> LensRunPlan:
    return LensRunPlan(
        lens_name="threatlens",
        relevance=RelevanceScore(score=0.95, reason="code"),
        depends_on=[],
        sub_prompt=sub_prompt,
    )


def test_includes_focus_from_plan():
    out = build_user_prompt(_ctx(), _plan())
    assert "Look for STRIDE-E in the new refund endpoint." in out


def test_focus_falls_back_when_plan_has_no_sub_prompt():
    out = build_user_prompt(_ctx(), _plan(sub_prompt=""))
    assert "STRIDE threats" in out
    assert "propose_threat" in out


def test_includes_project_assets_with_notes():
    """BulletItem notes survive — context.md role descriptions reach the agent."""
    out = build_user_prompt(_ctx(), _plan())
    assert "PAN: card numbers" in out
    assert "Customer: places orders" in out
    assert "API keys" in out


def test_includes_raw_diff_in_fenced_block():
    out = build_user_prompt(_ctx(), _plan())
    assert "+def refund(): pass" in out
    assert "```diff" in out
    assert "src/api/refund.py" in out


def test_renders_sbom_when_present():
    ctx = _ctx(sbom=SbomResult(
        components=[
            SbomComponent(name="requests", version="2.31.0"),
            SbomComponent(name="fastapi", version="0.104.0"),
        ],
        backend_name="syft",
    ))
    out = build_user_prompt(ctx, _plan())
    assert "requests@2.31.0" in out
    assert "fastapi@0.104.0" in out
    assert "backend: syft" in out


def test_truncates_large_sbom_with_count_note():
    components = [SbomComponent(name=f"pkg{i}", version="1.0") for i in range(50)]
    ctx = _ctx(sbom=SbomResult(components=components, backend_name="syft"))
    out = build_user_prompt(ctx, _plan())
    assert "showing first 30 of 50 components" in out
    assert "pkg0@1.0" in out
    assert "pkg29@1.0" in out
    assert "pkg49@1.0" not in out


def test_renders_cve_findings_grouped_by_severity():
    ctx = _ctx(cve_findings=CveResult(
        findings=[
            CveFinding(
                cve_id="CVE-2024-1234",
                component_name="requests", component_version="2.31.0",
                severity="critical", summary="Auth bypass via header injection.",
            ),
            CveFinding(
                cve_id="CVE-2024-5678",
                component_name="fastapi", component_version="0.104.0",
                severity="medium", summary="DoS via large multipart upload.",
            ),
        ],
        backend_name="grype",
    ))
    out = build_user_prompt(ctx, _plan())
    assert "CVE-2024-1234" in out
    assert "CVE-2024-5678" in out
    assert "Critical" in out
    assert "Medium" in out
    assert "backend: grype" in out
    # Critical block appears before the medium block — descending severity.
    assert out.index("CVE-2024-1234") < out.index("CVE-2024-5678")


def test_falls_back_gracefully_with_no_project():
    out = build_user_prompt(_ctx(project=None), _plan())
    assert "No project context loaded" in out


def test_handles_empty_diff():
    out = build_user_prompt(_ctx(diff=None), _plan())
    assert "No diff provided" in out


def test_renders_known_elements_with_ids():
    knowledge = KnowledgeGraph(
        last_updated=datetime(2026, 5, 15),
        elements=[
            Element(
                id="E-001", name="api-gateway", type="trust_boundary",
                interfaces=["ext:internet", "int:payment_service"],
            ),
        ],
    )
    out = build_user_prompt(_ctx(knowledge=knowledge), _plan())
    assert "E-001" in out
    assert "api-gateway" in out
    # Next-available ID hint so the agent can propose a new element by ID.
    assert "E-002" in out


def test_elements_section_falls_back_when_empty():
    out = build_user_prompt(_ctx(), _plan())
    assert "No elements are defined" in out


def test_sections_appear_in_canonical_order():
    """Stable prefix (project → diff → SBOM → CVE → elements) precedes the
    variable suffix (focus / sub_prompt). The focus section is moved to the
    trailing slot so Anthropic prompt caching can pin a breakpoint at the
    end of the stable prefix [principle §8 cost discipline, D-10]."""
    ctx = _ctx(
        sbom=SbomResult(
            components=[SbomComponent(name="x", version="1")],
            backend_name="syft",
        ),
        cve_findings=CveResult(
            findings=[
                CveFinding(
                    cve_id="CVE-2024-0001", component_name="x", component_version="1",
                    severity="high", summary="example",
                ),
            ],
            backend_name="grype",
        ),
    )
    out = build_user_prompt(ctx, _plan())
    sections_in_order = [
        "## Project context",
        "## Code changes",
        "## SBOM components",
        "## CVE findings",
        "## Known architectural elements",
        "## Focus for this run",
    ]
    last_index = -1
    for marker in sections_in_order:
        idx = out.find(marker)
        assert idx > last_index, f"{marker} appeared out of order"
        last_index = idx


def test_user_prompt_prefix_stable_across_subprompts():
    """Two plan entries with different sub_prompts share the same prefix up
    to the variable-suffix marker. This is the prompt-cache contract: only
    the trailing focus section may differ when ctx is identical."""
    ctx = _ctx(
        sbom=SbomResult(
            components=[SbomComponent(name="x", version="1")],
            backend_name="syft",
        ),
        cve_findings=CveResult(
            findings=[
                CveFinding(
                    cve_id="CVE-2024-0001", component_name="x", component_version="1",
                    severity="high", summary="example",
                ),
            ],
            backend_name="grype",
        ),
    )
    plan_a = _plan(sub_prompt="Look for STRIDE-S threats only.")
    plan_b = _plan(sub_prompt="Look exclusively at info-disclosure paths in refund.py.")

    a = build_user_prompt(ctx, plan_a)
    b = build_user_prompt(ctx, plan_b)

    marker = "## Focus for this run"
    pos_a = a.find(marker)
    pos_b = b.find(marker)
    assert pos_a > 0 and pos_b > 0, "marker must be present in both outputs"
    assert pos_a == pos_b, "stable prefix length must be identical"
    assert a[:pos_a] == b[:pos_b], (
        "stable prefix content must be byte-identical when only sub_prompt differs"
    )
