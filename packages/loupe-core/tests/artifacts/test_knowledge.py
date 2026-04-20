from datetime import date, datetime

from loupe_core.artifacts.knowledge import (
    Asset,
    CrossReference,
    Decision,
    Element,
    KnowledgeGraph,
)


def test_knowledge_graph_empty_roundtrip(tmp_path):
    kg = KnowledgeGraph(last_updated=datetime(2026, 5, 13, 14, 32))
    p = tmp_path / "knowledge.yaml"
    kg.save(p)
    loaded = KnowledgeGraph.load(p)
    assert loaded.assets == []
    assert loaded.schema_version == 1


def test_knowledge_graph_with_entities(tmp_path):
    kg = KnowledgeGraph(
        last_updated=datetime(2026, 5, 13, 14, 32),
        assets=[
            Asset(
                id="A-001",
                name="payment_service",
                description="Processes payments",
                criticality="high",
                facts_supporting=["F-001"],
                first_identified=date(2026, 4, 2),
                confirmed_by_human=True,
            )
        ],
        elements=[
            Element(
                id="E-001", name="api-gateway", type="trust_boundary", interfaces=["ext:internet"]
            )
        ],
        decisions=[
            Decision(
                id="D-2026-04-15-skip-rate-limit",
                type="risk_acceptance",
                rationale_file=".loupe/decisions/D-2026-04-15-skip-rate-limit.md",
                authored_by="human",
            )
        ],
        cross_references=[CrossReference(asset="A-001", threat_ids=["T-007"])],
    )
    p = tmp_path / "knowledge.yaml"
    kg.save(p)
    loaded = KnowledgeGraph.load(p)
    assert loaded.assets[0].id == "A-001"
    assert loaded.cross_references[0].threat_ids == ["T-007"]


def test_knowledge_graph_load_missing_file_returns_empty(tmp_path):
    p = tmp_path / "knowledge.yaml"
    loaded = KnowledgeGraph.load_or_empty(p)
    assert loaded.schema_version == 1
    assert loaded.assets == []
