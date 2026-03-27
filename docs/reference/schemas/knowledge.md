# KnowledgeGraph

The persistent cross-run knowledge graph stored at `.loupe/knowledge.yaml`. Where `.loupe/runs/*.json` are one-per-invocation audit records, `knowledge.yaml` is the single growing file that survives between runs and accumulates what Loupe has learned about your codebase.

## What's in it

Five typed sections, each backed by a Pydantic model:

| Section | Holds | Stable-ID format |
|---|---|---|
| `assets` | Things worth protecting (data, keys, signing material). Mostly human-curated. | `A-NNN` |
| `elements` | System components referenced in threat models (a process, a trust boundary, a data store). | `E-NNN` |
| `decisions` | Pointers to human-authored ADRs at `.loupe/decisions/*.md`. Records risk acceptances and design choices. | `D-YYYY-MM-DD-<slug>` |
| `cross_references` | Per-asset map from asset to the threats / hazards / privacy concerns that touch it. The knowledge-graph cross-reference check is a planned `loupe verify` Layer 3 check; the threats↔mitigations cross-reference check (a related but separate check) is already shipped today. | n/a |

## Promotion rules

Lenses produce `Fact`s into `RunContext.facts` during a run. Only high-confidence Facts get *promoted* into `knowledge.yaml` (see [`decisions.md` D-07](../decisions.md#d-07)):

- A Fact corroborated by a human decision (a referenced `decisions/D-*.md` file with `authored_by: human`).
- OR a Fact independently produced by two or more separate runs.

This prevents the graph from filling with low-confidence agent guesses. Promotion happens at end-of-run inside `loupe-core`, not by the lens directly; lenses cannot bypass the rule.

## Lifecycle

`KnowledgeGraph.load_or_empty()` returns an empty graph (with `schema_version: 1`) if the file is missing. Deleting `.loupe/knowledge.yaml` is therefore safe: the next run rebuilds from scratch. The contents will not be re-promoted automatically; they will re-accumulate as runs land.

## On-disk format

`loupe init` scaffolds the file with a header comment plus the empty-graph YAML (every list defaulted to `[]`).

```yaml
# .loupe/knowledge.yaml
# Persistent knowledge graph populated across runs.
# Lenses promote high-confidence Facts here; humans curate the rest.
# Safe to delete to reset; the next run rebuilds an empty graph.
schema_version: 1
last_updated: 2026-05-15T20:53:00
assets: []
elements: []
decisions: []
cross_references: []
```

## KnowledgeGraph

::: loupe_core.artifacts.knowledge.KnowledgeGraph

## Asset

::: loupe_core.artifacts.knowledge.Asset

## Element

::: loupe_core.artifacts.knowledge.Element

## Decision

::: loupe_core.artifacts.knowledge.Decision

## CrossReference

::: loupe_core.artifacts.knowledge.CrossReference

## Cross-references

- `assets[].facts_supporting` holds fact IDs (`F-NNN`) recorded in run records. Whether each referenced fact exists is a planned `loupe verify` Layer 3 check, not a parse-time one.
- `decisions[].rationale_file` should resolve to an existing `.loupe/decisions/*.md` file. Same Layer 3 check.
- `cross_references[].asset` must match an `assets[].id` entry. Same Layer 3 check.

## See also

- [`concepts/architecture.md`](../../concepts/architecture.md) — where `knowledge.yaml` sits in the data flow.
- [`reference/loupe-directory.md`](../loupe-directory.md) — the layout map.
- [`decisions.md` D-07](../decisions.md#d-07) — promotion rules and motivation.
