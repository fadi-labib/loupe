# Changelog

All notable changes to Loupe are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning will follow [SemVer](https://semver.org/) once v0.1 ships.

## [Unreleased]

The pre-alpha working set, in flight toward v0.1.

### Added

- Platform skeleton: `loupe-core`, `loupe-cli`, `loupe-threatlens`, `loupe-action` workspace packages.
- Nine artefact schemas (Pydantic models with YAML/JSON round-trip): `Threat`, `Mitigation`, `KnowledgeGraph`, `ProjectContext`, `LoupeConfig`, `RunRecord` (hash-chained), plus supporting types.
- Layer 1 enforcement: `PathBoundary`, `write_agent_artifact`, `propose_patch`, `BoundaryViolation`.
- `RunContext` within-run blackboard with namespaced findings + facts; `RunContext.bootstrap()` parses the diff and loads `context.md` and `knowledge.yaml`.
- Capability registry (D-18): `SbomCapability`, `CveCapability`, `SecretDetectionCapability`, `StaticAnalysisCapability` Protocols; composition modes (`single`, `fallback`, `union`, `consensus`, `pipeline`); bundled Syft and Grype backends.
- ThreatLens lens scaffolding: STRIDE-methodology system prompt, PydanticAI agent skeleton, `propose_threat` tool through Layer 1.
- CLI commands `loupe init`, `loupe ci`, `loupe verify`, `loupe chat` (placeholder), `loupe scan`.
- GitHub Action wrapper: typed input validation, PR diff fetcher, Markdown sticky-comment poster, six outputs (`findings_count`, per-severity counts, `run_id`, `run_hash`, `exit_code`).
- Two-tier evaluation methodology (D-19): Cesanta Mongoose (Tier 1) and Eclipse Mosquitto (Tier 2). Methodology recorded; scenario catalogue and scoring code pending.

### Designed, not yet shipped

- ThreatLens PydanticAI agent wired to a live LLM provider.
- `bootstrap_capabilities()` invocation inside `loupe ci` (today the wiring exists but is not called by the CLI flow).
- `loupe chat` conversational REPL (the command exists as a placeholder with a TTY guard).
- `loupe mcp` command and the MCP server implementation.
- Layer 2 branch-namespace enforcement with a fine-grained GitHub App token.
- `loupe verify` checks beyond hash-chain integrity (authorship, schema, cross-reference).
- Discovery subcommands (`loupe lens list`, `loupe cap list`).

## Versioning policy

Once v0.1 ships, the project follows SemVer for the public surface:

| Surface | What versioning means |
|---|---|
| `loupe-cli` public commands | Major bump on a breaking flag change or removal |
| `loupe-core` public Python API | Major bump on a breaking change to `LensCapabilities`, `RunContext`, `PathBoundary`, or the capability Protocols |
| Lens entry-point contract | Major bump on a method-signature change |
| Capability Protocols | Major bump on a Protocol method-signature change; minor on additions; result models version independently |
| Artefact schemas | The artefact's own `schema_version` field bumps independently of the package version, with documented migration where needed |
| GitHub Action inputs and outputs | Major bump on an input rename or output removal |

## Release process

This section will get more substantive once v0.1 is in flight. Outline:

1. CI green on `main` (tests, ruff, mypy, link check).
2. Update this CHANGELOG: move `[Unreleased]` content into the new version section, link the version's compare URL.
3. Tag the commit `v0.X.Y`.
4. Push the tag. The release workflow (to be added) builds wheels and publishes to PyPI.
5. Once the doc site is published, `mike deploy <version>` (mike is the standard MkDocs versioning tool) writes the versioned docs to the `gh-pages` branch.

[Unreleased]: https://github.com/fadilabib/loupe/commits/main
