# Changelog

All notable changes to Loupe are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning will follow [SemVer](https://semver.org/) once v0.1 ships.

## [Unreleased]

The pre-alpha working set, in flight toward v0.1.

### Added

- Platform skeleton: `loupe-core`, `loupe-cli`, `loupe-threatlens`, `loupe-action` workspace packages.
- Nine artefact schemas (Pydantic models with YAML/JSON round-trip): `Threat`, `Mitigation`, `KnowledgeGraph`, `ProjectContext`, `LoupeConfig`, `RunRecord` (hash-chained), plus supporting types.
- Layer 1 enforcement: `PathBoundary`, `write_agent_artifact`, `propose_patch`, `BoundaryViolation`.
- `RunContext` within-run blackboard with namespaced findings + facts; `RunContext.bootstrap()` parses the diff and loads `context.md` and `knowledge.yaml`.
- Capability registry (D-18): `SbomCapability`, `CveCapability`, `SecretDetectionCapability`, `StaticAnalysisCapability` Protocols; composition modes (`single`, `fallback`, `union`, `consensus`, `pipeline`); `bootstrap_capabilities()` wired into `loupe ci`.
- Ten bundled capability backends: Syft and cdxgen (SBOM); Grype and osv-scanner (CVE); gitleaks, TruffleHog, and detect-secrets (secret detection); Semgrep, CodeQL, and Bandit (static analysis). Every capability now has at least two backends, so composition modes are usable out of the box.
- ThreatLens lens: STRIDE-methodology system prompt, PydanticAI agent wired to a live LLM, agent prompt includes diff, project context, SBOM delta, CVE list, and architectural elements; `propose_threat` tool through Layer 1.
- CLI commands `loupe init`, `loupe ci`, `loupe verify`, `loupe chat` (TTY-guarded placeholder), `loupe scan`, `loupe mcp`, `loupe lens list`, `loupe cap list`.
- `loupe mcp` MCP server with stdio transport, using the official `mcp` SDK's FastMCP API (D-21).
- MCP read tools: `list_threats`, `query_by_severity`, `latest_run`, plus ThreatLens summary tool.
- MCP write tools: `propose_threat`, `propose_mitigation`, both gated through Layer 1.
- `loupe ci` severity gates: `ci.fail_on` (exit non-zero) and `ci.warn_on` (annotate but pass).
- `loupe verify` checks beyond the hash chain: artefact schema consistency, threats↔mitigations cross-references, and protected-path authorship (in strict mode). Four Layer-3 checks now ship.
- `loupe verify --strict` CLI flag.
- `RunRecord` token and cost fields populated from real agent runs.
- Pricing module (`loupe_core.pricing`) with a seven-model price table.
- Cost-regression test fixture replaying the live ThreatLens VCR cassette.
- `ProjectContext` frontmatter parsing for `schema_version`, `last_human_edit`, and `maintained_by`.
- Typed `ThreatId` / `MitigationId` / `ElementId` aliases; cross-reference fields validate at parse time.
- `init` template scaffolds three commented multi-LLM alternative provider lines.
- GitHub Action wrapper: typed input validation, PR diff fetcher with 5xx and rate-limited 403 retry, Markdown sticky-comment poster filtered by bot identity (PATCH-404 falls back to create), eight outputs (`findings_count`, per-severity counts, `run_id`, `run_hash`, `exit_code`). LLM-generated Markdown is escaped in sticky comments.
- Two-tier evaluation methodology (D-19): Cesanta Mongoose (Tier 1) and Eclipse Mosquitto (Tier 2). Methodology recorded; scenario catalogue and scoring code pending.
- CI workflow: pytest + ruff + mypy on every push and PR.
- D-21 decision: MCP server uses the official `mcp` SDK's FastMCP API, not the third-party `fastmcp` package.
- D-22 decision: MCP write tools enforce through Layer 1 (`PathBoundary`) alone; no separate Layer-4 confirm gate. MCP clients are not TTY-bound, so the human-in-the-loop UX belongs in the client, not the server.
- Typed `Finding` model with provenance (capability backend, rule, location) replacing free-form dicts in capability results.
- Typed `UpgradedPackage` model for diff-derived upgrade hints consumed by ThreatLens.
- `mypy --strict` pre-commit hook on `loupe-core`.

### Changed

- CLI usage-error exit code unified to 64 (BSD `sysexits.h` `EX_USAGE`).
- `loupe mcp` error handling narrowed: no silent config-error swallow.
- ThreatLens prompt structure: `sub_prompt` moved to the trailing slot so the stable prefix stays cache-pinned.
- ThreatLens emits a warning on missing or zero LLM usage telemetry rather than silently zeroing it.
- `init` template scaffolds three commented multi-LLM alternative provider lines so configuration is one uncomment away.
- CodeQL database path now flows through `CapabilityActivation.options` instead of an env var (env var deprecated).

### Fixed

- Layer 1 hardening: path-traversal, absolute-path, and NUL rejection in `propose_patch`; symlink rejection (parent chain via `dir_fd` + `O_NOFOLLOW`) in `write_agent_artifact`; atomic save (`tmp` + `os.replace`) for `RunRecord` to protect the hash chain.
- SBOM `union` and `consensus` modes rejected at config-validation (no longer silently empty).
- Unknown capability names rejected at config-validation.
- `loupe ci`: `--diff` and `--diff-file` mutual exclusion now enforced.
- Default `agent_writable_paths` now includes `.loupe/knowledge.yaml`, unblocking the first lens run.
- Stripped-under-O assertion in fallback composition replaced with an explicit raise.
- `loupe-action`: Markdown in agent-generated content is escaped in the sticky comment.
- `loupe-action`: PR fetcher retries on 5xx and rate-limited 403.
- `loupe-action`: sticky-comment poster filters by bot identity; PATCH-404 falls back to create.
- `loupe-action`: trusts the `loupe ci` gate verdict and surfaces usage errors as exit 64.
- `loupe-action`: top-level error mapping (64 for known usage errors, 1 for unknown).
- ThreatLens: single env-var resolution for `THREATLENS_MODEL` (no hard-coded default in `agent.py`).
- ThreatLens MCP query tool no longer references the nonexistent `informational` severity.
- `loupe-action`: `pip install` pinned in `action.yml` (source install pre-PyPI; pinned post-v0.1).
- `RunRecord.timestamp` requires a timezone-aware datetime; UTC is no longer silently assumed at parse time.
- Cross-platform tempfile path for `gitleaks` output (the previous `/dev/stdout` route was Linux-only).
- Capability bootstrap detects three-way `agent_writable_paths` conflicts cleanly, with a precise error pointing at the conflicting entries.
- Lens MCP-registration failures are isolated per-lens, so a broken lens cannot suppress the read tools of others.
- Capability backend errors include a stdout snippet when stderr is empty, so an unhelpful CLI exit no longer surfaces as a featureless `BackendError`.
- `pydantic-ai>=1.0,<2` bound corrected (a wrong upper bound was silently downgrading installs to a 0.2.x line).
- Upper bounds on pre-1.0 SDKs (`mcp`, `pydantic-ai`) added to insulate the project from minor-version API breaks.

### Refactored

- `loupe_core.atomic_write_yaml` shared helper for all artefact saves.
- ThreatLens: `_append_threat` extracted to deduplicate the two write paths.
- CLI discovery uses public `CapabilityRegistry.list_all()`.
- Capability backends run their external tool via `asyncio.to_thread` so the event loop is not blocked during long scans.
- Capability dependency graph consolidated into a single source-of-truth dict (previously fanned out across the bootstrap and the coordinator).
- `CodeDiff` moved into `diff.py`, removing a circular-import workaround.
- Relative-target-path validator centralised in `path_boundary` for reuse by both write tools.

### Designed, not yet shipped

- `loupe chat` conversational REPL pipeline (the TTY guard is wired; the REPL itself prints a placeholder).
- Layer 2 branch-namespace enforcement with a fine-grained GitHub App token (design recorded in `packages/loupe-action/action.yml` and D-08; runtime enforcement pending).
- HTTP+SSE remote MCP transport (stdio ships today).
- `--verbose` and `--budget-usd` CLI flags.

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

[Unreleased]: https://github.com/fadi-labib/loupe/commits/main
