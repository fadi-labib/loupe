---
tags:
  - reference
  - mcp
---

# MCP tools

The MCP tool surface in Loupe is the set of Python functions registered with a `FastMCP` server inside `packages/loupe-core/loupe_core/mcp_server.py` and `packages/loupe-threatlens/loupe_threatlens/mcp_tools.py`. Each tool corresponds to one MCP-protocol verb that a client (Claude Code, Cursor, ChatGPT desktop, custom IDE plugins) can invoke over JSON-RPC. The surface splits into two halves: read tools that return artefact contents as plain JSON, and write tools that append to `.loupe/threats.yaml` or `.loupe/mitigations.yaml`.

The Layer 1 contract for write tools is simple: every write goes through `write_agent_artifact` or `propose_patch`. These helpers check the target path against the operator's `agent_writable_paths` allow-list (the same list that gates `loupe ci`) before any bytes hit disk. An MCP client that asks to write outside the allow-list gets a `BoundaryViolation`, surfaced over MCP as a tool-call error. There is no second code path for MCP writes; they reuse the same enforcement primitive as the in-process agent. See [`data-handling.md` § MCP server data flow](data-handling.md#mcp-server-data-flow) for the broader picture.

Write tools are registered only when `loupe mcp` can build a `PathBoundary` from `.loupe/config.yaml`. With no usable config, the server runs in strictly read-only mode and the write decorators never fire. This is the safer default: a broken config closes the write surface entirely rather than silently opening a hole.

Loupe's MCP server uses the official `mcp` SDK (`mcp.server.fastmcp.FastMCP`), not the third-party package of the same name. The full rationale lives in [D-21](decisions.md#d-21); in short, the official SDK is governed by the protocol spec maintainers and gives us Pydantic-driven JSON Schema generation for free.

The `*_impl` functions on this page are deliberately decoupled from the MCP wiring. Each takes a `Path` to a `.loupe/` directory and returns plain Python data (dicts, lists, optionals). The decorated `@mcp.tool()` wrappers in `build_mcp_server` and `register_threatlens_mcp_tools` are thin closures over those impls. If the MCP spec or our framework choice changes, only the wiring layer moves; the data-access layer survives untouched. This mirrors the capability-layer split between `Protocol` and backend ([D-18](decisions.md#d-18)) and the lens-vs-platform split ([D-04](decisions.md#d-04)).

The implementations below are the testable surface. Each is reachable from the corresponding MCP tool name; the wrapper docstring on the decorated tool is what the LLM client sees, and the impl docstring is what a Loupe developer reads.

## Read tools (loupe-core)

### list_threats

::: loupe_core.mcp_server.list_threats_impl

### get_threat

::: loupe_core.mcp_server.get_threat_impl

### list_mitigations

::: loupe_core.mcp_server.list_mitigations_impl

### get_mitigation

::: loupe_core.mcp_server.get_mitigation_impl

### list_elements

::: loupe_core.mcp_server.list_elements_impl

### latest_run

::: loupe_core.mcp_server.latest_run_impl

## Read tools (ThreatLens lens)

These tools are registered when the `loupe-threatlens` package is installed. They live in the lens, not the core, because the questions they answer (filter by STRIDE letter, aggregate by severity) are domain-specific to threat modelling.

### threatlens_query_by_stride

::: loupe_threatlens.mcp_tools.query_threats_by_stride_impl

### threatlens_query_by_severity

::: loupe_threatlens.mcp_tools.query_threats_by_severity_impl

### threatlens_summary

::: loupe_threatlens.mcp_tools.threat_model_summary_impl

## Write tools (ThreatLens lens)

Write tools live in the lens for the same reason their read counterparts do: the schemas they accept (`ProposeThreatInput`, `ProposeMitigationInput`) are threat-modelling shapes, not core shapes. The Layer 1 enforcement is in core, but the input definitions and the validation rules around them belong to the lens that owns those artefacts.

These functions are the underlying writers. The MCP tool wrappers `threatlens_propose_threat` and `threatlens_propose_mitigation` are decorated closures over them.

### threatlens_propose_threat (write)

::: loupe_threatlens.tools.write_threat_directly

### threatlens_propose_mitigation (write)

::: loupe_threatlens.tools.write_mitigation_directly

## Server construction

The `FastMCP` server itself is built by `build_mcp_server` in `loupe-core`. It binds to one `.loupe/` directory at construction time and serves many requests against that same directory; to serve a different project, build a second server. Lenses with a `register_to_mcp` method contribute domain-specific tools to the same server during construction.

### build_mcp_server

::: loupe_core.mcp_server.build_mcp_server

### register_threatlens_mcp_tools

::: loupe_threatlens.mcp_tools.register_threatlens_mcp_tools

## See also

- [`concepts/architecture.md`](../concepts/architecture.md) — where MCP sits in the three-frontends picture.
- [`reference/data-handling.md` § MCP server data flow](data-handling.md#mcp-server-data-flow) — what the MCP process touches on disk and on the network.
- [`decisions.md#d-09`](decisions.md#d-09) — why MCP is a first-class frontend, not a derivative.
- [`decisions.md#d-21`](decisions.md#d-21) — why we use the official `mcp` SDK rather than third-party `fastmcp`.
- [`how-to/run-mcp-server.md`](../how-to/run-mcp-server.md) — operator-focused walkthrough of running `loupe mcp` and attaching a client.
