---
tags:
  - how-to
  - mcp
---

# Run the MCP server

`loupe mcp` is Loupe's third frontend, alongside `loupe ci` and `loupe chat`. It exposes a small set of read tools and a smaller set of write tools over the Model Context Protocol so any MCP-aware LLM client (Claude Code, Cursor, ChatGPT desktop, custom IDE plugins) can query and contribute to a project's threat model without shelling out to the CLI. Writes still flow through the Layer 1 path boundary that gates `loupe ci`, so an MCP client cannot exceed the local agent's authority — see [D-09](../reference/decisions.md#d-09).

## Invocation

```bash
cd /path/to/your/repo
loupe mcp
```

The command expects a `.loupe/` directory in the current working directory. Run `loupe init` first if you don't have one. To serve a project that isn't `cwd`, pass `--loupe-dir`:

```bash
loupe mcp --loupe-dir /absolute/path/to/your/repo/.loupe
```

The server listens on stdio (the MCP default for local transports). It does not open a network port. Stop it with `Ctrl-C` or by closing the client.

## Attaching a client

MCP clients spawn `loupe mcp` as a subprocess. The exact configuration file varies per client, but the shape is consistent. For Claude Code, add Loupe to your MCP config:

```json
{
  "mcpServers": {
    "loupe": {
      "command": "loupe",
      "args": ["mcp", "--loupe-dir", "/absolute/path/to/your/repo/.loupe"]
    }
  }
}
```

For Cursor, the same JSON lives under the editor's MCP-servers setting. ChatGPT desktop accepts the same shape under its tools panel. Use absolute paths in `--loupe-dir`; the client may launch the subprocess from a working directory that isn't your repo root.

## Read tools

These tools are always registered. They never write to `.loupe/`.

| Tool | Returns |
|---|---|
| `list_threats` | Every threat in `.loupe/threats.yaml` as a list of JSON dicts. Empty list when the file is absent. |
| `get_threat(threat_id)` | One threat by ID (`T-NNN`), or `None`. |
| `list_mitigations` | Every mitigation in `.loupe/mitigations.yaml`. |
| `get_mitigation(mitigation_id)` | One mitigation by ID (`M-NNN`), or `None`. |
| `list_elements` | Architectural elements from `.loupe/knowledge.yaml`. |
| `latest_run` | The most recent `RunRecord` from `.loupe/runs/`, or `None`. |

When ThreatLens is installed (it is by default), three lens-contributed read tools appear too:

| Tool | Returns |
|---|---|
| `threatlens_query_by_stride(stride_category)` | Threats filtered by STRIDE letter (`S`, `T`, `R`, `I`, `D`, `E`). |
| `threatlens_query_by_severity(severity)` | Threats at exactly the given severity (`critical`, `high`, `medium`, `low`). |
| `threatlens_summary` | Aggregate counts: total, by severity, by STRIDE, by status. |

## Write tools

Write tools are registered only when `loupe mcp` can load `.loupe/config.yaml` and construct a `PathBoundary` from the operator's `agent_writable_paths`. Without a usable config the server falls back to a strictly read-only surface and prints a warning to stderr. This is the safer default: a broken config does not silently open a hole.

| Tool | What it writes |
|---|---|
| `threatlens_propose_threat(element_id, stride_category, title, description, severity, rationale, cwe_refs=[], mitigation_ids=[])` | Appends a `Threat` to `.loupe/threats.yaml`. Returns `{"threat_id": "T-NNN", "status": "written"}`. |
| `threatlens_propose_mitigation(title, description, threats_addressed=[], status="proposed", evidence_kind=None, evidence_location=None)` | Appends a `Mitigation` to `.loupe/mitigations.yaml`. Returns `{"mitigation_id": "M-NNN", "status": "written"}`. |

Both tools route through the same `write_agent_artifact` path the in-process PydanticAI agent uses. The Layer 1 boundary checks the target file against `agent_writable_paths` before any bytes hit disk. An attempt to write to a path that isn't on the allow-list raises `BoundaryViolation`, which surfaces over MCP as a tool-call error. There is no way to write outside the allow-list via MCP, including no way to overwrite an existing threat (writes are append-only via stable-ID assignment).

The Layer 1 contract is identical to the local CLI: every write is gated by the same `agent_writable_paths` allow-list, the same PathBoundary class, and the same `write_agent_artifact` helper. MCP does not get its own bypass.

## What is not shipped

- **Remote transport.** Only stdio works today. HTTP+SSE for remote clients is designed but not wired; remote transport would require authentication and explicit opt-in. The design rationale lives in [D-09](../reference/decisions.md#d-09) and [D-21](../reference/decisions.md#d-21).
- **Granular per-tool writability flags.** Either you have a valid config with `agent_writable_paths` and get the full write surface, or you have no config and get the read-only surface. No middle ground.
- **`propose_patch` over MCP.** Source-tree edits via the four-layer write boundary do not yet have an MCP-exposed tool; they remain agent-only inside `loupe ci`.

## Auditing what the MCP server did

Reads do not produce audit artefacts. Writes that mutate `.loupe/threats.yaml` or `.loupe/mitigations.yaml` are observable via git history of those files. Run records (`.loupe/runs/<id>.json`) are produced by `loupe ci` and `loupe chat`, not by individual MCP tool calls — the MCP server is a thin frontend over the same artefact files, and it does not synthesise a `RunRecord` for one-off tool calls.

For the data-flow picture, including which directories the MCP process touches, see [data-handling.md § MCP server data flow](../reference/data-handling.md#mcp-server-data-flow).
