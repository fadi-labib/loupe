# How-to

Task-focused recipes. Each page is a short, self-contained answer to a specific question.

> [!NOTE]
> **Pre-alpha:** this section is populated as recipes are written. The [Quickstart](../quickstart.md) and [Contributing](../contributing.md) pages cover the most-asked starter questions in the meantime.

## Recipes

- [Troubleshooting](troubleshooting.md) — common failure modes (missing provider key, scanner binary not on `PATH`, empty diff, hash-chain break, VCR cassette mismatch, cost-cap refusal) with the diagnostic command and fix for each.
- [Run the MCP server](run-mcp-server.md) — operate `loupe mcp`, attach a Claude Code / Cursor client, understand the read and write tool surface.

## Planned recipes

- **Swap LLM provider** — switching between Anthropic, OpenAI, Google, and the Vercel AI Gateway via `THREATLENS_MODEL`.
- **Write a new lens** — minimum shape for a `<Domain>Lens` package, entry-point registration, `is_relevant()` heuristic.
- **Run Loupe offline** — local Ollama plus offline-capable SBOM and CVE backends.
- **Add a custom capability backend** — register a third-party backend under the `loupe.capabilities` entry-point group.

If you're new to Loupe, start at the [Quickstart](../quickstart.md), not here.
