# Loupe

Loupe is a Python platform that runs domain-specialised AI agents (lenses) against your code changes and writes auditor-credible evidence as plain files in your repo. v1 ships **ThreatLens**, which does STRIDE threat modelling and produces artefacts shaped to feed EU CRA Annex I conformity evidence.

A *loupe* is the precision lens jewellers and watchmakers use to inspect detail others miss. Each Loupe lens does the same to a codebase: ThreatLens looks for security threats, SafetyLens (future) for functional-safety hazards, PrivacyLens (future) for data-protection issues. Same instrument, different lens.

**Status:** pre-alpha. The platform, capability registry, CLI, GitHub Action, and ThreatLens scaffolding are in place. The PydanticAI agent inside ThreatLens is not yet wired to a live LLM; that's the next milestone.

## What it does for you

Three frontends, one core. `loupe ci` runs on every PR via the GitHub Action and posts a sticky comment with severity-grouped findings. `loupe chat` runs the same pipeline interactively in your terminal. `loupe mcp` (in progress) exposes the same tools to Claude Code, Cursor, or any MCP-aware client.

Outputs live in `.loupe/` as Git-tracked plain files: threats, mitigations, a CycloneDX SBOM, OpenVEX statements, hash-chained run records, and an ADR-style decision log. An auditor can verify any of this with their own tooling. There is no SaaS, no telemetry, no Loupe-hosted backend.

You pick the LLM. PydanticAI gives you Anthropic, OpenAI, Google, Mistral, Groq, Cohere, Ollama, and Bedrock through one env var. You pick the tools. SBOM, CVE, secret detection, and static analysis are pluggable Capability Protocols with composition modes (`single`, `fallback`, `union`, `consensus`, `pipeline`).

## Quick example

```bash
pip install loupe-cli loupe-threatlens
cd your-repo
loupe init
$EDITOR .loupe/context.md       # describe your product, assets, threat actors
loupe ci --diff-file <(git diff main...)
```

In a GitHub workflow:

```yaml
- uses: loupe-action@v1
  with:
    pr: ${{ github.event.pull_request.number }}
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Where to go next

| Question | File |
|---|---|
| What's the mental model? | [`docs/index.md`](docs/index.md) |
| How do I get started? | [`docs/start.md`](docs/start.md) |
| What are the principles? | [`docs/principles.md`](docs/principles.md) |
| Why was X decided this way? | [`docs/decisions.md`](docs/decisions.md) |
| How does Loupe compare with other tools? | [`docs/comparison.md`](docs/comparison.md) |
| What data leaves my repo? | [`docs/data.md`](docs/data.md) |
| Term I don't recognise? | [`docs/glossary.md`](docs/glossary.md) |
| How do I contribute? | [`docs/contributing.md`](docs/contributing.md) |

## Licence

Apache 2.0. See [`LICENSE`](LICENSE). Use it, fork it, ship it. Attribution appreciated, not required.
