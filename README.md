# Loupe

Loupe is a Python platform that runs domain-specialised AI agents (lenses) against your code changes and writes auditor-credible evidence as plain files in your repo. v1 ships **ThreatLens**, which does STRIDE threat modelling and produces artefacts shaped to feed EU CRA Annex I conformity evidence.

A *loupe* is the precision lens jewellers and watchmakers use to inspect detail others miss. Each Loupe lens does the same to a codebase: ThreatLens looks for security threats, SafetyLens (future) for functional-safety hazards, PrivacyLens (future) for data-protection issues. Same instrument, different lens.

**Status:** pre-alpha. The platform, capability registry, CLI, GitHub Action, and ThreatLens scaffolding are in place. The PydanticAI agent inside ThreatLens is not yet wired to a live LLM; that's the next milestone.

## What it does for you

Three frontends are designed, one is shipping. `loupe ci` runs on every PR via the GitHub Action and posts a sticky comment with severity-grouped findings; this is implemented and the agent wiring is the next milestone. `loupe chat` (interactive REPL) and `loupe mcp` (Model Context Protocol server) are designed in this repo but not yet implemented; `loupe chat` currently prints a placeholder, and `loupe mcp` is not registered as a command yet.

Outputs live in `.loupe/` as Git-tracked plain files. The artefact set is designed as: threats, mitigations, a CycloneDX SBOM, OpenVEX statements, hash-chained run records, and an ADR-style decision log. Today the platform writes the run records and the scaffolding for the rest; the LLM-driven generation of mitigation, SBOM, and VEX artefacts is gated on the ThreatLens agent going live. There is no SaaS, no telemetry, no Loupe-hosted backend.

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

The published docs site lives at <https://fadilabib.github.io/loupe/> with search, navigation, and per-page social previews. The table below is the GitHub-flavoured Markdown fallback for browsing in-tree.

| Question | File |
|---|---|
| What's the mental model? | [`docs/index.md`](docs/index.md) |
| How do I get started? | [`docs/quickstart.md`](docs/quickstart.md) |
| What are the principles? | [`docs/principles.md`](docs/principles.md) |
| What changed in this release? | [`CHANGELOG.md`](CHANGELOG.md) |
| How do I run the CLI? | [`docs/reference/cli.md`](docs/reference/cli.md) |
| How do I configure `.loupe/config.yaml`? | [`docs/reference/config.md`](docs/reference/config.md) |
| How do I verify the principles? | [`docs/reference/verification.md`](docs/reference/verification.md) |
| What does each artefact look like? | [`docs/reference/schemas/`](docs/reference/schemas/index.md) |
| Why was X decided this way? | [`docs/reference/decisions.md`](docs/reference/decisions.md) |
| How does Loupe compare with other tools? | [`docs/comparison.md`](docs/comparison.md) |
| What data leaves my repo? | [`docs/reference/data-handling.md`](docs/reference/data-handling.md) |
| Term I don't recognise? | [`docs/reference/glossary.md`](docs/reference/glossary.md) |
| How do I contribute? | [`docs/contributing.md`](docs/contributing.md) |

## Licence

Apache 2.0. See [`LICENSE`](LICENSE). Use it, fork it, ship it. Attribution appreciated, not required.
