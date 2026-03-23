# Loupe

Loupe is a Python platform that runs domain-specialised AI agents (lenses) against your code changes and writes auditor-credible evidence as plain files in your repo. v1 ships **ThreatLens**, which does STRIDE threat modelling and produces artefacts shaped to feed EU CRA Annex I conformity evidence.

A *loupe* is the precision lens jewellers and watchmakers use to inspect detail others miss. Each Loupe lens does the same to a codebase: ThreatLens looks for security threats, SafetyLens (future) for functional-safety hazards, PrivacyLens (future) for data-protection issues. Same instrument, different lens.

**Status:** pre-alpha. The platform, capability registry, CLI, GitHub Action, and ThreatLens lens are wired end-to-end. ThreatLens calls a live LLM through PydanticAI (a VCR cassette test fixture is committed, recorded against the configured provider). `loupe mcp` exposes read tools (`list_threats`, `query_by_severity`, `latest_run`) and write tools (`propose_threat`, `propose_mitigation`) over stdio. Run records today carry real token and cost data populated by the lens. Ten capability backends ship bundled (Syft, cdxgen, Grype, osv-scanner, gitleaks, TruffleHog, detect-secrets, Semgrep, CodeQL, Bandit), composing through `single` / `fallback` / `union` / `consensus` / `pipeline` modes.

Still in flight: the `loupe chat` REPL (TTY guard wired, conversational pipeline pending), Layer 2 fine-grained-PAT branch namespace enforcement, and the HTTP+SSE remote MCP transport.

## What it does for you

Three frontends, all functional. `loupe ci` runs on every PR via the GitHub Action and posts a sticky comment with severity-grouped findings. `loupe mcp` runs an MCP server over stdio with both read tools (queries against `.loupe/`) and Layer-1-gated write tools (proposes new threats and mitigations). `loupe chat` (interactive REPL) is the next frontend: the TTY guard is wired but the conversational pipeline is not.

Outputs live in `.loupe/` as Git-tracked plain files: threats, mitigations, a CycloneDX SBOM, OpenVEX statements, hash-chained run records, and an ADR-style decision log. The LLM-driven artefacts (threats, mitigations) are produced by ThreatLens against your configured provider; the SBOM and CVE artefacts come from the bundled capability backends. There is no SaaS, no telemetry, no Loupe-hosted backend.

You pick the LLM. PydanticAI gives you Anthropic, OpenAI, Google, Mistral, Groq, Cohere, Ollama, and Bedrock through one env var. You pick the tools. SBOM, CVE, secret detection, and static analysis are pluggable Capability Protocols with composition modes (`single`, `fallback`, `union`, `consensus`, `pipeline`).

## Quick example

**Install (pre-alpha; pre-PyPI):**

```bash
git clone https://github.com/fadilabib/loupe.git
cd loupe
uv sync --all-packages
```

This installs the four workspace packages (`loupe-core`, `loupe-cli`, `loupe-threatlens`, `loupe-action`) in editable mode. Invoke the CLI through `uv run loupe …`.

Once v0.1 is tagged and published, the install will simplify to:

```bash
pip install loupe-cli loupe-threatlens
```

The PyPI publishing process is documented in [`CHANGELOG.md`](CHANGELOG.md#release-process).

**First run:**

```bash
cd your-repo
uv run loupe init
$EDITOR .loupe/context.md       # describe your product, assets, threat actors
uv run loupe ci --diff-file <(git diff main...)
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
