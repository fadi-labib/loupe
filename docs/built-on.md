# Built on

Loupe stands on a deliberately small set of well-tested OSS dependencies, plus the standards bodies whose schemas it emits. Each row records what Loupe relies on and where in the codebase the dependency lives.

| Layer | Built with |
|---|---|
| LLM agent framework | [PydanticAI](https://ai.pydantic.dev/) (multi-provider, typed I/O) |
| Validation + serialisation | [Pydantic 2.x](https://docs.pydantic.dev/) |
| LLM tool protocol | [MCP](https://modelcontextprotocol.io/) (official Anthropic SDK, FastMCP API; see [D-21](reference/decisions.md#d-21)) |
| SBOM | [CycloneDX 1.6](https://cyclonedx.org/) via [Syft](https://github.com/anchore/syft) / [cdxgen](https://github.com/CycloneDX/cdxgen) |
| Vulnerability matching | [Grype](https://github.com/anchore/grype) · [osv-scanner](https://github.com/google/osv-scanner) |
| VEX | [OpenVEX 0.2](https://openvex.dev/) |
| Secret detection | [TruffleHog](https://github.com/trufflesecurity/trufflehog) · [gitleaks](https://github.com/gitleaks/gitleaks) · [detect-secrets](https://github.com/Yelp/detect-secrets) |
| Static analysis | [Semgrep](https://semgrep.dev/) · [CodeQL](https://codeql.github.com/) · [Bandit](https://github.com/PyCQA/bandit) |
| Threat-modelling method | [STRIDE](https://learn.microsoft.com/azure/security/develop/threat-modeling-tool-threats) (Microsoft); methodology inspiration from [StrideGPT](https://github.com/mrwadams/stride-gpt) (see [D-16](reference/decisions.md#d-16)) |
| Docs site | [MkDocs Material](https://squidfunk.github.io/mkdocs-material/) · [mkdocstrings](https://mkdocstrings.github.io/) · [mike](https://github.com/jimporter/mike) versioning |
| Workspace / packaging | [uv](https://docs.astral.sh/uv/) · [hatchling](https://hatch.pypa.io/) |
| Prose linting | [Vale](https://vale.sh/) with a custom [`Loupe`](https://github.com/fadi-labib/loupe/tree/main/.vale/styles/Loupe) style |

## Why this stack

The dependency set is deliberately conservative.

- **PydanticAI** rather than LangChain or LlamaIndex: typed I/O end-to-end, no framework lock-in, multi-provider native. See [D-04](reference/decisions.md#d-04).
- **CycloneDX over SPDX**: CycloneDX 1.6 has first-class vulnerability and ML-bill-of-materials sections; SPDX 3 was still draft when the choice was locked. See [D-12](reference/decisions.md#d-12).
- **OpenVEX over CSAF VEX profile**: smaller, simpler schema; CSAF can be added as an additional emitter without breaking the artefact contract. See [D-13](reference/decisions.md#d-13).
- **MCP via the official SDK** rather than a custom JSON-RPC layer: ties the tool surface to a real protocol with multi-client adoption, not a one-off interface. See [D-21](reference/decisions.md#d-21).

Every choice is reversible at the capability or backend layer without disturbing the platform; the artefact schemas are the stable surface.
