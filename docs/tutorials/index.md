# Tutorials

Guided learning paths. Each tutorial walks through an end-to-end scenario so you build a mental model of how Loupe feels in practice.

The canonical entry point is the [Quickstart](../quickstart.md), which lives at the top level because it's the one tutorial every new user runs first.

> [!NOTE]
> **Pre-alpha:** the Quickstart and the ThreatLens-on-Mongoose tutorial are validated end-to-end against a live LLM. Additional tutorials land here as they're written.

Available tutorials:

- [**ThreatLens on Mongoose**](threatlens-on-mongoose.md) — end-to-end walkthrough running Loupe against a real Cesanta Mongoose checkout. Covers `loupe doctor`, `loupe init`, `loupe ci` on a real protocol-parser fix diff, `loupe scan`, and `loupe verify --strict`. Doubles as the Tier-1 user-shaped validation for [D-19](../reference/decisions.md#d-19).

Planned tutorials:

- **Monorepo walkthrough** — running Loupe across multiple packages in one repo.
- **Offline / air-gapped CI** — wiring local Ollama plus offline SBOM and CVE backends.
- **GitLab integration** — using Loupe outside the GitHub Action.

If you already know Loupe and just want to accomplish a specific task, check [how-to](../how-to/index.md) instead.
