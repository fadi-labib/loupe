# Architecture (visual)

> All diagrams on this page render natively on GitHub — `mermaid` fenced code blocks, including Mermaid's C4 diagram types. No external services or images.
>
> The diagrams are deliberately layered (C4-style): start at **Context** for the big picture, drill into **Container** for the package shape, then **Component** for `loupe-core` internals. The two **sequence** diagrams at the end show dynamic behaviour (CI run, interactive run).
>
> If something looks wrong in a diagram, the design spec at [`specs/2026-05-13-loupe-design.md`](specs/2026-05-13-loupe-design.md) is the source of truth.

---

## C4 Level 1 — System Context

The big picture: who interacts with Loupe and what external systems it depends on.

```mermaid
C4Context
    title Loupe — System Context

    Person(dev, "Developer", "Opens PRs; runs loupe chat locally")
    Person(security, "Security / safety engineer", "Reviews proposal PRs; signs decisions")
    Person(auditor, "Auditor", "Reads .loupe/ artefacts to verify CRA / similar conformity")

    System_Boundary(loupe, "Loupe (this repo)") {
        System(platform, "Loupe Platform", "loupe-core + lenses; produces evidence-grade artefacts in your repo")
    }

    System_Ext(repo, "Your Git Repo", "Code under analysis + .loupe/ artefacts")
    System_Ext(ci, "CI Runner", "GitHub Actions / GitLab CI / Jenkins")
    System_Ext(llm, "LLM Provider", "Anthropic / OpenAI / Google / Mistral / etc. via PydanticAI")
    System_Ext(sbom, "SBOM / CVE tools", "Syft, Grype, osv-scanner; future: Trivy, gitleaks, Semgrep")
    System_Ext(mcp, "MCP Clients", "Claude Code, Cursor, ChatGPT desktop, custom agents")
    System_Ext(vcs, "GitHub / GitLab", "PR + branch hosting + proposal-PR workflow")

    Rel(dev, platform, "loupe chat, loupe scan, loupe init")
    Rel(ci, platform, "loupe ci on PR open")
    Rel(mcp, platform, "JSON-RPC via stdio or HTTP+SSE")
    Rel(platform, repo, "Reads diff + writes .loupe/* artefacts (Layer 1 enforced)")
    Rel(platform, llm, "Tool-using agent calls (PydanticAI)")
    Rel(platform, sbom, "Subprocess: Syft, Grype, etc.")
    Rel(platform, vcs, "Opens proposal PRs; never pushes to main")
    Rel(security, vcs, "Reviews proposal PRs; CODEOWNERS gates")
    Rel(auditor, repo, "Reads .loupe/ + Git history")
```

---

## C4 Level 2 — Containers

The four Python packages, the in-repo artefact directory, and the external systems they integrate with.

```mermaid
C4Container
    title Loupe — Containers

    Person(dev, "Developer / Security Engineer")
    Person(auditor, "Auditor")

    System_Boundary(loupe, "Loupe") {
        Container(cli, "loupe-cli", "Python (Typer)", "loupe ci / chat / mcp / init / verify / scan")
        Container(core, "loupe-core", "Python (PydanticAI)", "Coordinator, RunContext blackboard, lens registry, enforcement, MCP server, prompt builder, SBOM/CVE wrappers")
        Container(threatlens, "loupe-threatlens", "Python (PydanticAI agent)", "v1 lens: STRIDE threat modelling + CRA evidence")
        Container(action, "loupe-action", "GitHub Action (composite)", "Thin wrapper around loupe-cli for CI runners")
    }

    System_Boundary(repo, "Your Repo") {
        ContainerDb(artefacts, ".loupe/", "Versioned files in git", "context.md, threats.yaml, mitigations.yaml, threat-model.md, sbom.cdx.json, vex.json, decisions/, runs/, knowledge.yaml, config.yaml")
    }

    System_Ext(llm, "LLM Provider")
    System_Ext(syft, "Syft / Grype / etc.", "External binaries")
    System_Ext(gh, "GitHub", "Proposal PRs + CODEOWNERS")
    System_Ext(mcp_client, "MCP Client", "Claude Code, Cursor, etc.")

    Rel(dev, cli, "Invokes")
    Rel(action, cli, "Invokes loupe ci on PR")
    Rel(cli, core, "Bootstraps RunContext, runs coordinator")
    Rel(core, threatlens, "Discovers via entry point loupe.lenses; dispatches via plan")
    Rel(threatlens, llm, "PydanticAI agent calls")
    Rel(core, syft, "subprocess (loupe_core/sbom.py)")
    Rel(core, artefacts, "Reads / writes (Layer 1 enforced)")
    Rel(core, gh, "Pushes to loupe/proposal-*; opens PR")
    Rel(mcp_client, core, "MCP JSON-RPC (loupe mcp)")
    Rel(auditor, artefacts, "Reads (Git history)")
```

**Notes:**

- The `Container` boxes correspond exactly to the four `packages/*/pyproject.toml` directories in this repo.
- `.loupe/` is a directory, not a separate service — drawn as a container because conceptually it's the system's persistent state.
- Future lenses (SafetyLens, PrivacyLens, AIRiskLens) would sit alongside `loupe-threatlens` here; the diagram would gain one box per future lens.

---

## C4 Level 3 — Components inside `loupe-core`

The internals of the platform. This is where the design decisions (D-01 through D-18) actually take shape in code.

```mermaid
C4Component
    title loupe-core — Components

    Container_Boundary(core, "loupe-core") {
        Component(coord, "Coordinator", "build_run_plan()", "Relevance filter + topological sort + dependency-validity check (D-11, D-15)")
        Component(dispatch, "Dispatcher", "dispatch_plan()", "Runs each lens in plan, sequential where dependent, parallel where not")
        Component(runctx, "RunContext", "Pydantic model", "Shared blackboard within a run: findings, facts, plan, diff, sbom, project, knowledge (D-07)")
        Component(prompts, "PromptBuilder", "assemble_messages()", "Stable-prefix vs variable-suffix layering for prompt-cache leverage (D-10)")
        Component(lens_reg, "Lens Registry", "discover_lenses()", "Entry-point discovery, artifact-path conflict detection (D-04, D-11)")
        Component(cap_reg, "Capability Registry", "Future (v1.x, D-18)", "Tool-agnostic capability backends discovered via entry points")
        Component(enforce, "Enforcement", "PathBoundary, BoundaryViolation, verify", "Layer 1 (tool surface) + Layer 3 (verify hash chain) — D-08")
        Component(artefacts, "Artefacts", "Pydantic models", "Threat, Mitigation, KnowledgeGraph, ProjectContext, RunRecord, LoupeConfig (D-06)")
        Component(tools, "Core Tools", "write_agent_artifact, propose_patch", "The ONLY filesystem-mutating tools — Layer 1 enforced (D-08)")
        Component(vcs, "VCS Adapter", "GitHubAdapter (future for GitLab/Gitea)", "Branch + PR + comment operations (D-08 Layer 2)")
        Component(sbom, "SBOM wrappers", "generate_sbom, diff_sboms", "Subprocess wrappers for Syft / Grype (current); becomes capability backends in v1.x (D-18)")
        Component(mcp_srv, "MCP Server", "Future (Phase 9)", "Exposes loupe.tools.* + loupe.workflows.* over stdio + HTTP (D-09)")
    }

    ComponentDb(artefact_files, ".loupe/", "Files", "9 artefact types + runs/ + decisions/ + knowledge.yaml + config.yaml")
    Component_Ext(lens, "Lens (e.g., loupe-threatlens)", "External package", "Discovered via entry point; lives in its own pip-installable package")

    Rel(coord, lens_reg, "Discovers available lenses")
    Rel(coord, runctx, "Builds plan into ctx.plan")
    Rel(dispatch, lens, "lens.run(ctx, plan_entry, boundary, loupe_dir)")
    Rel(dispatch, runctx, "Passes shared blackboard to every lens call")
    Rel(lens, prompts, "PromptBuilder.assemble_messages(parts)")
    Rel(lens, tools, "write_agent_artifact (Layer 1)")
    Rel(lens, cap_reg, "Future: ctx.capabilities.sbom / .cve / .secret_detect")
    Rel(tools, enforce, "PathBoundary.is_agent_writable check")
    Rel(tools, artefact_files, "Writes ONLY if allowed")
    Rel(artefacts, artefact_files, "Pydantic round-trip with ruamel.yaml")
    Rel(sbom, artefact_files, "Generates sbom.cdx.json")
    Rel(coord, vcs, "Future: opens proposal PRs after dispatch")
```

---

## Lens / Capability extension model

A specialised view focusing on Loupe's two parallel extension points (lenses for *domains*, capabilities for *operations*) — see [`CAPABILITIES.md`](CAPABILITIES.md) and [D-18](DESIGN-DECISIONS.md#d-18--capability-abstraction-tool-agnostic-functional-building-blocks).

```mermaid
flowchart TB
    classDef core fill:#e3f2fd,stroke:#1565c0,color:#0d47a1
    classDef lens fill:#fff3e0,stroke:#e65100,color:#bf360c
    classDef cap fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20
    classDef back fill:#f3e5f5,stroke:#6a1b9a,color:#4a148c
    classDef future stroke-dasharray: 5 5

    Core["loupe-core (platform)"]:::core

    subgraph Lenses["Lenses (domain plugins — nouns)"]
        TL[ThreatLens<br/>security / STRIDE]:::lens
        SL[SafetyLens<br/>ISO 26262 / HARA]:::lens
        SL_:::future
        PL[PrivacyLens<br/>LINDDUN / GDPR]:::lens
        PL_:::future
        AR[AIRiskLens<br/>NIST AI RMF / MAESTRO]:::lens
        AR_:::future
    end

    subgraph Capabilities["Capabilities (tool-agnostic operations — verbs)"]
        SBOM[SbomCapability]:::cap
        CVE[CveCapability]:::cap
        SEC[SecretDetectionCapability]:::cap
        SA[StaticAnalysisCapability]:::cap
        LIC[LicenseScanCapability]:::cap
        VDB[VulnDbCapability]:::cap
    end

    subgraph SbomBackends["SBOM backends"]
        Syft[Syft]:::back
        Trivy_S[Trivy]:::back
        Cdxgen[cdxgen]:::back
        GhApi[GitHub API]:::back
    end

    subgraph SecretBackends["Secret-detection backends"]
        TH[TruffleHog]:::back
        GL[gitleaks]:::back
        DS[detect-secrets]:::back
    end

    Core --> Lenses
    Core --> Capabilities

    TL -- "requires_capabilities" --> SBOM
    TL -- "requires_capabilities" --> CVE
    TL -- "requires_capabilities" --> SEC
    SL -. future .-> SA
    PL -. future .-> SEC
    AR -. future .-> VDB

    SBOM --> Syft
    SBOM --> Trivy_S
    SBOM --> Cdxgen
    SBOM --> GhApi

    SEC --> TH
    SEC --> GL
    SEC --> DS

    SL:::future
    PL:::future
    AR:::future
```

Solid arrows = current v1; dashed arrows + dashed boxes = future v1.x.

---

## Sequence diagram — CI run on a PR

A walkthrough of what happens when a developer opens a PR and the GitHub Action runs `loupe ci`. This is the "happy path" — the one Loupe is optimised for. See [§7 of the spec](specs/2026-05-13-loupe-design.md#section-7--end-to-end-flows-ci--interactive) for the full prose narrative.

```mermaid
sequenceDiagram
    autonumber
    participant Dev as Developer
    participant GH as GitHub
    participant Actions as GitHub Actions
    participant Action as loupe-action
    participant CLI as loupe-cli
    participant Core as loupe-core
    participant Lens as ThreatLens
    participant LLM as LLM provider<br/>(via PydanticAI)
    participant Syft
    participant Repo as .loupe/ (in repo)

    Dev->>GH: Open PR #128
    GH->>Actions: Trigger workflow
    Actions->>Action: Invoke composite action
    Action->>CLI: loupe ci --pr 128 (env-quoted)
    CLI->>Core: load_config + bootstrap RunContext
    Core->>Syft: subprocess (regenerate SBOM)
    Syft-->>Core: sbom.cdx.json
    Core->>Core: parse diff + load knowledge.yaml + context.md
    Core->>Core: discover_lenses() via entry points
    Core->>Core: build_run_plan() — relevance + deps + topo sort
    Core->>Lens: dispatch lens.run(ctx, plan_entry, boundary, loupe_dir)
    Lens->>Lens: build PydanticAI agent (deferred model check)
    Lens->>LLM: agent.run(prompt, deps=AgentDeps) — with stable-prefix cache
    LLM-->>Lens: tool calls (propose_threat × N)
    loop for each proposed threat
        Lens->>Core: write_agent_artifact(threats.yaml) — Layer 1 enforced
        Core->>Repo: write threats.yaml
        Lens->>Lens: ctx.record_finding("threatlens", "threat:T-NNN", ...)
    end
    LLM-->>Lens: final summary text (discarded)
    Lens-->>Core: returns
    Core->>Core: promote stable facts → knowledge.yaml
    Core->>Repo: write runs/<id>.json with hash chain
    Core->>GH: git push loupe/proposal-pr-128
    Core->>GH: gh pr create + gh pr comment on #128
    GH-->>Dev: PR comment with summary
    Actions->>CLI: loupe-verify (required check)
    CLI->>Repo: verify hash chain + authorship + schemas
    CLI-->>Actions: exit 0
```

Key properties visible in this diagram:

- **Steps 1–9** happen *before any LLM call* — the deterministic part. Cheap.
- **Step 11** is the only LLM call per lens per run. The stable-prefix cache means the *prompt prefix* is paid full price once and ~10% on subsequent lenses in the same run (D-10).
- **Step 15** is where Layer 1 enforcement actually intercepts — between the lens's intent ("write threats.yaml") and the filesystem.
- **Steps 19–20** complete the audit trail: knowledge graph promotion + hash-chained run record.
- **Steps 21–23** are Layer 2 enforcement: the runner can only push to `loupe/proposal-*` branches and must open a PR — `main` is never touched.

---

## Sequence diagram — Interactive run (`loupe chat`)

The interactive flow differs in two ways: a TTY is required, and every protected-path proposal is gated by a `[y/N/edit/skip]` prompt with default-N (Layer 4 enforcement).

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant Chat as loupe chat
    participant Core as loupe-core
    participant Lens as ThreatLens
    participant LLM as LLM provider
    participant Repo as .loupe/

    User->>Chat: loupe chat
    Chat->>Chat: TTY check (refuses otherwise)
    Chat->>Core: load_config + bootstrap RunContext (mode=interactive)
    Chat->>User: prompt for question
    User->>Chat: "What threats does the new refund endpoint introduce?"
    Chat->>Core: dispatch via coordinator
    Core->>Lens: lens.run(ctx, plan_entry, boundary, loupe_dir)
    Lens->>LLM: agent.run(...) with deps
    LLM-->>Lens: tool call: propose_threat(...)
    Lens->>Chat: render diff for user approval
    Chat->>User: "Apply this patch? [y/N/edit/skip]" (default N)
    User->>Chat: y (or edit + re-confirm, or skip)
    Chat->>Core: write_agent_artifact (Layer 1)
    Core->>Repo: write threats.yaml
    Lens-->>Chat: returns
    Core->>Repo: runs/<id>.json with hash chain
    Chat->>User: cost summary; next prompt
```

Notable differences from CI:

- No proposal PR — changes apply directly to the working tree (the human is the reviewer in real time).
- Every change passes through a default-N prompt — no `--auto-confirm` flag exists.
- The run record still gets written, so the audit trail is intact even for interactive use.

---

## Sequence diagram — Driving Loupe from an external MCP client

When Claude Code, Cursor, or a custom agent attaches to a running `loupe mcp` server and invokes a workflow.

```mermaid
sequenceDiagram
    autonumber
    participant Client as MCP Client<br/>(Claude Code, Cursor, etc.)
    participant MCP as loupe mcp<br/>(stdio or HTTP)
    participant Core as loupe-core
    participant Lens as ThreatLens
    participant LLM as Lens's LLM provider
    participant Repo as .loupe/

    Client->>MCP: tools/list (JSON-RPC)
    MCP-->>Client: [loupe.tools.*, loupe.workflows.*]
    Client->>MCP: tools/call: loupe.workflows.run_for_diff(diff)
    MCP->>Core: bootstrap RunContext + dispatch
    Core->>Lens: lens.run(...)
    Lens->>LLM: agent.run(...)
    LLM-->>Lens: propose_threat tool calls
    Lens->>Core: write_agent_artifact (Layer 1 still applies)
    Core->>Repo: write threats.yaml
    Core-->>MCP: structured result
    MCP-->>Client: tools/call response
    Client->>Client: render to user
```

Key invariant: **Layer 1 enforcement applies identically over MCP.** An external client cannot exceed the local agent's authority — the same `PathBoundary` checks every write, regardless of who initiated it.

---

## How to keep these diagrams in sync with the code

A few discipline rules:

1. **When a new package lands in `packages/`**, add a Container box to the Level 2 diagram.
2. **When a new component lands in `loupe-core/`**, add a Component box to the Level 3 diagram and update the `Rel(...)` lines.
3. **When a new lens lands**, add it to the "Lens / Capability extension model" diagram with the appropriate `requires_capabilities` arrows.
4. **When a new capability protocol is defined**, add the box + at least one backend; promote any "future / dashed" status to "current / solid" once shipped.
5. **The sequence diagrams** should be updated when a step in [`§7 of the spec`](specs/2026-05-13-loupe-design.md#section-7--end-to-end-flows-ci--interactive) changes — they're meant to be the visual companion to that narrative.

A future PR-review-toolkit hook could even diff this file's Mermaid against the live entry-point graph and warn on drift, but that's out of scope for v1.

---

## Why C4 + Mermaid (and not PlantUML, Structurizr, or images)

- **GitHub-native rendering** — readers don't need to install anything; the diagrams are visible directly in the rendered Markdown.
- **Source-controlled, diffable, AI-editable** — text in git is auditable in the same way the rest of Loupe is. A regulator can see in `git log` exactly when an arrow was added or removed.
- **C4's deliberate layering** maps cleanly to Loupe's: System Context → Containers → Components is exactly the storey-by-storey walk a new contributor wants.
- **The cost is render quality** — dedicated tools like Structurizr produce nicer-looking diagrams. We pay that cost in exchange for the diagrams living next to the code and updating with PRs.
