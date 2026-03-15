# Contributing to Loupe

## Prerequisites

- **Python 3.13** (uv will fetch it automatically if not installed)
- **uv** ≥ 0.10 [installation instructions](https://docs.astral.sh/uv/getting-started/installation/)
- **git** ≥ 2.40
- An **Anthropic API key** if you are re-recording VCR cassettes (the test suite replays cassettes without one)

## Initial setup

```bash
git clone <repo>
cd loupe
uv sync --all-packages
```

This will:
1. Auto-fetch Python 3.13 if you don't have it
2. Create a `.venv/` at the repo root
3. Install all four workspace packages (`loupe-core`, `loupe-cli`, `loupe-threatlens`, `loupe-action`) in editable mode
4. Install dev dependencies (`pytest`, `pytest-vcr`, `ruff`, `mypy`)

Recommended one-time setup of the pre-commit hooks, which run the strict docs build, ruff lint, and ruff format-check on every commit:

```bash
uv tool install pre-commit
pre-commit install
```

The hooks add about two seconds per commit and catch broken doc links, ruff regressions, and format drift before push.

## Running the documentation site locally

```bash
uv sync --all-packages --group docs
uv run mkdocs serve
```

Opens at <http://127.0.0.1:8000>. Live-reloads on save. `uv run mkdocs build --strict` is what CI runs; same command runs cleanly locally.

## Prose linting (Vale)

`.vale.ini` plus the rules under `.vale/styles/Loupe/` enforce the voice the docs were rewritten into: no em-dash overuse, no bold-prefixed sentence openers, no AI-vocabulary smell-test words, no templated `**The practical consequence**:` footers. The same checks run on every PR.

Install Vale once:

```bash
# Linux: brew, apt, or download the binary from https://vale.sh/
brew install vale
# or
sudo snap install vale
```

Then locally:

```bash
vale docs/
```

CI fails on any new warning introduced by the PR (`filter_mode: added`), so the lint stays focused on the diff, not the whole corpus.

## Running tests

```bash
uv run pytest                       # whole workspace
uv run pytest packages/loupe-core   # only core tests
uv run pytest -v                    # verbose
uv run pytest -k threat             # tests matching 'threat'
```

Tests must pass with no API keys present. Any test that talks to an LLM does so via VCR cassettes (recorded once, replayed forever; see [`principles.md` §9](principles.md#principle-9)).

## Code style

```bash
uv run ruff check .                 # lint
uv run ruff format .                # format
uv run mypy packages/loupe-core/    # type-check
```

Configured in the root `pyproject.toml`:
- Line length 100
- Target Python 3.13
- Ruff rules: `E`, `F`, `I`, `B`, `UP`, `ANN` (with `ANN101`/`ANN102` ignored: no `self`/`cls` annotations needed)
- mypy `strict = true`

## What CI runs on every PR

Four workflows under `.github/workflows/` gate every PR. They run in parallel; a PR is mergeable when all four are green.

| Workflow | File | When it triggers | What it does | What blocks the PR |
|---|---|---|---|---|
| `tests` | `tests.yml` | On any push | pytest across the full workspace; ruff lint + format; mypy strict | Any test failure, lint error, or type error |
| `docs` | `docs.yml` | Push to main, plus PRs touching `docs/`, `mkdocs.yml`, `pyproject.toml`, or `packages/**/*.py` | Builds the MkDocs site with `--strict`; on main, deploys to GitHub Pages via `actions/deploy-pages@v4` | Any broken link, missing snippet target, stale anchor, or unrecognised plugin directive |
| `link-check` | `link-check.yml` | Push or PR touching `**.md` | Runs lychee against every Markdown file; caches results between runs | A broken external URL or unresolvable relative link |
| `prose-check` | `prose-check.yml` | Push or PR touching `docs/**/*.md`, `.vale.ini`, or `.vale/**` | Runs Vale against `docs/` with `filter_mode: added`; only flags warnings introduced by the diff | Any new em-dash overuse, bold-prefixed sentence opener, AI-vocabulary word, or templated footer |

Locally, the pre-commit hook (see [Initial setup](#initial-setup) above) runs the docs strict build, ruff lint, and ruff format-check on every commit. That covers two of the four CI workflows without waiting for the PR.

## Workspace layout

```
loupe/
├── docs/                                Documentation (you are here)
│   ├── about.md
│   ├── principles.md
│   ├── reference/decisions.md
│   ├── contributing.md
│   ├── concepts/architecture.md
│   ├── concepts/capabilities.md
│   ├── comparison.md
│   ├── reference/data-handling.md
│   ├── reference/evaluation.md
│   └── reference/glossary.md
├── packages/                            All Python packages
│   ├── loupe-core/                      The platform
│   ├── loupe-cli/                       The CLI shell
│   ├── loupe-threatlens/                The v1 lens
│   └── loupe-action/                    GitHub Action wrapper
├── pyproject.toml                       Workspace root
└── README.md
```

## Working on the codebase

### Before changing code

Read the relevant section of [`reference/decisions.md`](reference/decisions.md). If your change updates an existing decision (D-NN), note that in the PR description and update the log. If it creates a new decision, add the next available `D-NN` to the log.

When a change touches enforcement, cost-saving, or human-in-the-loop concerns, [`principles.md`](principles.md) is the source of truth for what we will and won't compromise on.

### Implementation discipline

Every code change should:

1. Start with a failing test in `packages/<package>/tests/`.
2. Implement the minimum to make it pass.
3. Run `uv run pytest` and confirm green.
4. Commit with a Conventional Commits–style message (`feat(core):`, `fix(threatlens):`, `chore:`, `docs:`, `test:`, etc.).
5. Never add `Co-Authored-By` lines attributing AI in commit messages.

Granularity rule of thumb: ~2–5 minutes per step, ~5 steps per task, ~5 tasks per logical chunk of work. If a change starts feeling bigger than that, split it.

### Adding a new artefact schema

Artefacts are Pydantic models with a YAML or JSON round-trip:

1. Create `packages/loupe-core/loupe_core/artifacts/<name>.py`.
2. Create `packages/loupe-core/tests/artifacts/test_<name>.py` with at least:
   - A minimal-valid test
   - A schema-rejection test (invalid ID format, missing field, etc.)
   - A round-trip test (save + load)
3. If the artefact is agent-writable, add its path to the `agent_writable_paths` list in any relevant fixtures.

### Adding a new tool to a lens

1. Define an input model (Pydantic) in the lens's `tools.py`.
2. Define a result model (Pydantic).
3. Implement the tool function. It MUST use `write_agent_artifact` (or `propose_patch`) to mutate state; never write directly.
4. Add a unit test that exercises the tool without an LLM.
5. Register the tool with the lens's PydanticAI agent via `@agent.tool`.

### Writing a new lens

The lens API has shipped; the current minimal contract (six methods, one declared attribute) is recorded in [`reference/decisions.md` D-11](reference/decisions.md#d-11). When the second lens lands, the API will get refined; until then, the v1 shape is what to follow.

The minimum shape:

```python
# packages/loupe-<myname>/loupe_<myname>/lens.py
from loupe_core.lens_api import LensCapabilities
from loupe_core.run_context import RunContext, RelevanceScore

class MyLens:
    capabilities = LensCapabilities(
        name="myname",
        domain="my-domain",
        handles_intent_keywords=["…"],
        artifact_paths=[".loupe/my-artifact.yaml"],
    )

    def build_agent(self, deps_type):
        ...

    def mcp_tools(self):
        return [...]

    def mcp_workflows(self):
        return [...]

    def is_relevant(self, ctx: RunContext) -> RelevanceScore:
        # MUST be a pure-Python heuristic, no LLM call
        ...

    async def run(self, ctx, plan_entry, boundary, loupe_dir) -> None:
        ...
```

Register via Python entry points in your `pyproject.toml`:

```toml
[project.entry-points."loupe.lenses"]
myname = "loupe_myname.lens:MyLens"
```

Once your package is installed alongside `loupe-cli`, the entry-point group `loupe.lenses` will surface it. A `loupe lens list` discovery subcommand is part of the CLI design but not yet registered.

### Working on the GitHub Action

The Action lives in `packages/loupe-action/`:

- `action.yml`: the composite-action manifest GitHub reads.
- `loupe_action/inputs.py`: typed env-var validation.
- `loupe_action/pr_fetcher.py`: fetch PR base/head SHA + unified diff via the API.
- `loupe_action/formatter.py`: render run record + threats as Markdown.
- `loupe_action/comment_poster.py`: sticky comment (find-or-create).
- `loupe_action/entrypoint.py`: top-level `run(env, client, cwd)` orchestrator.

`run(...)` takes its environment, HTTP client, and working directory as
parameters so tests can drive it end-to-end with `httpx.MockTransport` +
a `tmp_path` workspace + a stubbed `ci_command`. See
`tests/test_entrypoint.py` for the pattern.

To test against a real GitHub PR locally:

```bash
export GITHUB_TOKEN=ghp_...
export GITHUB_REPOSITORY=acme/widgets
export GITHUB_WORKSPACE=$PWD
export INPUT_PR=123
export INPUT_CONFIG=.loupe/config.yaml
export INPUT_COMMENT_MODE=none    # don't actually post while iterating
python -m loupe_action.entrypoint
```

## Useful commands

```bash
# Find TODO/FIXME markers across the Python source.
# The default-config template at loupe-cli/init_cmd.py contains
# intentional TODO placeholders inside the .loupe/context.md scaffold
# (those are markers for the user to fill in, not code debt). Filter
# those out with `grep -v init_cmd` if you want a clean list of source
# TODOs.
grep -rn "TODO\|FIXME" packages/

# Build all packages
uv build --all-packages

# Open a Python REPL with everything loaded
uv run python

# Show the git history with a tree view
git log --oneline --graph --all
```

## Commit conventions

Conventional Commits with these scopes:

- `feat(core):`, `feat(cli):`, `feat(threatlens):`, `feat(action):` new functionality
- `fix(<scope>):` bug fixes
- `chore:` workspace config, dependencies, tooling
- `docs:` documentation changes only
- `test:` test additions/changes that don't touch behaviour
- `refactor:` code restructuring without behaviour change

Examples from the existing history:
- `feat(core): RunContext with Fact + namespaced findings`
- `chore: workspace pyproject + gitignore + readme`
- `docs: add Loupe v1 design spec`

Never use `--no-verify` or `Co-Authored-By` lines.

## Filing issues / proposing changes

(Not yet set up; this is a pre-alpha private repo.)

When the repo opens:

1. Read [`about.md`](about.md), [`principles.md`](principles.md), and [`reference/decisions.md`](reference/decisions.md) before opening a PR with a structural change.
2. For a bug fix or small feature: open a PR with a failing test in the same commit as the description, and the fix in a follow-up commit.
3. For a new lens: open a discussion issue first to discuss the lens API surface; adding a second instance is the moment we expect to refine the plugin contract (D-04).
