# Versioning policy

Loupe is a workspace of four packages plus a set of independently-versioned schemas. This page is the contract: what counts as a breaking change in each surface, what doesn't, and how the surfaces compose.

The release-process steps (tag, build, publish, doc-site versioning via `mike`) live in [`CHANGELOG.md`](../changelog.md#release-process). This page is the *policy* document.

## SemVer tiers

Three tiers:

- **Pre-0.1 (today):** anything can change without warning. No SemVer guarantee.
- **0.1 through 0.x:** [SemVer 2.0](https://semver.org/) applies, with the pre-1.0 caveat that breaking changes may land in a minor release. Any such break is flagged `### Breaking` in CHANGELOG with a migration path.
- **1.0 onwards:** strict SemVer. Breaking changes only at major bumps.

## The six versioned surfaces

| Surface | Where the version lives | What a major bump means | What a minor bump means | What a patch bump means |
|---|---|---|---|---|
| `loupe-cli` commands & flags | `packages/loupe-cli/pyproject.toml` | A flag is renamed/removed, a subcommand is removed, an exit code changes meaning, or an existing command's output schema changes incompatibly. | A new subcommand or flag is added; output gains a field. | Bug fix or internal change with no observable behaviour shift. |
| `loupe-core` public Python API | `packages/loupe-core/pyproject.toml` | A breaking change to `Lens`, `LensCapabilities`, `RunContext`, `PathBoundary`, or any Capability Protocol method signature. | Additive: a new optional method on a Protocol; a new field on a model with a default; a new entry-point group. | Bug fix only. |
| Lens entry-point contract | Tracked with `loupe-core` major | Any change to the six required methods or to `LensCapabilities` field shape that breaks existing lenses. | New optional method (lenses can opt-in). | n/a (contract changes are not patches). |
| Capability Protocols | Tracked with `loupe-core` major | A Protocol method signature changes; a backend interface adds a required argument. Result models version *independently* — see below. | New optional Protocol method; new optional field on an input/result model. | Pure bug fix. |
| Artefact schemas (`Threat`, `Mitigation`, `RunRecord`, …) | The artefact's own `schema_version` field | The file format changes such that an older `loupe verify` cannot read it. Always paired with a documented migration in the changelog. | A new optional field added to the schema. | n/a. |
| GitHub Action inputs/outputs | `packages/loupe-action/action.yml` | An input is renamed or made required; an output is removed; the `exit_code` mapping changes. | A new optional input or new output is added. | Bug fix. |

## Why artefact schemas version independently

Run records, threats, mitigations, VEX statements, and the knowledge graph are files committed to repos. They outlive the version of Loupe that produced them. If a user upgrades `loupe-core` from v0.3 to v0.4 but has a year of `runs/*.json` files on disk, the upgraded `loupe verify` must still read them.

Each schema therefore carries its own `schema_version` field. A bump on that field is its own migration event with documented forward-compat rules. The Loupe package version is independent.

Example: `threats.yaml` schema v1 → v2 might add a new optional `attack_pattern_refs` field. The Pydantic model gets `schema_version: int = 2` plus `attack_pattern_refs: list[str] = []`. `loupe-core` v0.4 reads both v1 and v2 files. The CHANGELOG entry says "Threats schema bumped to v2: added `attack_pattern_refs`. v1 files are read transparently."

## Deprecation rules

For any surface above:

1. **Soft deprecation** — the old API still works but emits a `DeprecationWarning` (Python) or a banner on stderr (CLI). The deprecation note appears in the next minor release's CHANGELOG.
2. **One full minor cycle** of soft deprecation before removal. If `--foo` is soft-deprecated in v0.3, it can be removed in v0.4.
3. **Patch releases never deprecate.** Deprecations are documentation events; they ship with minors.
4. **Removal at majors only.** Once a feature is past its deprecation cycle, removal happens at the next major.

## What is *not* in the versioned surface

These can change at any time, no notice, no migration:

- Internal module layout (`loupe_core._internal.*` or any module starting with `_`).
- Test fixture schemas under `packages/*/tests/fixtures/`.
- Internal helper functions not exported from a package's top-level `__init__.py`.
- The exact wording of LLM prompts (under `loupe_threatlens/prompts/`). Prompts evolve with the agent's behaviour; the contract is *what the agent produces*, not *how it is asked*.
- Mermaid diagrams in the docs.
- The exact prose of CHANGELOG/about/comparison entries.
- The order of fields inside YAML/JSON output (we canonicalise on serialisation; consumers MUST not rely on key order).

## Pre-1.0 honesty

Until v1.0:

- Minor bumps *may* contain breaking changes if a design flaw is discovered. We try hard to avoid this; the CHANGELOG flags any breaking minor with `### Breaking` and the migration path.
- Schema breaking changes require a `schema_version` bump regardless of the host package version.
- We will not break the `runs/*.json` hash chain compatibility under any circumstance. Verifying an old run record on a new Loupe must keep working forever; that is the audit guarantee.

## Docs site versioning (via `mike`)

The docs site uses [`mike`](https://github.com/jimporter/mike) for versioned deploys. Every push to `main` writes the built site to the `gh-pages` branch under a `dev/` directory with the `latest` alias pointing at it. The version picker in the top-right of the docs only renders once at least one version has been deployed.

**Deploy commands** (the CI workflow does these automatically — `dev` aliased to `latest` on every push to main):

```bash
# Deploy the current branch as `dev`, alias to `latest`
uv run mike deploy --push --update-aliases dev latest

# Make `/latest/` the default redirect at the site root
uv run mike set-default --push latest
```

**When v0.1 ships**, the release process cuts the version directory and shifts the `latest` alias:

```bash
uv run mike deploy --push --update-aliases 0.1 latest
uv run mike set-default --push latest
# `dev` remains in the picker as a separate selectable version
```

**Local preview** of a versioned build (without pushing):

```bash
uv run mike deploy dev latest      # writes to local gh-pages branch
uv run mike serve                  # serves http://localhost:8000/
```

> [!NOTE]
> **About the in-repo `versions.json` stub:**
>
> - The Material theme fetches `versions.json` to populate the version picker.
> - Before `mike` has ever deployed, no such file exists; the dev server would log repeated 404 warnings.
> - To silence them, an empty `docs/versions.json` (`[]`) ships in-repo. The picker sees zero versions and hides itself.
> - Once `mike` deploys (CI on push to `main`, or `mike deploy` locally), the real `versions.json` lives at the `gh-pages` branch root and the picker renders real entries. The in-repo stub only sits inside each per-version directory, where the theme doesn't look.

**Deleting a version** (e.g., a botched deploy):

```bash
uv run mike delete --push 0.1
```

The GitHub Pages source must be set to **"Deploy from a branch"** with branch `gh-pages` (root). This is a one-time manual step in repo Settings → Pages and is incompatible with the older "GitHub Actions" source that uses `actions/upload-pages-artifact`.

## Cross-references

- [CHANGELOG.md](../changelog.md) — what changed in each release.
- [Decisions log](decisions.md) — *why* major surfaces are shaped the way they are.
- [Principle §10](../principles.md#principle-10) — "Design for current cases, not imagined ones." Versioning policy is itself a current case; we'll refine when v0.1 ships and a second concrete release follows.
