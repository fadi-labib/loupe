"""Loupe GitHub Action — entrypoint that wraps `loupe ci` for a PR.

Reads the Action's inputs from environment variables (per the GitHub
Actions convention: ``INPUT_*``), assembles the diff via the GitHub API,
invokes the CI pipeline as an in-process function call, formats the
result as a sticky PR comment, and writes Action outputs for downstream
steps.

Submodules:

- ``inputs``           — parse + validate environment-supplied inputs.
- ``formatter``        — render a RunRecord + threats into Markdown.
- ``comment_poster``   — find-or-create sticky PR comment.
- ``entrypoint``       — top-level orchestration.
"""
