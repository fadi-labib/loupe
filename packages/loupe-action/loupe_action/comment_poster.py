"""Comment posters for the GitHub PR API.

Two strategies, selectable via ``action.yml``'s ``comment_mode`` input:

- ``StickyCommentPoster.post(body)`` is find-or-create. List comments,
  PATCH any prior bot-authored comment carrying ``COMMENT_SENTINEL``,
  otherwise POST a new one. Long-lived PRs end with *one* current
  Loupe summary instead of one per push.
- ``FreshCommentPoster.post(body)`` always POSTs a new comment, even if
  a prior sticky one exists. Use when reviewers prefer a per-push
  timeline (each comment captures the state at that push) over a single
  rolling summary.

The hash-chained run records under ``.loupe/runs/`` are where the audit
trail lives — PR comments are a summary affordance, not authoritative.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from loupe_action.formatter import COMMENT_SENTINEL


class GitHubAPIError(RuntimeError):
    """Wraps a non-2xx response from the GitHub API."""


# The login identity the GitHub Actions runner publishes comments under
# when authenticated with the default ``GITHUB_TOKEN``. Filtering on this
# ensures the sticky-comment poster won't *edit* a stranger's comment that
# happens to contain the sentinel marker (e.g. a copy-pasted bug repro).
_BOT_LOGIN = "github-actions[bot]"


class StickyCommentPoster:
    def __init__(
        self,
        *,
        client: httpx.AsyncClient,
        repo_owner: str,
        repo_name: str,
        pr_number: int,
        token: str,
        api_url: str = "https://api.github.com",
    ) -> None:
        self._client = client
        self._owner = repo_owner
        self._name = repo_name
        self._pr = pr_number
        self._token = token
        self._api = api_url.rstrip("/")

    async def post(self, *, body: str) -> int:
        existing = await self._find_existing()
        if existing is not None:
            return await self._edit(comment_id=existing, body=body)
        return await self._create(body=body)

    async def _find_existing(self) -> int | None:
        url: str | None = (
            f"{self._api}/repos/{self._owner}/{self._name}/issues/{self._pr}/comments?per_page=100"
        )
        while url is not None:
            response = await self._client.get(url, headers=self._headers())
            if response.status_code != 200:
                raise GitHubAPIError(f"GET {url} returned {response.status_code}: {response.text}")
            for comment in response.json():
                if not comment.get("body", "").startswith(COMMENT_SENTINEL):
                    continue
                # Identity check: only edit comments authored by the bot
                # we publish under. A reviewer copy-pasting our sentinel
                # into their own comment (intentionally or otherwise)
                # should not cause us to overwrite it.
                if comment.get("user", {}).get("login") != _BOT_LOGIN:
                    continue
                return int(comment["id"])
            url = _next_link(response.headers.get("Link"))
        return None

    async def _edit(self, *, comment_id: int, body: str) -> int:
        url = f"{self._api}/repos/{self._owner}/{self._name}/issues/comments/{comment_id}"
        response = await self._client.patch(
            url, content=json.dumps({"body": body}), headers=self._headers()
        )
        if response.status_code == 404:
            # The sticky comment we previously created has been deleted
            # (manually by a reviewer, or by branch-protection cleanup).
            # Recover by creating a fresh comment rather than failing the
            # whole run for a transient state.
            return await self._create(body=body)
        if response.status_code != 200:
            raise GitHubAPIError(f"PATCH {url} returned {response.status_code}: {response.text}")
        return comment_id

    async def _create(self, *, body: str) -> int:
        url = f"{self._api}/repos/{self._owner}/{self._name}/issues/{self._pr}/comments"
        response = await self._client.post(
            url, content=json.dumps({"body": body}), headers=self._headers()
        )
        if response.status_code != 201:
            raise GitHubAPIError(f"POST {url} returned {response.status_code}: {response.text}")
        payload: dict[str, Any] = response.json()
        return int(payload["id"])

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        }


class FreshCommentPoster(StickyCommentPoster):
    """Always create a new comment; never edit an existing sticky one.

    Inherits header construction and ``_create`` from
    ``StickyCommentPoster`` so the only behavioural delta is the override
    of ``post()`` — no list / patch logic. The shared transport state
    (auth header, API base, repo coords) is wired through the parent
    constructor unchanged.

    This implements ``comment_mode: new`` from ``action.yml``. Operators
    who want a per-push audit trail in the PR timeline pick this over
    sticky; operators who want a single rolling summary pick sticky.
    """

    async def post(self, *, body: str) -> int:
        # Deliberately bypass `_find_existing` — even if a prior sticky
        # comment exists, we leave it alone and create fresh. The historical
        # bot-authored comments stay in the timeline as a per-push record.
        return await self._create(body=body)


_LINK_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


def _next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    match = _LINK_NEXT.search(link_header)
    return match.group(1) if match else None
