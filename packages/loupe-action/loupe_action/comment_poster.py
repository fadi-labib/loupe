"""Sticky-comment poster for the GitHub PR API.

`StickyCommentPoster.post(body)` is find-or-create:

1. List comments on the PR, paginating until exhausted.
2. If any comment body starts with ``COMMENT_SENTINEL``, ``PATCH`` it.
3. Otherwise, ``POST`` a new comment.

The sticky behaviour matters for audit hygiene: a long-lived PR with
30 push events should end with *one* Loupe comment showing the current
state, not 30 stale comments cluttering the review timeline. The
hash-chained run records under ``.loupe/runs/`` are where the audit
trail lives — the PR comment is a summary affordance.
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
            f"{self._api}/repos/{self._owner}/{self._name}/"
            f"issues/{self._pr}/comments?per_page=100"
        )
        while url is not None:
            response = await self._client.get(url, headers=self._headers())
            if response.status_code != 200:
                raise GitHubAPIError(
                    f"GET {url} returned {response.status_code}: {response.text}"
                )
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
            raise GitHubAPIError(
                f"PATCH {url} returned {response.status_code}: {response.text}"
            )
        return comment_id

    async def _create(self, *, body: str) -> int:
        url = f"{self._api}/repos/{self._owner}/{self._name}/issues/{self._pr}/comments"
        response = await self._client.post(
            url, content=json.dumps({"body": body}), headers=self._headers()
        )
        if response.status_code != 201:
            raise GitHubAPIError(
                f"POST {url} returned {response.status_code}: {response.text}"
            )
        payload: dict[str, Any] = response.json()
        return int(payload["id"])

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        }


_LINK_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


def _next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    match = _LINK_NEXT.search(link_header)
    return match.group(1) if match else None
