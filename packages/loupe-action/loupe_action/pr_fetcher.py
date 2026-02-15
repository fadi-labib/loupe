"""Fetch a PR's metadata + unified diff via the GitHub API.

The Action is meant to work regardless of the runner's checkout depth.
``actions/checkout@v4`` defaults to a shallow clone, which means git
locally cannot compute ``git diff base...head`` without an extra fetch.
Going through the API sidesteps that entirely and produces a stable
unified-diff format that loupe_core.diff already parses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


class PRFetchError(RuntimeError):
    """Raised when the GitHub API returns a non-2xx response for PR data."""


@dataclass(frozen=True)
class PullRequestData:
    base_sha: str
    head_sha: str
    unified_diff: str


class PRFetcher:
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

    async def fetch(self) -> PullRequestData:
        meta = await self._fetch_metadata()
        diff = await self._fetch_diff()
        return PullRequestData(
            base_sha=meta["base"]["sha"],
            head_sha=meta["head"]["sha"],
            unified_diff=diff,
        )

    async def _fetch_metadata(self) -> dict[str, Any]:
        url = f"{self._api}/repos/{self._owner}/{self._name}/pulls/{self._pr}"
        response = await self._client.get(
            url,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        if response.status_code != 200:
            raise PRFetchError(
                f"GET {url} returned {response.status_code}: {response.text}"
            )
        body: dict[str, Any] = response.json()
        return body

    async def _fetch_diff(self) -> str:
        url = f"{self._api}/repos/{self._owner}/{self._name}/pulls/{self._pr}"
        response = await self._client.get(
            url,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github.v3.diff",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        if response.status_code != 200:
            raise PRFetchError(
                f"GET {url} (diff) returned {response.status_code}: {response.text}"
            )
        return response.text
