"""Fetch a PR's metadata + unified diff via the GitHub API.

The Action is meant to work regardless of the runner's checkout depth.
``actions/checkout@v4`` defaults to a shallow clone, which means git
locally cannot compute ``git diff base...head`` without an extra fetch.
Going through the API sidesteps that entirely and produces a stable
unified-diff format that loupe_core.diff already parses.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx

_MAX_ATTEMPTS = 3
_INITIAL_BACKOFF_S = 1.0


class PRFetchError(RuntimeError):
    """Raised when the GitHub API returns a non-2xx response for PR data."""


class PRNotFoundError(PRFetchError):
    """Raised specifically when the PR (or repo) returns 404.

    Distinct subclass so callers can react to a missing PR (e.g. an
    out-of-date workflow firing against a PR that's been closed and the
    branch deleted) differently from transient or auth errors.
    """


@dataclass(frozen=True)
class PullRequestData:
    base_sha: str
    head_sha: str
    unified_diff: str


async def _request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
) -> httpx.Response:
    """Three-attempt exponential backoff for transient GitHub API failures.

    Retries on 5xx and on 403-with-``X-RateLimit-Remaining: 0``. Honours
    the ``Retry-After`` response header when present. 404 surfaces as a
    distinct :class:`PRNotFoundError`. All other 4xx responses propagate
    immediately as :class:`PRFetchError` — retrying a 401/403-with-auth-issue
    just burns time before the same failure.
    """
    last_response: httpx.Response | None = None
    for attempt in range(_MAX_ATTEMPTS):
        response = await client.request(method, url, headers=headers)
        if response.status_code < 400:
            return response
        if response.status_code == 404:
            raise PRNotFoundError(
                f"{method} {url} returned 404: {response.text}"
            )
        rate_limited = (
            response.status_code == 403
            and response.headers.get("X-RateLimit-Remaining") == "0"
        )
        is_retryable = response.status_code >= 500 or rate_limited
        if not is_retryable:
            raise PRFetchError(
                f"{method} {url} returned {response.status_code}: {response.text}"
            )
        last_response = response
        if attempt < _MAX_ATTEMPTS - 1:
            retry_after = response.headers.get("Retry-After")
            if retry_after is not None:
                try:
                    wait_s = float(retry_after)
                except ValueError:
                    wait_s = _INITIAL_BACKOFF_S * (2**attempt)
            else:
                wait_s = _INITIAL_BACKOFF_S * (2**attempt)
            await asyncio.sleep(wait_s)
    # Exhausted retries — surface the last response we saw.
    assert last_response is not None  # noqa: S101  # loop guarantees this
    raise PRFetchError(
        f"{method} {url} returned {last_response.status_code} "
        f"after {_MAX_ATTEMPTS} attempts: {last_response.text}"
    )


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
        response = await _request_with_retry(
            self._client,
            "GET",
            url,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        body: dict[str, Any] = response.json()
        return body

    async def _fetch_diff(self) -> str:
        url = f"{self._api}/repos/{self._owner}/{self._name}/pulls/{self._pr}"
        response = await _request_with_retry(
            self._client,
            "GET",
            url,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github.v3.diff",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        return response.text
