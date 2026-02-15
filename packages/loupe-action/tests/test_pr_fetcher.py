from __future__ import annotations

import httpx
import pytest
from loupe_action.pr_fetcher import PRFetcher, PRFetchError


def _async_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _fetcher(client):
    return PRFetcher(
        client=client,
        repo_owner="acme",
        repo_name="widgets",
        pr_number=42,
        token="ghp_test",
    )


@pytest.mark.asyncio
async def test_fetch_returns_base_head_and_diff():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("accept") == "application/vnd.github.v3.diff":
            return httpx.Response(200, text="diff --git a/x b/x\n+x\n")
        return httpx.Response(
            200,
            json={"base": {"sha": "b" * 40}, "head": {"sha": "h" * 40}},
        )

    async with _async_client(handler) as client:
        data = await _fetcher(client).fetch()
    assert data.base_sha == "b" * 40
    assert data.head_sha == "h" * 40
    assert "diff --git" in data.unified_diff


@pytest.mark.asyncio
async def test_fetch_raises_on_metadata_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "not found"})

    async with _async_client(handler) as client:
        with pytest.raises(PRFetchError, match="404"):
            await _fetcher(client).fetch()


@pytest.mark.asyncio
async def test_fetch_raises_on_diff_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("accept") == "application/vnd.github.v3.diff":
            return httpx.Response(422, text="diff too large")
        return httpx.Response(
            200,
            json={"base": {"sha": "x" * 40}, "head": {"sha": "y" * 40}},
        )

    async with _async_client(handler) as client:
        with pytest.raises(PRFetchError, match="422"):
            await _fetcher(client).fetch()
