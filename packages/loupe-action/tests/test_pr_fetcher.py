from __future__ import annotations

import httpx
import pytest
from loupe_action.pr_fetcher import PRFetcher, PRFetchError, PRNotFoundError


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
            json={
                "base": {"sha": "b" * 40, "ref": "main"},
                "head": {"sha": "h" * 40, "ref": "feature/x"},
            },
        )

    async with _async_client(handler) as client:
        data = await _fetcher(client).fetch()
    assert data.base_sha == "b" * 40
    assert data.head_sha == "h" * 40
    assert data.head_branch == "feature/x"
    assert data.base_branch == "main"
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
            json={
                "base": {"sha": "x" * 40, "ref": "main"},
                "head": {"sha": "y" * 40, "ref": "feature/x"},
            },
        )

    async with _async_client(handler) as client:
        with pytest.raises(PRFetchError, match="422"):
            await _fetcher(client).fetch()


@pytest.mark.asyncio
async def test_fetch_404_raises_pr_not_found_error():
    # 404 (PR closed, repo renamed, wrong number) is structurally distinct
    # from auth or rate-limit failures — we want callers to be able to
    # `except PRNotFoundError` without swallowing transient errors.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "not found"})

    async with _async_client(handler) as client:
        with pytest.raises(PRNotFoundError):
            await _fetcher(client).fetch()


@pytest.mark.asyncio
async def test_fetch_retries_on_502_and_succeeds(monkeypatch):
    # Patch sleep to keep the test fast.
    import loupe_action.pr_fetcher as mod

    async def _no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr(mod.asyncio, "sleep", _no_sleep)

    metadata_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal metadata_calls
        if request.headers.get("accept") == "application/vnd.github.v3.diff":
            return httpx.Response(200, text="diff --git a/x b/x\n+x\n")
        metadata_calls += 1
        if metadata_calls < 3:
            return httpx.Response(502, text="bad gateway")
        return httpx.Response(
            200,
            json={
                "base": {"sha": "b" * 40, "ref": "main"},
                "head": {"sha": "h" * 40, "ref": "feature/x"},
            },
        )

    async with _async_client(handler) as client:
        data = await _fetcher(client).fetch()
    assert metadata_calls == 3  # confirmed it took all 3 attempts
    assert data.base_sha == "b" * 40


@pytest.mark.asyncio
async def test_fetch_retries_on_rate_limited_403(monkeypatch):
    import loupe_action.pr_fetcher as mod

    async def _no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr(mod.asyncio, "sleep", _no_sleep)

    metadata_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal metadata_calls
        if request.headers.get("accept") == "application/vnd.github.v3.diff":
            return httpx.Response(200, text="diff --git a/x b/x\n+x\n")
        metadata_calls += 1
        if metadata_calls == 1:
            return httpx.Response(
                403,
                text="rate limited",
                headers={"X-RateLimit-Remaining": "0", "Retry-After": "0"},
            )
        return httpx.Response(
            200,
            json={
                "base": {"sha": "b" * 40, "ref": "main"},
                "head": {"sha": "h" * 40, "ref": "feature/x"},
            },
        )

    async with _async_client(handler) as client:
        data = await _fetcher(client).fetch()
    assert metadata_calls == 2
    assert data.head_sha == "h" * 40


@pytest.mark.asyncio
async def test_fetch_does_not_retry_on_non_rate_limited_403(monkeypatch):
    # A plain 403 (e.g. token lacks scope) is *not* retryable — we don't
    # want to burn time and quota on the same auth failure three times.
    import loupe_action.pr_fetcher as mod

    sleep_called = False

    async def _spy_sleep(_: float) -> None:
        nonlocal sleep_called
        sleep_called = True

    monkeypatch.setattr(mod.asyncio, "sleep", _spy_sleep)

    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(403, text="forbidden")

    async with _async_client(handler) as client:
        with pytest.raises(PRFetchError, match="403"):
            await _fetcher(client).fetch()
    assert calls == 1
    assert sleep_called is False


@pytest.mark.asyncio
async def test_fetch_exhausts_retries_and_surfaces_last_status(monkeypatch):
    import loupe_action.pr_fetcher as mod

    async def _no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr(mod.asyncio, "sleep", _no_sleep)

    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, text="service unavailable")

    async with _async_client(handler) as client:
        with pytest.raises(PRFetchError, match="503"):
            await _fetcher(client).fetch()
    assert calls == 3  # all attempts used
