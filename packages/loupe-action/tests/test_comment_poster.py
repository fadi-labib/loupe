from __future__ import annotations

from typing import Any

import httpx
import pytest
from loupe_action.comment_poster import (
    GitHubAPIError,
    StickyCommentPoster,
)
from loupe_action.formatter import COMMENT_SENTINEL


def _client(handler):
    transport = httpx.MockTransport(handler)
    return httpx.Client(transport=transport)


def _async_client(handler):
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport)


def _build_poster(client) -> StickyCommentPoster:
    return StickyCommentPoster(
        client=client,
        repo_owner="acme",
        repo_name="widgets",
        pr_number=42,
        token="ghp_test",
    )


@pytest.mark.asyncio
async def test_posts_new_comment_when_none_exists():
    posted: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "comments" in str(request.url):
            return httpx.Response(200, json=[])  # no existing comments
        if request.method == "POST" and "comments" in str(request.url):
            posted["body"] = request.content.decode()
            return httpx.Response(201, json={"id": 999})
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    async with _async_client(handler) as client:
        body = f"{COMMENT_SENTINEL}\n## Loupe analysis\nclean\n"
        await _build_poster(client).post(body=body)
    assert COMMENT_SENTINEL in posted["body"]


@pytest.mark.asyncio
async def test_edits_existing_sticky_comment_in_place():
    edits: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path.endswith("/comments"):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 100,
                        "body": "unrelated user comment",
                        "user": {"login": "alice"},
                    },
                    {
                        "id": 101,
                        "body": f"{COMMENT_SENTINEL}\n## old",
                        "user": {"login": "github-actions[bot]"},
                    },
                    {
                        "id": 102,
                        "body": "another comment",
                        "user": {"login": "bob"},
                    },
                ],
            )
        if request.method == "PATCH" and "comments/101" in str(request.url):
            edits["body"] = request.content.decode()
            return httpx.Response(200, json={"id": 101})
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    async with _async_client(handler) as client:
        body = f"{COMMENT_SENTINEL}\n## Loupe analysis\nnew\n"
        await _build_poster(client).post(body=body)
    assert "new" in edits["body"]


@pytest.mark.asyncio
async def test_authorization_header_carries_token():
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        if request.method == "GET":
            return httpx.Response(200, json=[])
        return httpx.Response(201, json={"id": 1})

    async with _async_client(handler) as client:
        await _build_poster(client).post(body=f"{COMMENT_SENTINEL}\n")
    assert seen_headers["authorization"] == "Bearer ghp_test"
    assert seen_headers["accept"] == "application/vnd.github+json"


@pytest.mark.asyncio
async def test_raises_on_listing_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "rate limited"})

    async with _async_client(handler) as client:
        with pytest.raises(GitHubAPIError, match="403"):
            await _build_poster(client).post(body=f"{COMMENT_SENTINEL}\n")


@pytest.mark.asyncio
async def test_raises_on_post_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=[])
        return httpx.Response(422, json={"message": "validation"})

    async with _async_client(handler) as client:
        with pytest.raises(GitHubAPIError, match="422"):
            await _build_poster(client).post(body=f"{COMMENT_SENTINEL}\n")


@pytest.mark.asyncio
async def test_handles_paginated_comment_listing():
    # The API returns up to 100 comments per page; we must follow Link headers
    # to find a sticky comment that's pages deep on a long-running PR.
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.method == "GET" and "page=2" not in str(request.url):
            return httpx.Response(
                200,
                json=[{"id": 1, "body": "unrelated", "user": {"login": "alice"}}],
                headers={
                    "Link": f'<{request.url}&page=2>; rel="next"'
                },
            )
        if request.method == "GET" and "page=2" in str(request.url):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 99,
                        "body": f"{COMMENT_SENTINEL}\nfound",
                        "user": {"login": "github-actions[bot]"},
                    }
                ],
            )
        if request.method == "PATCH" and "/99" in str(request.url):
            return httpx.Response(200, json={"id": 99})
        raise AssertionError(f"unexpected: {request.method} {request.url}")

    async with _async_client(handler) as client:
        await _build_poster(client).post(body=f"{COMMENT_SENTINEL}\nnew\n")
    assert any("page=2" in c for c in calls)


@pytest.mark.asyncio
async def test_ignores_stranger_authored_comment_with_sentinel():
    # A reviewer pastes our sentinel into their own comment. We must NOT
    # treat that as our sticky comment and overwrite it. Falling through
    # to POST means we create a fresh bot-authored comment instead.
    posted_bodies: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "comments" in str(request.url):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 555,
                        "body": f"{COMMENT_SENTINEL}\nI pasted this!",
                        "user": {"login": "curious-reviewer"},
                    },
                ],
            )
        if request.method == "POST" and "comments" in str(request.url):
            posted_bodies.append(request.content.decode())
            return httpx.Response(201, json={"id": 9999})
        if request.method == "PATCH":
            raise AssertionError("must not PATCH a stranger's comment")
        raise AssertionError(f"unexpected: {request.method} {request.url}")

    async with _async_client(handler) as client:
        await _build_poster(client).post(body=f"{COMMENT_SENTINEL}\nfresh\n")
    assert len(posted_bodies) == 1
    assert "fresh" in posted_bodies[0]


@pytest.mark.asyncio
async def test_patch_404_falls_back_to_create():
    # The previously-stickied comment got deleted between the GET that
    # found it and the PATCH that tried to edit it. Don't fail the run —
    # create a fresh sticky comment instead.
    posted_bodies: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "comments" in str(request.url):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 101,
                        "body": f"{COMMENT_SENTINEL}\nold",
                        "user": {"login": "github-actions[bot]"},
                    }
                ],
            )
        if request.method == "PATCH" and "comments/101" in str(request.url):
            return httpx.Response(404, json={"message": "Not Found"})
        if request.method == "POST" and "comments" in str(request.url):
            posted_bodies.append(request.content.decode())
            return httpx.Response(201, json={"id": 202})
        raise AssertionError(f"unexpected: {request.method} {request.url}")

    async with _async_client(handler) as client:
        await _build_poster(client).post(body=f"{COMMENT_SENTINEL}\nrecovered\n")
    assert len(posted_bodies) == 1
    assert "recovered" in posted_bodies[0]
