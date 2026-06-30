"""Bearer-token auth for `loupe mcp --transport sse`.

The stdio transport (the default) is process-local — no network port, no
auth needed. The SSE remote transport is the opt-in exception: per D-09,
remote MCP access "requires authentication and explicit opt-in." This
module wires that requirement using the official `mcp` SDK's own
bearer-auth primitives (`mcp.server.auth`) rather than hand-rolling
Starlette middleware, so loupe inherits the SDK's `WWW-Authenticate`
error contract and any future hardening for free.

Per the chosen design (a static, operator-supplied token — no
auto-generation, no OAuth flow), `AuthSettings.issuer_url` is a required
field shaped for a real OAuth authorization server. We never set
`auth_server_provider`, so no OAuth discovery routes
(`/.well-known/oauth-*`) ever mount; only the bearer-verifier plumbing in
`token_verifier` is exercised. The dummy self-referential `issuer_url`
below is safe under that condition — see D-28.
"""

from __future__ import annotations

import hmac
import os

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings

LOUPE_MCP_TOKEN_ENV = "LOUPE_MCP_TOKEN"


class StaticTokenVerifier(TokenVerifier):
    """Accepts exactly one operator-supplied token.

    Comparison is constant-time (`hmac.compare_digest`) so token checking
    doesn't leak timing information about how much of the token matched.
    """

    def __init__(self, token: str) -> None:
        self._token = token

    async def verify_token(self, token: str) -> AccessToken | None:
        if hmac.compare_digest(token, self._token):
            return AccessToken(token=token, client_id="operator", scopes=[])
        return None


def resolve_token(token_flag: str | None) -> str | None:
    """Resolve the SSE bearer token: ``--token`` flag wins over `LOUPE_MCP_TOKEN`.

    Returns None when neither source provides a token — callers must
    treat that as "refuse to start the SSE transport," not "run with no
    auth."
    """
    if token_flag is not None:
        return token_flag
    return os.environ.get(LOUPE_MCP_TOKEN_ENV)


def build_auth_settings(host: str, port: int) -> AuthSettings:
    """Build the `AuthSettings` FastMCP needs to enable bearer-token auth.

    `issuer_url` is required by the field's type but is never dereferenced
    as a real OAuth endpoint here (no `auth_server_provider` is set), so a
    self-referential URL is a safe placeholder. `resource_server_url=None`
    keeps this server purely a bearer-verifying resource, not a combined
    authorization server.
    """
    return AuthSettings(issuer_url=f"http://{host}:{port}", resource_server_url=None)  # type: ignore[arg-type]
