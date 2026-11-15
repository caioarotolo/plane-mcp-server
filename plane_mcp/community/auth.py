"""Adapt verified identities to upstream's existing per-request API-key context."""

import re

from fastmcp.server.auth import MultiAuth
from fastmcp.server.auth.oidc_proxy import OIDCProxy
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware
from fastmcp.tools.tool import ToolResult

from plane_mcp.auth.plane_header_auth_provider import PlaneHeaderAuthProvider
from plane_mcp.community.store import Vault, identity_key

PAT_PATTERN = re.compile(r"plane_api_[0-9a-f]{32}")


class CommunityOIDCProxy(OIDCProxy):
    def _prepare_scopes_for_upstream_refresh(self, scopes):
        # Authentik requires offline_access even when a client narrows its
        # refresh request to openid. It was granted on the initial login.
        return sorted(set(scopes) | {"offline_access"})

    def _decode_list_cookie(self, request, base_name):
        # Same upstream fix as PlaneOAuthProvider: a declined attempt must not
        # prevent the person from consenting on a later attempt.
        if base_name == "MCP_DENIED_CLIENTS":
            return []
        return super()._decode_list_cookie(request, base_name)


class PersonalTokenVerifier(PlaneHeaderAuthProvider):
    async def verify_token(self, token):
        # Never forward OAuth JWTs or arbitrary credentials to the Plane API.
        if not PAT_PATTERN.fullmatch(token):
            return None
        return await super().verify_token(token)


class CommunityAuth(MultiAuth):
    def __init__(self, *, server, vault: Vault, workspace: str):
        super().__init__(server=server, verifiers=[PersonalTokenVerifier()], required_scopes=[])
        self.vault = vault
        self.workspace = workspace

    async def verify_token(self, token):
        verified = await super().verify_token(token)
        if verified is None or verified.claims.get("auth_method") == "api_key_header":
            return verified
        subject = identity_key(verified.claims)
        binding = await self.vault.get("binding", subject)
        claims = {
            "auth_method": "api_key_header" if binding else "community_unlinked",
            "workspace_slug": self.workspace,
            "community_subject": subject,
            "plane_user_id": binding["user_id"] if binding else None,
        }
        # This copy lives only inside the authenticated request. OAuth issuance,
        # refresh and revocation remain owned by OIDCProxy; PATs never go to clients.
        return verified.model_copy(update={"token": binding["pat"] if binding else "", "claims": claims})


class RequireBinding(Middleware):
    async def on_call_tool(self, context, call_next):
        token = get_access_token()
        if token and token.claims.get("auth_method") == "community_unlinked" and context.message.name != "identity":
            return ToolResult(content="Link your Plane account first: call identity to get the secure account page.")
        return await call_next(context)


class LegacyHeaders:
    """Keep the deployed PAT-only clients compatible on the same /mcp URL."""

    def __init__(self, app, workspace: str):
        self.app, self.workspace = app, workspace

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"] == "/mcp":
            headers = list(scope["headers"])
            auth = [value for key, value in headers if key.lower() == b"authorization"]
            if len(auth) > 1:
                from starlette.responses import Response

                return await Response(status_code=400)(scope, receive, send)
            if auth and PAT_PATTERN.fullmatch(auth[0].decode("latin1").strip()):
                headers = [(k, b"Bearer " + v.strip() if k.lower() == b"authorization" else v) for k, v in headers]
            if not any(k.lower() == b"x-workspace-slug" for k, _ in headers):
                headers.append((b"x-workspace-slug", self.workspace.encode()))
            scope = {**scope, "headers": headers}
        await self.app(scope, receive, send)
