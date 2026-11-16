"""OAuth grants for Plane Community; no external identity server."""

import secrets
import time

import httpx
from fastmcp.server.auth.auth import AccessToken, OAuthProvider, PrivateKeyJWTClientAuthenticator, TokenHandler
from fastmcp.server.auth.cimd import CIMDClientManager
from fastmcp.server.auth.redirect_validation import matches_allowed_pattern
from mcp.server.auth.handlers.revoke import RevocationHandler
from mcp.server.auth.provider import AuthorizationCode, AuthorizeError, RefreshToken, RegistrationError, TokenError
from mcp.server.auth.routes import build_metadata, cors_middleware
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.datastructures import FormData
from starlette.responses import JSONResponse
from starlette.routing import Route

from plane_mcp.community.auth import validate_pat
from plane_mcp.server import get_allowed_client_redirect_uris

ACCESS_TTL = 600
GRANT_TTL = 7 * 86400


class BoundTokenHandler(TokenHandler):
    async def handle(self, request):
        form = await request.form()
        if form.get("resource") not in (None, self.provider.settings.resource):
            return JSONResponse({"error": "invalid_target"}, status_code=400)
        return await super().handle(request)


class PublicRevocationHandler(RevocationHandler):
    async def handle(self, request):
        # The locked SDK requires this nullable field even for public clients.
        # Its client authentication and token ownership checks still run.
        form = await request.form()
        if "client_secret" not in form:
            request._form = FormData([*form.multi_items(), ("client_secret", "")])
        return await super().handle(request)


class DirectOAuth(OAuthProvider):
    def __init__(self, settings, vault):
        super().__init__(
            base_url=settings.origin,
            required_scopes=["plane"],
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=["plane"], default_scopes=["plane"]
            ),
            revocation_options=RevocationOptions(enabled=True),
        )
        self.settings, self.vault = settings, vault
        self.redirects = get_allowed_client_redirect_uris()
        self.cimd = CIMDClientManager(default_scope="plane", allowed_redirect_uri_patterns=self.redirects)

    async def get_client(self, client_id):
        if self.cimd.is_cimd_client_id(client_id):
            return await self.cimd.get_client(client_id)
        value = await self.vault.get("client", client_id)
        return OAuthClientInformationFull.model_validate(value) if value else None

    async def register_client(self, client_info):
        if client_info.token_endpoint_auth_method not in ("none", "client_secret_post", "client_secret_basic"):
            raise RegistrationError("invalid_client_metadata", "Unsupported authentication method")
        if not client_info.redirect_uris or any(
            not any(matches_allowed_pattern(str(uri), pattern) for pattern in self.redirects)
            for uri in client_info.redirect_uris
        ):
            raise RegistrationError("invalid_redirect_uri", "Redirect URI is not allowed")
        await self.vault.put("client", client_info.client_id, client_info.model_dump(mode="json"), GRANT_TTL)

    async def authorize(self, client, params):
        if params.resource not in (None, self.settings.resource):
            raise AuthorizeError("invalid_request", "Unexpected resource")
        if set(params.scopes or ["plane"]) != {"plane"}:
            raise AuthorizeError("invalid_scope", "The supported scope is plane")
        if not params.code_challenge or len(params.code_challenge) != 43:
            raise AuthorizeError("invalid_request", "PKCE S256 is required")
        flow = secrets.token_urlsafe(32)
        await self.vault.put(
            "flow",
            flow,
            {
                "client_id": client.client_id,
                "client_name": client.client_name or "MCP client",
                "params": params.model_dump(mode="json"),
            },
            300,
        )
        return self.settings.origin + "/mcp/authorize?request=" + flow

    async def load_authorization_code(self, client, authorization_code):
        data = await self.vault.get("code", authorization_code)
        if not data or data["client_id"] != client.client_id:
            return None
        return AuthorizationCode.model_validate(data)

    async def exchange_authorization_code(self, client, authorization_code):
        data = await self.vault.get("code", authorization_code.code, consume=True)
        if not data or data["client_id"] != client.client_id or data["expires_at"] <= time.time():
            raise TokenError("invalid_grant", "Code expired or already used")
        return await self.issue(data["grant_id"], ["plane"])

    async def issue(self, grant_id, scopes):
        grant = await self.vault.get("grant", grant_id)
        if not grant or grant["expires_at"] <= time.time():
            raise TokenError("invalid_grant", "Authorization expired or revoked")
        remaining = max(1, int(grant["expires_at"] - time.time()))
        ttl = min(ACCESS_TTL, remaining)
        access, refresh = "pmcp_a_" + secrets.token_urlsafe(32), "pmcp_r_" + secrets.token_urlsafe(32)
        common = {
            "grant_id": grant_id,
            "client_id": grant["client_id"],
            "scopes": scopes,
            "resource": self.settings.resource,
            "subject": grant["user_id"],
        }
        await self.vault.put("access", access, common | {"expires_at": int(time.time()) + ttl}, ttl)
        await self.vault.put("refresh", refresh, common | {"expires_at": grant["expires_at"]}, remaining)
        return OAuthToken(
            access_token=access, token_type="Bearer", expires_in=ttl, refresh_token=refresh, scope=" ".join(scopes)
        )

    async def detect_refresh_replay(self, token, client_id):
        spent = await self.vault.get("spent", token)
        if spent and spent["client_id"] == client_id:
            await self.vault.delete("grant", spent["grant_id"])

    async def load_refresh_token(self, client, refresh_token):
        if not refresh_token.startswith("pmcp_r_"):
            return None
        data = await self.vault.get("refresh", refresh_token)
        if not data:
            await self.detect_refresh_replay(refresh_token, client.client_id)
            return None
        if data["client_id"] != client.client_id or not await self.vault.get("grant", data["grant_id"]):
            return None
        return RefreshToken(
            token=refresh_token, **{k: data[k] for k in ("client_id", "scopes", "expires_at", "subject")}
        )

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        data = await self.vault.get("refresh", refresh_token.token)
        if not data:
            await self.detect_refresh_replay(refresh_token.token, client.client_id)
            raise TokenError("invalid_grant", "Refresh token already used")
        grant = await self.vault.get("grant", data["grant_id"])
        if not grant or data["client_id"] != client.client_id:
            raise TokenError("invalid_grant", "Authorization revoked")
        try:
            valid = await validate_pat(grant["pat"], self.settings.workspace)
        except (httpx.HTTPError, ValueError):
            raise TokenError("invalid_grant", "Plane validation unavailable") from None
        if not valid or valid["user_id"] != grant["user_id"]:
            await self.vault.delete("grant", data["grant_id"])
            raise TokenError("invalid_grant", "Plane access revoked")
        if not await self.vault.consume_refresh(refresh_token.token):
            await self.detect_refresh_replay(refresh_token.token, client.client_id)
            raise TokenError("invalid_grant", "Refresh token already used")
        return await self.issue(data["grant_id"], scopes)

    async def load_access_token(self, token):
        if not token.startswith("pmcp_a_"):
            return None
        data = await self.vault.get("access", token)
        if not data or data["expires_at"] <= time.time() or data["resource"] != self.settings.resource:
            return None
        grant = await self.vault.get("grant", data["grant_id"])
        if not grant or grant["client_id"] != data["client_id"] or grant["expires_at"] <= time.time():
            return None
        return AccessToken(
            token=token,
            client_id=data["client_id"],
            scopes=data["scopes"],
            expires_at=data["expires_at"],
            resource=data["resource"],
            subject=data["subject"],
            claims={"grant_id": data["grant_id"]},
        )

    async def verify_token(self, token):
        verified = await self.load_access_token(token)
        if not verified:
            return None
        grant = await self.vault.get("grant", verified.claims["grant_id"])
        if not grant:
            return None
        return verified.model_copy(
            update={
                "token": grant["pat"],
                "claims": {
                    "auth_method": "api_key_header",
                    "workspace_slug": self.settings.workspace,
                    "plane_user_id": grant["user_id"],
                },
            }
        )

    async def revoke_token(self, token):
        kind = "refresh" if isinstance(token, RefreshToken) else "access"
        data = await self.vault.get(kind, token.token)
        if data and data["client_id"] == token.client_id:
            await self.vault.delete("grant", data["grant_id"])

    async def metadata(self, request):
        data = build_metadata(
            self.base_url, None, self.client_registration_options, self.revocation_options
        ).model_dump(mode="json", exclude_none=True)
        data.update(
            client_id_metadata_document_supported=True,
            token_endpoint_auth_methods_supported=[
                "none",
                "client_secret_post",
                "client_secret_basic",
                "private_key_jwt",
            ],
            revocation_endpoint_auth_methods_supported=[
                "none",
                "client_secret_post",
                "client_secret_basic",
                "private_key_jwt",
            ],
        )
        return JSONResponse(data, headers={"Cache-Control": "public, max-age=300"})

    def get_routes(self, mcp_path=None):
        from plane_mcp.community.portal import ConsentPage

        routes = super().get_routes(mcp_path)
        authenticator = PrivateKeyJWTClientAuthenticator(self, self.cimd, self.settings.origin + "/token")
        handlers = {
            "/token": BoundTokenHandler(self, authenticator).handle,
            "/revoke": PublicRevocationHandler(self, authenticator).handle,
            "/.well-known/oauth-authorization-server": self.metadata,
        }
        for index, route in enumerate(routes):
            if isinstance(route, Route) and route.path in handlers:
                methods = ["GET", "OPTIONS"] if route.path.startswith("/.well-known") else ["POST", "OPTIONS"]
                routes[index] = Route(route.path, cors_middleware(handlers[route.path], methods), methods=methods)
        routes.extend(ConsentPage(self).routes())
        return routes
