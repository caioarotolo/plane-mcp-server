"""Run with python -m plane_mcp.community; leave upstream entry points untouched."""

import os

# Upstream defaults to payload logging. Credentials and account data are private.
os.environ["LOG_PAYLOADS"] = "false"
os.environ["LOG_USER_INFO"] = "false"

import uvicorn  # noqa: E402
from fastmcp.server.dependencies import get_access_token  # noqa: E402
from redis.asyncio import Redis  # noqa: E402
from starlette.middleware.trustedhost import TrustedHostMiddleware  # noqa: E402

from plane_mcp.community.auth import CommunityAuth, CommunityOIDCProxy, LegacyHeaders, RequireBinding  # noqa: E402
from plane_mcp.community.portal import AccountPortal  # noqa: E402
from plane_mcp.community.settings import Settings  # noqa: E402
from plane_mcp.community.store import Vault  # noqa: E402
from plane_mcp.server import get_allowed_client_redirect_uris, get_header_mcp  # noqa: E402
from plane_mcp.storage import build_token_store  # noqa: E402


def build_app(settings: Settings):
    vault = Vault(Redis.from_url(settings.redis_url), settings.encryption_key)
    proxy = CommunityOIDCProxy(
        config_url=settings.discovery_url,
        client_id=settings.client_id,
        client_secret=settings.client_secret,
        audience=settings.client_id,
        algorithm="RS256",
        required_scopes=["openid"],
        base_url=settings.origin,
        redirect_path="/mcp/oauth/callback",
        allowed_client_redirect_uris=get_allowed_client_redirect_uris(),
        client_storage=build_token_store(),
        jwt_signing_key=settings.signing_key,
        token_endpoint_auth_method="client_secret_post",
        extra_authorize_params={"scope": "openid profile email offline_access"},
        enable_cimd=True,
        timeout_seconds=10,
    )
    server = get_header_mcp()
    server.auth = CommunityAuth(server=proxy, vault=vault, workspace=settings.workspace)
    server.add_middleware(RequireBinding())

    @server.tool
    async def identity() -> dict:
        """Show connection status and the secure browser page for linking/unlinking your own Plane token."""
        token = get_access_token()
        return {
            "linked": bool(token and token.claims.get("auth_method") == "api_key_header"),
            "account_url": settings.origin + "/mcp/account",
            "instructions": "Open the account page in your browser. Never paste your token into the chat.",
        }

    portal = AccountPortal(settings, vault, proxy.oidc_config)
    app = server.http_app(path="/mcp", stateless_http=True)
    app.router.routes.extend(portal.routes())
    from urllib.parse import urlsplit

    app = TrustedHostMiddleware(app, allowed_hosts=[urlsplit(settings.origin).hostname, "127.0.0.1", "localhost"])
    return LegacyHeaders(app, settings.workspace)


if __name__ == "__main__":
    uvicorn.run(build_app(Settings.from_env()), host="0.0.0.0", port=8211, access_log=False, proxy_headers=False)
