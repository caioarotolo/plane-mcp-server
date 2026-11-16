"""Optional entry point. All official tools and entry points remain untouched."""

import os

os.environ["LOG_PAYLOADS"] = "false"
os.environ["LOG_USER_INFO"] = "false"

from urllib.parse import urlsplit  # noqa: E402

import uvicorn  # noqa: E402
from fastmcp.server.auth import MultiAuth  # noqa: E402
from redis.asyncio import Redis  # noqa: E402
from starlette.middleware.trustedhost import TrustedHostMiddleware  # noqa: E402

from plane_mcp.community.auth import AuthGuard, LegacyHeaders, PersonalTokenVerifier  # noqa: E402
from plane_mcp.community.oauth import DirectOAuth  # noqa: E402
from plane_mcp.community.settings import Settings  # noqa: E402
from plane_mcp.community.store import Vault  # noqa: E402
from plane_mcp.server import get_header_mcp  # noqa: E402


def build_app(settings):
    vault = Vault(
        Redis.from_url(settings.redis_url, socket_timeout=3, socket_connect_timeout=3), settings.encryption_key
    )
    server = get_header_mcp()
    server.auth = MultiAuth(
        server=DirectOAuth(settings, vault), verifiers=[PersonalTokenVerifier()], required_scopes=[]
    )
    app = server.http_app(path="/mcp", stateless_http=True)
    app = AuthGuard(app, vault.redis)
    app = TrustedHostMiddleware(app, allowed_hosts=[urlsplit(settings.origin).hostname, "127.0.0.1", "localhost"])
    return LegacyHeaders(app, settings.workspace)


if __name__ == "__main__":
    uvicorn.run(build_app(Settings.from_env()), host="0.0.0.0", port=8211, access_log=False, proxy_headers=False)
