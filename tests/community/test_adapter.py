"""Security boundaries and backward compatibility of the optional adapter."""

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fakeredis.aioredis import FakeRedis
from fastmcp.server.auth.auth import AccessToken, TokenVerifier
from fastmcp.server.auth.oidc_proxy import OIDCConfiguration
from fastmcp.server.auth.providers.jwt import JWTVerifier
from key_value.aio.stores.memory import MemoryStore
from starlette.applications import Starlette
from starlette.testclient import TestClient

from plane_mcp.community.auth import CommunityAuth, CommunityOIDCProxy, RequireBinding
from plane_mcp.community.portal import COOKIE, AccountPortal
from plane_mcp.community.settings import Settings
from plane_mcp.community.store import Vault, identity_key

ORIGIN = "https://planner.example.com"
ISSUER = "https://login.example.com/application/o/plane/"
PAT = "plane_api_" + "a" * 32
SETTINGS = Settings(
    origin=ORIGIN,
    discovery_url=ISSUER + ".well-known/openid-configuration",
    client_id="plane-client",
    client_secret="secret-for-tests-only",
    encryption_key=Fernet.generate_key().decode(),
    signing_key="test-signing-key-" * 4,
    redis_url="redis://localhost:6379/0",
    workspace="openmarkets",
)
OIDC = OIDCConfiguration(
    issuer=ISSUER,
    authorization_endpoint=ISSUER + "authorize/",
    token_endpoint=ISSUER + "token/",
    jwks_uri=ISSUER + "jwks/",
    response_types_supported=["code"],
    subject_types_supported=["public"],
    id_token_signing_alg_values_supported=["RS256"],
)


def run(coro):
    return asyncio.run(coro)


def make_vault():
    return Vault(FakeRedis(), SETTINGS.encryption_key)


def token(user="one", issuer=ISSUER):
    return AccessToken(
        token="oauth-jwt-" + user,
        client_id="client",
        scopes=["openid"],
        expires_at=int(time.time()) + 600,
        claims={"iss": issuer, "sub": user},
    )


def test_vault_encrypts_pats_and_consumes_state_atomically():
    async def scenario():
        vault = make_vault()
        await vault.put("binding", "one", {"pat": PAT, "user_id": "1"})
        raw = await vault.redis.get("community:binding:one")
        assert PAT.encode() not in raw
        assert (await vault.get("binding", "one"))["pat"] == PAT
        await vault.put("login", "nonce", {"verifier": "secret"}, 600)
        assert 0 < await vault.redis.ttl("community:login:nonce") <= 600
        results = await asyncio.gather(*(vault.get("login", "nonce", consume=True) for _ in range(5)))
        assert sum(item is not None for item in results) == 1
        await vault.delete("binding", "one")
        assert await vault.get("binding", "one") is None

    run(scenario())


def test_identity_keys_include_issuer_and_subject():
    assert identity_key({"iss": "a", "sub": "bc"}) != identity_key({"iss": "ab", "sub": "c"})
    assert identity_key({"iss": "a", "sub": "u"}) != identity_key({"iss": "b", "sub": "u"})
    with pytest.raises(ValueError):
        identity_key({"sub": "u"})


def test_oauth_bindings_are_isolated_and_do_not_change_issued_tokens():
    async def scenario():
        vault = make_vault()
        one, two = token("one"), token("two")
        provider = TokenVerifier()
        provider.verify_token = AsyncMock(side_effect=lambda raw: {"one": one, "two": two}.get(raw))
        auth = CommunityAuth(server=provider, vault=vault, workspace="openmarkets")
        await vault.put("binding", identity_key(one.claims), {"pat": PAT, "user_id": "plane-one"})
        first, second = await asyncio.gather(auth.verify_token("one"), auth.verify_token("two"))
        assert first.token == PAT and first.claims["plane_user_id"] == "plane-one"
        assert second.token == "" and second.claims["auth_method"] == "community_unlinked"
        assert one.token == "oauth-jwt-one" and "community_subject" not in one.claims
        from plane_mcp.client import get_plane_client_context

        with (
            patch("plane_mcp.client.get_access_token", return_value=first),
            patch("plane_mcp.client.PlaneClient") as sdk,
        ):
            get_plane_client_context()
            assert sdk.call_args.kwargs["api_key"] == PAT
            assert "access_token" not in sdk.call_args.kwargs
        await vault.delete("binding", identity_key(one.claims))
        assert (await auth.verify_token("one")).claims["auth_method"] == "community_unlinked"

    run(scenario())


def test_unbound_user_cannot_call_plane_tools():
    async def scenario():
        unbound = token().model_copy(update={"claims": {"auth_method": "community_unlinked"}})
        next_call = AsyncMock(return_value="called")
        with patch("plane_mcp.community.auth.get_access_token", return_value=unbound):
            ctx = SimpleNamespace(message=SimpleNamespace(name="project"))
            await RequireBinding().on_call_tool(ctx, next_call)
            next_call.assert_not_awaited()
            ctx.message.name = "identity"
            assert await RequireBinding().on_call_tool(ctx, next_call) == "called"

    run(scenario())


def test_jwt_verification_rejects_wrong_audience_issuer_and_expiration():
    async def scenario():
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = (
            private.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )
        verifier = JWTVerifier(public_key=public, issuer=ISSUER, audience=SETTINGS.client_id, algorithm="RS256")
        claims = {"iss": ISSUER, "sub": "one", "aud": SETTINGS.client_id, "exp": int(time.time()) + 600}
        assert await verifier.verify_token(jwt.encode(claims, private, algorithm="RS256"))
        for change in [{"aud": "other"}, {"iss": "https://attacker.example"}, {"exp": 1}]:
            assert await verifier.verify_token(jwt.encode(claims | change, private, algorithm="RS256")) is None

    run(scenario())


def test_portal_login_uses_pkce_nonce_and_secure_cookie():
    portal = AccountPortal(SETTINGS, make_vault(), OIDC)
    with TestClient(Starlette(routes=portal.routes()), base_url=ORIGIN) as client:
        response = client.get("/mcp/account/login", follow_redirects=False)
        query = parse_qs(urlsplit(response.headers["location"]).query)
        assert query["code_challenge_method"] == ["S256"]
        assert query["nonce"] and query["state"] and query["code_challenge"]
        assert "HttpOnly" in response.headers["set-cookie"] and "Secure" in response.headers["set-cookie"]
        assert response.headers["cache-control"] == "no-store"
        assert client.get("/mcp/account/callback?state=wrong&code=x").status_code == 400


def test_portal_requires_login_and_rejects_csrf_without_storing_pat():
    vault = make_vault()
    portal = AccountPortal(SETTINGS, vault, OIDC)
    run(vault.put("session", "session-id", {"subject": "one", "csrf": "csrf-secret"}, 600))
    with TestClient(Starlette(routes=portal.routes()), base_url=ORIGIN) as client:
        assert client.get("/mcp/account", follow_redirects=False).status_code == 303
        client.cookies.set(COOKIE, "session-id", domain="planner.example.com", path="/mcp/account")
        response = client.post("/mcp/account", data={"pat": PAT, "csrf": "csrf-secret"})
        assert response.status_code == 403
        response = client.post("/mcp/account", data={"pat": PAT, "csrf": "wrong"}, headers={"Origin": ORIGIN})
        assert response.status_code == 403
        portal.validate_pat = AsyncMock(return_value={"pat": PAT, "user_id": "one", "email": "user@example.com"})
        response = client.post("/mcp/account", data={"pat": PAT, "csrf": "csrf-secret"}, headers={"Origin": ORIGIN})
        assert response.status_code == 200 and "Conta conectada" in response.text
        assert PAT not in response.text
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        response = client.post(
            "/mcp/account", data={"action": "disconnect", "csrf": "csrf-secret"}, headers={"Origin": ORIGIN}
        )
        assert "desvinculada" in response.text


def test_portal_callback_nonce_and_replay_checks():
    vault = make_vault()
    portal = AccountPortal(SETTINGS, vault, OIDC)
    run(vault.put("login", "state", {"nonce": "expected", "verifier": "verifier"}, 600))
    oauth = AsyncMock()
    oauth.__aenter__.return_value = oauth
    oauth.fetch_token.return_value = {"id_token": "signed-token"}
    portal.oauth_client = lambda: oauth
    portal.verifier.verify_token = AsyncMock(return_value=token().model_copy(update={"claims": {"nonce": "wrong"}}))
    with TestClient(Starlette(routes=portal.routes()), base_url=ORIGIN) as client:
        client.cookies.set(COOKIE, "state", domain="planner.example.com", path="/mcp/account")
        assert client.get("/mcp/account/callback?state=state&code=code").status_code == 400
        assert client.get("/mcp/account/callback?state=state&code=code").status_code == 400
        assert oauth.fetch_token.await_count == 1


def test_discovery_pkce_and_legacy_pat_auth_share_one_endpoint(monkeypatch):
    from plane_mcp.community.__main__ import build_app

    monkeypatch.setattr("plane_mcp.community.__main__.build_token_store", lambda: MemoryStore())
    monkeypatch.setattr("plane_mcp.community.__main__.Redis.from_url", lambda *a, **kw: FakeRedis())
    with patch("fastmcp.server.auth.oidc_proxy.OIDCProxy.get_oidc_configuration", return_value=OIDC):
        app = build_app(SETTINGS)
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
    }
    headers = {"Accept": "application/json, text/event-stream"}
    with TestClient(app, base_url=ORIGIN) as client:
        metadata = client.get("/.well-known/oauth-authorization-server").json()
        assert metadata["code_challenge_methods_supported"] == ["S256"]
        assert metadata["authorization_endpoint"] == ORIGIN + "/authorize"
        resource = client.get("/.well-known/oauth-protected-resource/mcp").json()
        assert resource["resource"] == ORIGIN + "/mcp"
        assert client.post("/mcp", json=initialize, headers=headers).status_code == 401
        registration = client.post(
            "/register",
            json={
                "redirect_uris": ["http://127.0.0.1:8765/callback"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
            },
        )
        assert registration.status_code == 201
        response = client.get(
            "/authorize",
            params={
                "client_id": registration.json()["client_id"],
                "response_type": "code",
                "redirect_uri": "http://127.0.0.1:8765/callback",
                "state": "abc",
            },
            follow_redirects=False,
        )
        assert response.status_code == 302
        error = parse_qs(urlsplit(response.headers["location"]).query)
        assert error["error"] == ["invalid_request"]
        assert "code_challenge" in error["error_description"][0]
        with patch(
            "plane_mcp.auth.plane_header_auth_provider.PlaneHeaderAuthProvider._validate_api_key",
            new=AsyncMock(side_effect=lambda pat: pat == PAT),
        ) as verify:
            for value in [PAT, "Bearer " + PAT]:
                response = client.post("/mcp", json=initialize, headers=headers | {"Authorization": value})
                assert response.status_code == 200, response.text
            before = verify.await_count
            assert (
                client.post("/mcp", json=initialize, headers=headers | {"Authorization": "Bearer bad-jwt"}).status_code
                == 401
            )
            assert verify.await_count == before
        response = client.post(
            "/mcp", json=initialize, headers=[*headers.items(), ("Authorization", PAT), ("Authorization", PAT)]
        )
        assert response.status_code == 400


def test_settings_reject_shared_credentials(monkeypatch):
    monkeypatch.setenv("PLANE_API_KEY", PAT)
    with pytest.raises(ValueError, match="Shared"):
        Settings.from_env()


def test_declining_oauth_does_not_permanently_block_the_client():
    with patch("fastmcp.server.auth.oidc_proxy.OIDCProxy.get_oidc_configuration", return_value=OIDC):
        provider = CommunityOIDCProxy(
            config_url=SETTINGS.discovery_url,
            client_id=SETTINGS.client_id,
            client_secret=SETTINGS.client_secret,
            base_url=ORIGIN,
            client_storage=MemoryStore(),
        )
    request = SimpleNamespace(cookies={})
    assert provider._decode_list_cookie(request, "MCP_DENIED_CLIENTS") == []
