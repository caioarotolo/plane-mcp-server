"""Exercise the real SDK OAuth handlers and the adapter's security boundaries."""

import asyncio
import base64
import hashlib
import json
import re
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import httpx
import pytest
from cryptography.fernet import Fernet
from fakeredis.aioredis import FakeRedis
from fastmcp.server.dependencies import get_access_token
from starlette.requests import Request
from starlette.testclient import TestClient

from plane_mcp.community.auth import validate_pat
from plane_mcp.community.oauth import DirectOAuth
from plane_mcp.community.session import create_credential, session_identity
from plane_mcp.community.settings import Settings
from plane_mcp.community.store import Vault

ORIGIN = "https://planner.example.com"
CALLBACK = "http://127.0.0.1:8765/callback"
PATS = ["plane_api_" + "a" * 32, "plane_api_" + "b" * 32]
SETTINGS = Settings(ORIGIN, Fernet.generate_key().decode(), "redis://localhost", "openmarkets")


@pytest.fixture
def env(monkeypatch):
    from plane_mcp.community import __main__ as entry

    redis = FakeRedis()
    vault = Vault(redis, SETTINGS.encryption_key)
    provider = DirectOAuth(SETTINGS, vault)
    users = {pat: {"pat": pat, "user_id": str(i), "email": f"user{i}@example.invalid"} for i, pat in enumerate(PATS)}
    check = AsyncMock(side_effect=lambda pat, workspace: users.get(pat))

    async def who(request, settings):
        user = users.get(request.cookies.get("session-id"))
        return {k: v for k, v in user.items() if k != "pat"} if user else None

    async def mint(request, settings, identity, name, expires):
        return users[request.cookies["session-id"]]

    monkeypatch.setattr("plane_mcp.community.portal.session_identity", who)
    monkeypatch.setattr("plane_mcp.community.portal.create_credential", AsyncMock(side_effect=mint))
    monkeypatch.setattr("plane_mcp.community.oauth.validate_pat", check)
    monkeypatch.setattr(entry.Redis, "from_url", lambda *a, **kw: redis)
    monkeypatch.setattr(entry, "DirectOAuth", lambda *a: provider)
    monkeypatch.setattr(
        "plane_mcp.auth.plane_header_auth_provider.PlaneHeaderAuthProvider._validate_api_key",
        AsyncMock(side_effect=lambda pat: pat in users),
    )
    original = entry.get_header_mcp

    def factory():
        server = original()

        @server.tool
        def probe():
            token = get_access_token()
            assert token.token == PATS[int(token.claims["plane_user_id"])]
            return {"user": token.claims["plane_user_id"], "workspace": token.claims["workspace_slug"]}

        return server

    monkeypatch.setattr(entry, "get_header_mcp", factory)
    app = entry.build_app(SETTINGS)
    with TestClient(app, base_url=ORIGIN) as client:
        client.cookies.set("session-id", PATS[0])
        yield client, provider, users, app


def register(client, **extra):
    r = client.post(
        "/register",
        json={
            "client_name": "Test client",
            "redirect_uris": [CALLBACK],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            **extra,
        },
    )
    assert r.status_code == 201, r.text
    return r.json()


def begin(client, registration, **changes):
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    params = {
        "client_id": registration["client_id"],
        "response_type": "code",
        "redirect_uri": CALLBACK,
        "scope": "plane",
        "state": "client-state",
        "resource": SETTINGS.resource,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        **changes,
    }
    r = client.get("/authorize", params=params, follow_redirects=False)
    return r, verifier


def consent(client, registration, pat=PATS[0]):
    client.cookies.set("session-id", pat)
    r, verifier = begin(client, registration)
    assert r.status_code == 302
    url = r.headers["location"]
    page = client.get(url)
    csrf = re.search('name="csrf" value="([^"]+)"', page.text).group(1)
    r = client.post(url, data={"csrf": csrf, "action": "allow"}, headers={"Origin": ORIGIN}, follow_redirects=False)
    assert r.status_code == 303, r.text
    assert pat not in r.text and pat not in r.headers["location"]
    query = parse_qs(urlsplit(r.headers["location"]).query)
    assert query["state"] == ["client-state"]
    return {
        "grant_type": "authorization_code",
        "client_id": registration["client_id"],
        "code": query["code"][0],
        "code_verifier": verifier,
        "redirect_uri": CALLBACK,
        "resource": SETTINGS.resource,
    }


def tokens(client, registration, pat=PATS[0]):
    r = client.post("/token", data=consent(client, registration, pat))
    assert r.status_code == 200, r.text
    return r.json()


def refresh(client, registration, token, **extra):
    return client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": registration["client_id"],
            "refresh_token": token,
            "resource": SETTINGS.resource,
            **extra,
        },
    )


def rpc(client, token, method="tools/call", params=None, **headers):
    if params is None:
        params = {"name": "probe", "arguments": {}}
    r = client.post(
        "/mcp",
        headers={"Authorization": "Bearer " + token, "Accept": "application/json, text/event-stream", **headers},
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
    )
    return r


def result(response):
    assert response.status_code == 200, response.text
    raw = (
        response.json()
        if "application/json" in response.headers["content-type"]
        else json.loads(next(x[5:].strip() for x in response.text.splitlines() if x.startswith("data:")))
    )
    return raw["result"]["structuredContent"]


def test_discovery_redirects_pkce_and_resource_restrictions(env):
    c, p, _, _ = env
    meta = c.get("/.well-known/oauth-authorization-server").json()
    assert meta["code_challenge_methods_supported"] == ["S256"] and meta["client_id_metadata_document_supported"]
    assert "none" in meta["token_endpoint_auth_methods_supported"]
    assert c.get("/.well-known/oauth-protected-resource/mcp").json()["resource"] == SETTINGS.resource
    for uri in ["https://attacker.invalid/callback", "http://localhost@attacker.invalid/callback"]:
        assert c.post("/register", json={"redirect_uris": [uri]}).status_code == 400
    reg = register(c)
    for changes in [
        {"code_challenge": None},
        {"code_challenge_method": "plain"},
        {"resource": "https://attacker.invalid/mcp"},
        {"redirect_uri": "https://attacker.invalid/callback"},
    ]:
        r, _ = begin(c, reg, **changes)
        assert r.status_code == 400 or "error=" in r.headers.get("location", "")
    form = consent(c, reg)
    assert c.post("/token", data=form | {"code_verifier": "wrong"}).status_code == 401
    assert c.post("/token", data=form | {"resource": "https://other.invalid/mcp"}).status_code == 400
    assert c.post("/token", data=form | {"redirect_uri": CALLBACK + "/other"}).status_code == 400
    assert c.post("/token", data=form).status_code == 200
    assert c.post("/token", data=form).status_code == 401


def test_consent_csrf_cookie_origin_and_denial(env):
    c, _, _, _ = env
    reg = register(c)
    r, _ = begin(c, reg)
    url = r.headers["location"]
    page = c.get(url)
    assert "Secure" in page.headers["set-cookie"] and "HttpOnly" in page.headers["set-cookie"]
    assert (
        page.headers["cache-control"] == "no-store"
        and "frame-ancestors 'none'" in page.headers["content-security-policy"]
    )
    csrf = re.search('name="csrf" value="([^"]+)"', page.text).group(1)
    for headers, body in [
        ({"Origin": "https://other.invalid"}, {"csrf": csrf}),
        ({"Origin": ORIGIN}, {"csrf": "wrong"}),
    ]:
        assert c.post(url, headers=headers, data=body | {"pat": PATS[0]}).status_code == 403
    cookies = list(c.cookies.jar)
    c.cookies.delete("__Secure-plane-mcp-consent")
    assert c.post(url, headers={"Origin": ORIGIN}, data={"csrf": csrf, "pat": PATS[0]}).status_code == 403
    for cookie in cookies:
        c.cookies.jar.set_cookie(cookie)
    c.cookies.set("session-id", PATS[1])
    assert c.post(url, headers={"Origin": ORIGIN}, data={"csrf": csrf, "action": "allow"}).status_code == 403
    c.cookies.set("session-id", PATS[0])
    denied = c.post(url, headers={"Origin": ORIGIN}, data={"csrf": csrf, "action": "deny"}, follow_redirects=False)
    assert denied.status_code == 303 and "access_denied" in denied.headers["location"]
    assert c.get(url).status_code == 400
    assert tokens(c, reg)["access_token"].startswith("pmcp_a_")


def test_concurrent_exchange_is_single_use_and_pats_stay_encrypted(env):
    c, p, _, _ = env
    reg = register(c)
    form = consent(c, reg)
    with ThreadPoolExecutor(max_workers=2) as pool:
        codes = list(pool.map(lambda _: c.post("/token", data=form).status_code, range(2)))
    assert sorted(codes) == [200, 401]

    async def inspect():
        for key in await p.vault.redis.keys("*"):
            raw = await p.vault.redis.get(key)
            assert PATS[0].encode() not in raw and form["code"].encode() not in key

    c.portal.call(inspect)


def test_oauth_users_are_isolated_and_workspace_header_cannot_override(env):
    c, _, _, _ = env
    reg = register(c)
    one = tokens(c, reg)
    two = tokens(c, reg, PATS[1])
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(
                lambda t: result(rpc(c, t, "tools/call", None, **{"X-Workspace-Slug": "evil"})),
                [one["access_token"], two["access_token"]],
            )
        )
    assert responses == [{"user": "0", "workspace": "openmarkets"}, {"user": "1", "workspace": "openmarkets"}]
    assert rpc(c, "pmcp_a_" + secrets.token_urlsafe(32)).status_code == 401


def test_refresh_rotates_and_replay_revokes_only_its_family(env):
    c, _, _, _ = env
    reg = register(c)
    one = tokens(c, reg)
    two = tokens(c, reg, PATS[1])
    renewed = refresh(c, reg, one["refresh_token"])
    assert renewed.status_code == 200
    renewed = renewed.json()
    assert renewed["refresh_token"] != one["refresh_token"]
    assert result(rpc(c, renewed["access_token"]))["user"] == "0"
    assert refresh(c, reg, one["refresh_token"]).status_code == 401
    assert rpc(c, renewed["access_token"]).status_code == 401
    assert refresh(c, reg, renewed["refresh_token"]).status_code == 401
    assert result(rpc(c, two["access_token"]))["user"] == "1"


def test_revocation_public_confidential_and_cross_client_ownership(env):
    c, _, _, _ = env
    reg = register(c)
    other = register(c)
    issued = tokens(c, reg)
    body = {"token": issued["refresh_token"], "token_type_hint": "refresh_token"}
    assert c.post("/revoke", data=body | {"client_id": other["client_id"]}).status_code == 200
    assert result(rpc(c, issued["access_token"]))["user"] == "0"
    assert c.post("/revoke", data=body | {"client_id": reg["client_id"]}).status_code == 200
    assert rpc(c, issued["access_token"]).status_code == 401
    assert refresh(c, reg, issued["refresh_token"]).status_code == 401
    confidential = register(c, token_endpoint_auth_method="client_secret_post")
    body = {"client_id": confidential["client_id"], "token": "unknown-token"}
    assert c.post("/revoke", data=body).status_code == 401
    assert c.post("/revoke", data=body | {"client_secret": "wrong"}).status_code == 401
    assert c.post("/revoke", data=body | {"client_secret": confidential["client_secret"]}).status_code == 200


def test_revoked_pat_and_expired_grant_block_refresh(env):
    c, p, users, _ = env
    reg = register(c)
    issued = tokens(c, reg)
    users.pop(PATS[0])
    assert refresh(c, reg, issued["refresh_token"]).status_code == 401
    assert rpc(c, issued["access_token"]).status_code == 401
    issued = tokens(c, reg, PATS[1])

    async def expire():
        data = await p.vault.get("access", issued["access_token"])
        grant = await p.vault.get("grant", data["grant_id"])
        grant["expires_at"] = int(time.time()) - 1
        await p.vault.put("grant", data["grant_id"], grant, 60)

    c.portal.call(expire)
    assert rpc(c, issued["access_token"]).status_code == 401
    assert refresh(c, reg, issued["refresh_token"]).status_code == 401


def test_existing_pat_clients_raw_bearer_and_duplicate_headers(env):
    c, _, _, _ = env
    init = {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "legacy", "version": "1"}}
    for auth in [PATS[0], "Bearer " + PATS[0]]:
        r = c.post(
            "/mcp",
            headers={"Authorization": auth, "Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": init},
        )
        assert r.status_code == 200
    assert c.post("/mcp", headers=[("Authorization", PATS[0]), ("Authorization", PATS[1])]).status_code == 400


def test_pat_validation_requires_user_and_workspace_access(monkeypatch):
    monkeypatch.setenv("PLANE_INTERNAL_BASE_URL", "https://plane.internal")
    original = httpx.AsyncClient
    for status in [200, 403]:

        def respond(request, status=status):
            assert request.headers["X-Api-Key"] == PATS[0]
            return (
                httpx.Response(200, json={"id": "one"})
                if request.url.path.endswith("/me/")
                else httpx.Response(status, json={})
            )

        transport = httpx.MockTransport(respond)
        monkeypatch.setattr(
            "plane_mcp.community.auth.httpx.AsyncClient",
            lambda transport=transport, **kwargs: original(transport=transport, **kwargs),
        )
        assert bool(asyncio.run(validate_pat(PATS[0], "openmarkets"))) == (status == 200)
    assert asyncio.run(validate_pat("invalid", "openmarkets")) is None


def test_replay_marking_is_atomic():
    async def scenario():
        vault = Vault(FakeRedis(), SETTINGS.encryption_key)
        await vault.put("refresh", "token", {"grant_id": "grant", "client_id": "client"}, 60)
        values = await asyncio.gather(*(vault.consume_refresh("token") for _ in range(5)))
        assert sum(v is not None for v in values) == 1
        assert (await vault.get("spent", "token"))["grant_id"] == "grant"

    asyncio.run(scenario())


def test_shared_plane_credential_is_rejected(monkeypatch):
    monkeypatch.setenv("PLANE_API_KEY", PATS[0])
    with pytest.raises(ValueError, match="Shared"):
        Settings.from_env()


def test_cimd_client_uses_the_same_pkce_consent_and_token_flow(env, monkeypatch):
    from fastmcp.server.auth.cimd import CIMDDocument

    c, provider, _, _ = env
    client_id = "https://client.example/oauth-metadata.json"
    document = CIMDDocument(
        client_id=client_id,
        client_name="Published client",
        redirect_uris=[CALLBACK],
        grant_types=["authorization_code", "refresh_token"],
    )
    monkeypatch.setattr(provider.cimd._fetcher, "fetch", AsyncMock(return_value=document))
    issued = tokens(c, {"client_id": client_id})
    assert result(rpc(c, issued["access_token"]))["user"] == "0"


def test_auth_bodies_and_registration_abuse_are_bounded(env):
    c, provider, _, _ = env
    assert c.post("/register", content=b"x" * 32769).status_code == 413
    c.portal.call(provider.vault.redis.set, "community-direct:rate:/register", 60)
    assert c.post("/register", json={}).status_code == 429


def test_expired_codes_and_other_clients_cannot_redeem_authorization(env):
    c, provider, _, _ = env
    reg, other = register(c), register(c)
    form = consent(c, reg)
    assert c.post("/token", data=form | {"client_id": other["client_id"]}).status_code == 401

    async def expire():
        data = await provider.vault.get("code", form["code"])
        data["expires_at"] = time.time() - 1
        await provider.vault.put("code", form["code"], data, 60)

    c.portal.call(expire)
    assert c.post("/token", data=form).status_code == 401


@pytest.fixture
def anyio_backend():
    return "asyncio"


def request():
    return Request(
        {
            "type": "http",
            "headers": [
                (b"cookie", b"session-id=browser-session; csrftoken=csrf; other=do-not-forward"),
                (b"authorization", b"Bearer do-not-forward"),
                (b"host", b"attacker.invalid"),
            ],
        }
    )


@pytest.mark.anyio
async def test_session_uses_only_trusted_backend_and_owned_expiring_credential(monkeypatch):
    calls = []
    expiry = int(time.time()) + 600

    def handler(req):
        calls.append(req)
        assert req.url.host == "plane-internal" and req.headers["host"] == "planner.example.com"
        assert req.headers["origin"] == ORIGIN and req.headers["x-csrftoken"] == "csrf"
        assert "authorization" not in req.headers and "do-not-forward" not in str(req.headers)
        if req.url.path == "/api/users/me/":
            return httpx.Response(200, json={"id": "user-1", "email": "test@example.invalid"})
        if req.url.path == "/api/users/me/workspaces/":
            return httpx.Response(200, json=[{"slug": "openmarkets"}])
        assert req.method == "POST" and req.url.path == "/api/users/api-tokens/"
        body = json.loads(req.content)
        assert body["label"] == "MCP OAuth · Claude" and "user" not in body
        assert datetime.fromisoformat(body["expired_at"]).timestamp() == expiry
        return httpx.Response(201, json={"id": str(uuid4()), "user": "user-1", "token": PATS[0], **body})

    factory = httpx.AsyncClient
    monkeypatch.setenv("PLANE_INTERNAL_BASE_URL", "http://plane-internal")
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: factory(transport=httpx.MockTransport(handler), **kw))
    identity = await session_identity(request(), SETTINGS)
    assert identity == {"user_id": "user-1", "email": "test@example.invalid"}
    monkeypatch.setattr("plane_mcp.community.session.validate_pat", AsyncMock(return_value=identity | {"pat": PATS[0]}))
    assert await create_credential(request(), SETTINGS, identity, "Claude", expiry) == identity | {"pat": PATS[0]}
    assert len(calls) == 3


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["expired_at", "user", "validation"])
async def test_bad_generated_credential_is_removed(monkeypatch, failure):
    expiry, token_id = int(time.time()) + 600, str(uuid4())
    deleted = []

    def handler(req):
        if req.method == "DELETE":
            assert req.url.path == f"/api/users/api-tokens/{token_id}/"
            deleted.append(True)
            return httpx.Response(204)
        data = {
            "id": token_id,
            "user": "user-1",
            "token": PATS[0],
            "expired_at": datetime.fromtimestamp(expiry, timezone.utc).isoformat(),
        }
        if failure != "validation":
            data[failure] = None if failure == "expired_at" else "another-user"
        return httpx.Response(201, json=data)

    factory = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: factory(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr("plane_mcp.community.session.validate_pat", AsyncMock(return_value=None))
    with pytest.raises((TypeError, ValueError)):
        await create_credential(request(), SETTINGS, {"user_id": "user-1"}, "Claude", expiry)
    assert deleted == [True]


def test_login_redirect_expired_session_and_no_token_field(env, monkeypatch):
    c, _, _, _ = env
    mint = AsyncMock()
    monkeypatch.setattr("plane_mcp.community.portal.create_credential", mint)
    reg = register(c)
    r, _ = begin(c, reg)
    url = r.headers["location"]
    c.cookies.clear()
    r = c.get(url, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith(ORIGIN + "/?next_path=%2Fmcp%2Fauthorize")
    assert c.post(url, data={"action": "allow"}, headers={"Origin": ORIGIN}).status_code == 401
    c.cookies.set("session-id", PATS[0])
    page = c.get(url)
    assert page.status_code == 200 and 'name="pat"' not in page.text
    assert "user0@example.invalid" in page.text and "Autorizar" in page.text
    mint.assert_not_called()


def test_no_workspace_access_blocks_consent(env, monkeypatch):
    c, _, _, _ = env
    monkeypatch.setattr("plane_mcp.community.portal.session_identity", AsyncMock(side_effect=PermissionError))
    r, _ = begin(c, register(c))
    assert c.get(r.headers["location"]).status_code == 403
