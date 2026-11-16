"""Keep direct PAT clients and the official per-request Plane context unchanged."""

import os
import re

import httpx

from plane_mcp.auth.plane_header_auth_provider import PlaneHeaderAuthProvider

PAT_PATTERN = re.compile(r"plane_api_[0-9a-f]{32}")


async def validate_pat(pat, workspace):
    if not PAT_PATTERN.fullmatch(pat):
        return None
    base = (os.getenv("PLANE_INTERNAL_BASE_URL") or os.environ["PLANE_BASE_URL"]).rstrip("/")
    async with httpx.AsyncClient(timeout=10, trust_env=False, follow_redirects=False) as client:
        me = await client.get(base + "/api/v1/users/me/", headers={"X-Api-Key": pat})
        if me.status_code != 200 or not me.json().get("id"):
            return None
        access = await client.get(base + f"/api/v1/workspaces/{workspace}/projects/", headers={"X-Api-Key": pat})
        if access.status_code != 200:
            return None
    return {"pat": pat, "user_id": str(me.json()["id"]), "email": str(me.json().get("email", ""))}


class PersonalTokenVerifier(PlaneHeaderAuthProvider):
    async def verify_token(self, token):
        if not PAT_PATTERN.fullmatch(token):
            return None
        return await super().verify_token(token)


class AuthGuard:
    """Small global abuse budgets for auth routes; MCP calls are unaffected."""

    LIMITS = {
        "/register": (60, 3600),
        "/authorize": (120, 60),
        "/mcp/authorize": (120, 60),
        "/token": (300, 60),
        "/revoke": (300, 60),
    }

    def __init__(self, app, redis):
        self.app, self.redis = app, redis

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"] in self.LIMITS:
            from starlette.responses import Response

            limit, seconds = self.LIMITS[scope["path"]]
            async with self.redis.pipeline() as pipe:
                key = "community-direct:rate:" + scope["path"]
                pipe.incr(key)
                pipe.expire(key, seconds, nx=True)
                count, _ = await pipe.execute()
            if count > limit:
                return await Response(status_code=429, headers={"Retry-After": str(seconds)})(scope, receive, send)
            body = b""
            while True:
                chunk = await receive()
                if chunk["type"] == "http.disconnect":
                    return
                body += chunk.get("body", b"")
                if len(body) > 32768:
                    return await Response(status_code=413)(scope, receive, send)
                if not chunk.get("more_body", False):
                    break
            original_receive = receive
            sent = False

            async def buffered_receive():
                nonlocal sent
                if not sent:
                    sent = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await original_receive()

            receive = buffered_receive
        await self.app(scope, receive, send)


class LegacyHeaders:
    def __init__(self, app, workspace):
        self.app, self.workspace = app, workspace

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"] == "/mcp":
            headers = list(scope["headers"])
            auth = [v for k, v in headers if k.lower() == b"authorization"]
            if len(auth) > 1:
                from starlette.responses import Response

                return await Response(status_code=400)(scope, receive, send)
            if auth and PAT_PATTERN.fullmatch(auth[0].decode("latin1").strip()):
                headers = [(k, b"Bearer " + v.strip() if k.lower() == b"authorization" else v) for k, v in headers]
            if not any(k.lower() == b"x-workspace-slug" for k, _ in headers):
                headers.append((b"x-workspace-slug", self.workspace.encode()))
            scope = {**scope, "headers": headers}
        await self.app(scope, receive, send)
