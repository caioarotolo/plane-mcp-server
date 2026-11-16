"""Use Plane's existing browser login; never persist its session or password."""

import os
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from plane_mcp.community.auth import PAT_PATTERN, validate_pat


def plane_session(request, settings):
    # Forward only Plane's own cookies, only to the configured trusted backend.
    # No client-supplied host, URL, Authorization or workspace is forwarded.
    base = (os.getenv("PLANE_INTERNAL_BASE_URL") or settings.origin).rstrip("/")
    cookies = {name: request.cookies[name] for name in ("session-id", "csrftoken") if name in request.cookies}
    headers = {"Origin": settings.origin, "Referer": settings.origin + "/", "Host": urlsplit(settings.origin).netloc}
    if "csrftoken" in cookies:
        headers["X-CSRFToken"] = cookies["csrftoken"]
    return httpx.AsyncClient(
        base_url=base, cookies=cookies, headers=headers, timeout=10, trust_env=False, follow_redirects=False
    )


async def session_identity(request, settings):
    if not request.cookies.get("session-id"):
        return None
    async with plane_session(request, settings) as client:
        me = await client.get("/api/users/me/")
        if me.status_code in (401, 403):
            return None
        me.raise_for_status()
        user = me.json()
        if not user.get("id"):
            return None
        workspaces = await client.get("/api/users/me/workspaces/")
        workspaces.raise_for_status()
        if not any(w.get("slug") == settings.workspace for w in workspaces.json()):
            raise PermissionError("No access to configured workspace")
    return {"user_id": str(user["id"]), "email": str(user.get("email", ""))}


async def create_credential(request, settings, identity, client_name, expires_at):
    """Create one expiring token only after explicit, session-bound consent."""
    async with plane_session(request, settings) as client:
        response = await client.post(
            "/api/users/api-tokens/",
            json={
                "label": ("MCP OAuth · " + client_name)[:255],
                "description": "Created after OAuth consent. Revoke here to disconnect this MCP authorization.",
                "expired_at": datetime.fromtimestamp(expires_at, timezone.utc).isoformat(),
            },
        )
        response.raise_for_status()
        record = response.json()
        try:
            # Fail closed if a Plane upgrade changes token ownership or expiry semantics.
            if not isinstance(record.get("expired_at"), str):
                raise ValueError("Missing token expiry")
            expiry = datetime.fromisoformat(record["expired_at"].replace("Z", "+00:00")).timestamp()
            if str(record["user"]) != identity["user_id"] or abs(expiry - expires_at) > 1:
                raise ValueError("Unexpected token owner or expiry")
            if not PAT_PATTERN.fullmatch(record["token"]):
                raise ValueError("Unexpected Plane token format")
            checked = await validate_pat(record["token"], settings.workspace)
            if not checked or checked["user_id"] != identity["user_id"]:
                raise ValueError("Plane credential validation failed")
            return checked
        except (KeyError, TypeError, ValueError, httpx.HTTPError):
            # This request still has the session; remove an unusable generated token.
            from uuid import UUID

            token_id = str(UUID(str(record["id"])))
            await client.delete("/api/users/api-tokens/" + token_id + "/")
            raise
