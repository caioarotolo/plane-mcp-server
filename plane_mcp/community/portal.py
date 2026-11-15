"""Small authenticated web page for linking a PAT without exposing it to an LLM."""

import secrets
from html import escape

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.oauth2.rfc6749 import OAuth2Error
from fastmcp.server.auth.providers.jwt import JWTVerifier
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

from plane_mcp.community.auth import PAT_PATTERN
from plane_mcp.community.settings import Settings
from plane_mcp.community.store import Vault, identity_key

COOKIE = "__Secure-plane-mcp-account"
COOKIE_PATH = "/mcp/account"
SESSION_TTL = 600
HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
    ),
}


def page(body: str, status: int = 200):
    return HTMLResponse(
        '<!doctype html><html lang="pt-BR"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width"><title>Conectar Plane</title>'
        "<style>body{font:16px system-ui;max-width:560px;margin:64px auto;padding:20px}"
        "input,button{font:inherit;padding:10px;margin:8px 0}input{width:95%}</style>"
        f"<h1>Conectar sua conta do Plane</h1>{body}</html>",
        status_code=status,
        headers=HEADERS,
    )


class AccountPortal:
    def __init__(self, settings: Settings, vault: Vault, oidc):
        self.settings, self.vault, self.oidc = settings, vault, oidc
        self.callback_url = settings.origin + COOKIE_PATH + "/callback"
        self.verifier = JWTVerifier(
            jwks_uri=str(oidc.jwks_uri), issuer=str(oidc.issuer), audience=settings.client_id, algorithm="RS256"
        )

    def oauth_client(self):
        return AsyncOAuth2Client(
            self.settings.client_id,
            self.settings.client_secret,
            redirect_uri=self.callback_url,
            scope="openid profile email",
            code_challenge_method="S256",
            token_endpoint_auth_method="client_secret_post",
            timeout=10,
            trust_env=False,
        )

    async def login(self, request):
        state, verifier, nonce = (secrets.token_urlsafe(32) for _ in range(3))
        await self.vault.put("login", state, {"verifier": verifier, "nonce": nonce}, SESSION_TTL)
        async with self.oauth_client() as client:
            url, _ = client.create_authorization_url(
                str(self.oidc.authorization_endpoint), state=state, code_verifier=verifier, nonce=nonce
            )
        response = RedirectResponse(url, status_code=303, headers=HEADERS)
        response.set_cookie(
            COOKIE, state, max_age=SESSION_TTL, path=COOKIE_PATH, secure=True, httponly=True, samesite="lax"
        )
        return response

    async def callback(self, request):
        state = request.query_params.get("state", "")
        cookie = request.cookies.get(COOKIE, "")
        if not state or not cookie or not secrets.compare_digest(state, cookie):
            return page("<p>Login inválido. Inicie novamente.</p>", 400)
        flow = await self.vault.get("login", state, consume=True)
        if not flow or not request.query_params.get("code"):
            return page("<p>Login expirado ou recusado. Inicie novamente.</p>", 400)
        try:
            async with self.oauth_client() as client:
                tokens = await client.fetch_token(
                    str(self.oidc.token_endpoint), code=request.query_params["code"], code_verifier=flow["verifier"]
                )
            verified = await self.verifier.verify_token(tokens.get("id_token", ""))
            if not verified or not secrets.compare_digest(str(verified.claims.get("nonce", "")), flow["nonce"]):
                return page("<p>Não foi possível verificar sua identidade.</p>", 400)
            subject = identity_key(verified.claims)
        except (httpx.HTTPError, OAuth2Error, ValueError):
            return page("<p>Não foi possível concluir o login. Tente novamente.</p>", 400)
        session = secrets.token_urlsafe(32)
        await self.vault.put("session", session, {"subject": subject, "csrf": secrets.token_urlsafe(32)}, SESSION_TTL)
        response = RedirectResponse(COOKIE_PATH, status_code=303, headers=HEADERS)
        response.set_cookie(
            COOKIE, session, max_age=SESSION_TTL, path=COOKIE_PATH, secure=True, httponly=True, samesite="lax"
        )
        return response

    async def validate_pat(self, pat: str):
        if not PAT_PATTERN.fullmatch(pat):
            return None
        import os

        base = (os.getenv("PLANE_INTERNAL_BASE_URL") or os.environ["PLANE_BASE_URL"]).rstrip("/")
        async with httpx.AsyncClient(timeout=10, trust_env=False, follow_redirects=False) as client:
            me = await client.get(base + "/api/v1/users/me/", headers={"X-Api-Key": pat})
            if me.status_code != 200:
                return None
            user = me.json()
            if not user.get("id"):
                return None
            # Linking requires real access to this workspace, not merely a valid PAT.
            access = await client.get(
                base + f"/api/v1/workspaces/{self.settings.workspace}/projects/", headers={"X-Api-Key": pat}
            )
            if access.status_code != 200:
                return None
        return {"pat": pat, "user_id": str(user["id"]), "email": str(user.get("email", ""))}

    async def account(self, request):
        session = await self.vault.get("session", request.cookies.get(COOKIE, ""))
        if not session:
            return RedirectResponse(COOKIE_PATH + "/login", status_code=303, headers=HEADERS)
        message = ""
        if request.method == "POST":
            if request.headers.get("origin") != self.settings.origin:
                return page("<p>Origem inválida.</p>", 403)
            form = await request.form(max_fields=3, max_files=0, max_part_size=4096)
            if not secrets.compare_digest(str(form.get("csrf", "")), session["csrf"]):
                return page("<p>Sessão inválida.</p>", 403)
            if form.get("action") == "disconnect":
                await self.vault.delete("binding", session["subject"])
                message = "<p>Conta desvinculada. O acesso OAuth ao Plane foi interrompido.</p>"
            else:
                try:
                    binding = await self.validate_pat(str(form.get("pat", "")).strip())
                except (httpx.HTTPError, ValueError):
                    binding = None
                if binding:
                    await self.vault.put("binding", session["subject"], binding)
                    message = "<p>Conta conectada. Você já pode voltar ao Claude ou Codex.</p>"
                else:
                    message = "<p>Token inválido ou sem acesso ao workspace. Confira o token e tente novamente.</p>"
        binding = await self.vault.get("binding", session["subject"])
        csrf = escape(session["csrf"])
        connected = f"<p>Conta vinculada: <strong>{escape(binding['email'])}</strong></p>" if binding else ""
        return page(
            message + connected + "<p>Gere seu token nas configurações de API do Plane e cole abaixo.</p>"
            "<p>O token fica protegido no servidor e não é enviado à conversa.</p>"
            f'<form method="post"><input type="hidden" name="csrf" value="{csrf}">'
            '<label for="pat">Token pessoal do Plane</label>'
            '<input id="pat" name="pat" type="password" autocomplete="off" required maxlength="128">'
            '<button type="submit">Conectar conta</button></form>'
            f'<form method="post"><input type="hidden" name="csrf" value="{csrf}">'
            '<input type="hidden" name="action" value="disconnect"><button>Desvincular conta</button></form>'
        )

    def routes(self):
        return [
            Route(COOKIE_PATH, self.account, methods=["GET", "POST"]),
            Route(COOKIE_PATH + "/login", self.login),
            Route(COOKIE_PATH + "/callback", self.callback),
        ]
