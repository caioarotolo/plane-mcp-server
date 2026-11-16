"""One consent form: validate a Plane PAT, then return a single-use OAuth code."""

import secrets
import time
from html import escape

import httpx
from mcp.server.auth.provider import construct_redirect_uri
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

from plane_mcp.community.auth import validate_pat
from plane_mcp.community.oauth import GRANT_TTL
from plane_mcp.community.store import digest

COOKIE = "__Secure-plane-mcp-consent"
PATH = "/mcp/authorize"
HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
}
# No form-action: browsers apply it to the final external OAuth callback as well.
# The form posts to this fixed path; every redirect is validated before consent.


def page(body, status=200):
    return HTMLResponse(
        '<!doctype html><html lang="pt-BR"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width"><title>Autorizar Plane MCP</title>'
        "<style>body{font:16px system-ui;max-width:580px;margin:64px auto;padding:20px}"
        "input,button{font:inherit;padding:10px;margin:8px 0}input{width:95%}code{overflow-wrap:anywhere}</style>"
        "<h1>Conectar ao Plane</h1>" + body + "</html>",
        status_code=status,
        headers=HEADERS,
    )


class ConsentPage:
    def __init__(self, provider):
        self.provider, self.vault, self.settings = provider, provider.vault, provider.settings

    async def help(self, request):
        return page(
            "<p>No Claude ou Codex, adicione <code>"
            + escape(self.settings.resource)
            + "</code> com OAuth e inicie a conexão. A autorização abrirá aqui.</p>"
            "<p>Você só precisa do seu token pessoal do Plane. Não há outra conta nem outra senha.</p>"
        )

    async def consent(self, request):
        flow_id = request.query_params.get("request", "")
        flow = await self.vault.get("flow", flow_id)
        if not flow:
            return page("<p>Autorização expirada. Inicie novamente pelo seu cliente MCP.</p>", 400)
        message = ""
        if request.method == "GET":
            csrf = secrets.token_urlsafe(32)
            flow["csrf_hash"] = digest(csrf)
            await self.vault.put("flow", flow_id, flow, 300)
        else:
            if request.headers.get("origin") != self.settings.origin:
                return page("<p>Origem inválida.</p>", 403)
            form = await request.form(max_files=0, max_fields=3, max_part_size=4096)
            csrf = str(form.get("csrf", ""))
            cookie = request.cookies.get(COOKIE, "")
            if (
                not csrf
                or not cookie
                or not secrets.compare_digest(csrf, cookie)
                or not secrets.compare_digest(digest(csrf), flow.get("csrf_hash", ""))
            ):
                return page("<p>Sessão inválida. Inicie novamente pelo seu cliente MCP.</p>", 403)
            params = flow["params"]
            if form.get("action") == "deny":
                if not await self.vault.get("flow", flow_id, consume=True):
                    return page("<p>Autorização já utilizada.</p>", 400)
                return RedirectResponse(
                    construct_redirect_uri(params["redirect_uri"], error="access_denied", state=params.get("state")),
                    status_code=303,
                    headers=HEADERS,
                )
            try:
                identity = await validate_pat(str(form.get("pat", "")).strip(), self.settings.workspace)
            except (httpx.HTTPError, ValueError):
                identity = None
            if identity:
                consumed = await self.vault.get("flow", flow_id, consume=True)
                if not consumed or consumed.get("csrf_hash") != flow.get("csrf_hash"):
                    return page("<p>Autorização já utilizada ou expirada.</p>", 400)
                grant_id, code = secrets.token_urlsafe(32), "pmcp_c_" + secrets.token_urlsafe(32)
                grant = identity | {"client_id": flow["client_id"], "expires_at": int(time.time()) + GRANT_TTL}
                await self.vault.put("grant", grant_id, grant, GRANT_TTL)
                await self.vault.put(
                    "code",
                    code,
                    {
                        "code": code,
                        "grant_id": grant_id,
                        "scopes": ["plane"],
                        "client_id": flow["client_id"],
                        "expires_at": time.time() + 60,
                        "code_challenge": params["code_challenge"],
                        "redirect_uri": params["redirect_uri"],
                        "redirect_uri_provided_explicitly": params["redirect_uri_provided_explicitly"],
                        "resource": self.settings.resource,
                        "subject": identity["user_id"],
                    },
                    60,
                )
                response = RedirectResponse(
                    construct_redirect_uri(params["redirect_uri"], code=code, state=params.get("state")),
                    status_code=303,
                    headers=HEADERS,
                )
                response.delete_cookie(COOKIE, path=PATH, secure=True, httponly=True, samesite="lax")
                return response
            message = "<p>Token inválido ou sem acesso ao workspace. Confira o token e tente novamente.</p>"
        body = (
            message
            + "<p><strong>"
            + escape(flow["client_name"])
            + "</strong> solicita acesso ao workspace <strong>"
            + escape(self.settings.workspace)
            + "</strong>.</p>"
        )
        body += "<p>O aplicativo poderá ler e alterar dados conforme suas permissões no Plane.</p>"
        body += "<p>Destino da autorização: <code>" + escape(flow["params"]["redirect_uri"]) + "</code></p>"
        body += (
            "<p>Gere um token pessoal nas configurações de API do Plane e cole abaixo. "
            "O token fica protegido no servidor e não é enviado ao aplicativo nem ao chat.</p>"
        )
        body += (
            '<form method="post"><input type="hidden" name="csrf" value="'
            + escape(csrf)
            + '"><label for="pat">Token pessoal do Plane</label>'
            '<input id="pat" name="pat" type="password" autocomplete="off" maxlength="128" required>'
            '<button name="action" value="allow">Autorizar</button>'
            '<button name="action" value="deny" formnovalidate>Cancelar</button></form>'
        )
        response = page(body)
        response.set_cookie(COOKIE, csrf, max_age=300, path=PATH, secure=True, httponly=True, samesite="lax")
        return response

    def routes(self):
        return [Route(PATH, self.consent, methods=["GET", "POST"]), Route("/mcp/account", self.help)]
