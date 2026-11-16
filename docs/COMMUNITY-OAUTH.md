# Direct OAuth for Plane Community

This optional adapter adds OAuth to the official MCP server without changing any
existing upstream source file, tool, dependency, lockfile or entry point. Run it
with `python -m plane_mcp.community`.

## User experience

1. Add `https://planner.openmarkets.com.br/mcp` to Claude or Codex with OAuth/sign-in.
2. The browser opens Plane's own login if you are not already signed in.
3. Check your account, the requesting application and callback destination, then
   click **Authorize**. No API token copying or separate account is required.
4. The adapter creates a dedicated, expiring Plane API token through the ordinary
   user API and keeps it encrypted. The MCP client receives separate OAuth tokens.

Plane must share the adapter's HTTPS origin and use its default `session-id`
cookie. Only that session cookie and `csrftoken` are forwarded to the configured
trusted Plane backend. Browser sessions and passwords are never persisted by the
adapter or sent to the MCP client. It verifies the current user and workspace
membership again when consent is submitted, and rejects an account switch.

The generated credential is named `MCP OAuth · <client name>` in Plane's API
settings. It expires after seven days, together with the OAuth grant. Deleting it
in Plane disconnects that authorization. It is created only after explicit
consent; visiting or cancelling the page creates no credential. Token ownership,
expiry and workspace access are verified before issuing an OAuth code.

Existing clients using `Authorization: Bearer plane_api_...` or the raw PAT keep
working on the same `/mcp` URL. A missing workspace header uses the configured
workspace. OAuth always uses the configured workspace, regardless of headers.

## Architecture and security

- FastMCP/MCP SDK handlers handle discovery, registration, client authentication,
  redirect validation and Authorization Code + PKCE S256 verification. FastMCP's
  CIMD manager handles published client identities, SSRF-safe metadata retrieval
  and private-key client assertions. Redirects also use the official allowlist.
- The adapter supplies consent and encrypted authorization records. It uses
  random 256-bit opaque codes/tokens, not a custom JWT signing scheme.
- Consent expires after five minutes. Secure/HttpOnly/SameSite cookies, exact
  Origin and CSRF checks, no-store, same-origin referrer policy and frame restrictions
  protect the form. Users see both the requesting application and its callback.
- Authorization codes expire after 60 seconds. Atomic consumption prevents
  concurrent reuse after the SDK checks PKCE, client and redirect URI.
- Access tokens last at most ten minutes. Grants expire after seven days; refresh
  cannot extend that absolute limit. Refresh revalidates access in Plane.
- Refresh tokens rotate atomically. Reuse of an old refresh token revokes its
  entire authorization family. Separate users and connections remain unaffected.
- Revoking an access or refresh token deletes that authorization family. Every
  request checks the grant, so revocation blocks subsequent requests immediately.
  Requests already in flight can finish. Revoking the PAT in Plane also blocks
  subsequent Plane API operations and refresh, including direct PAT clients.
  OAuth revocation deletes the encrypted credential from the grant immediately;
  its now-inaccessible backing token remains listed in Plane until removed there
  and expires within seven days. No browser session is retained for later cleanup.
- Redis stores SHA-256 identifiers and Fernet-encrypted records. PATs and OAuth
  bearer tokens are never stored as plaintext Redis keys. A verified PAT is placed
  only in the official server's request-local context, never issued to a client.
- Global auth budgets for this small deployment: 60 client registrations/hour,
  120 authorization requests/minute, 120 consent requests/minute and 300 token or
  revocation requests/minute. Auth bodies are capped at 32 KiB. MCP tool calls are
  unaffected. Client registrations expire after seven days and can be renewed by
  registering again. There are no public database or Redis ports.

The locked SDK incorrectly requires a nullable `client_secret` form field at
revocation. The adapter supplies an empty field when omitted, while retaining
client authentication and token ownership checks. This is covered for public
and confidential clients.

## Deployment

Only the MCP container and a dedicated persistent Redis are required, alongside
the existing Plane and HTTPS proxy. Examples: `deploy/community/`.

Required configuration:

| Variable | Value |
|---|---|
| COMMUNITY_PUBLIC_URL | HTTPS origin, e.g. `https://planner.openmarkets.com.br` |
| COMMUNITY_ENCRYPTION_KEY | A Fernet key retained across deployments |
| REDIS_URL | Private persistent Redis URL (the Compose file constructs it) |
| MCP_DEFAULT_WORKSPACE_SLUG | `openmarkets` |
| PLANE_BASE_URL | Public Plane origin |
| PLANE_INTERNAL_BASE_URL | Trusted internal Plane API origin |

Compose additionally requires `MCP_IMAGE` and `REDIS_PASSWORD`. Build from the
frozen official lockfile; deploy a pinned image. Never configure a global
`PLANE_API_KEY` or `PLANE_ACCESS_TOKEN`: the adapter rejects shared credentials.
Keep environment files outside Git with permissions 0600.

Proxy these paths without stripping prefixes:

- `/mcp` and `/mcp/*`
- `/.well-known/oauth-authorization-server`
- `/.well-known/oauth-protected-resource` and its `/mcp` variant
- `/authorize`, `/token`, `/register`, `/revoke`

Plane's SPA router cannot render the adapter's page. On the existing `/auth/*`
proxy route, rewrite only a successful login redirect for our exact consent path
into a document redirect. Example Caddy configuration for this deployment:

```caddy
reverse_proxy /auth/* api:8000 {
    header_down Location "^https://planner[.]openmarkets[.]com[.]br/[?]next_path=(/mcp/authorize[?]request=[A-Za-z0-9_-]{43})$" "$1"
}
```

Use your exact public hostname. Error redirects and all other Plane logins remain
unchanged. The consent endpoint validates the session and authorization request
again; the redirect itself grants no access. This proxy rule replaces no Plane
source and must be retained when upgrading the proxy configuration.

`/mcp/account` only explains how to start authorization from the MCP client; it
has no login or credential form. The consent page requires a valid authorization
request from the client.

Back up Redis and the encryption key, storing the key separately. Losing either
requires users to authorize again. There is no identity-provider database to
maintain. Changing the key invalidates existing records.

## Synchronizing the fork

Run `bash scripts/community-sync.sh` from a clean checkout. It fetches official
`main`, creates a `codex/upstream-...` review branch from the fork's `main`, merges,
runs lint and the complete upstream + adapter tests, then opens a PR. It never
resets the fork, force-pushes or deploys. Conflicts stop the script.

Keep the adapter separate. Dependency or behavior changes upstream can still
require adaptation; isolated files avoid textual conflicts, while tests detect
compatibility regressions. Build and validate a new image before changing the
running deployment.

## Validation and rollback

Run `uv sync --frozen --extra dev` and `uv run --frozen --extra dev pytest -q`.
Tests exercise the actual OAuth handlers: PKCE, CSRF, resource/client/redirect
binding, expiry, concurrent code exchange, encryption, refresh rotation/replay,
revocation, per-user context, CIMD, Plane session/consent binding, credential
ownership/expiry and legacy PAT compatibility.

Before deployment, validate real Plane permissions and CRUD with temporary
accounts, restart Redis/MCP to check persistence, and test public HTTPS. Keep the
previous image and proxy configuration until these checks pass. Roll back by
restoring the previous image/configuration; retain the Redis volume and key.
