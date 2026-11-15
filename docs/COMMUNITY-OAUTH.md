# Plane Community: OAuth and personal tokens

This fork adds an optional deployment adapter under `plane_mcp/community/`.
The official source files, tools, package metadata, lockfile, and entry points are
unchanged. Start the adapter with `python -m plane_mcp.community`.

The design is inspired by the Authentik/PAT bridge in
[andreafio/plane-mcp-server](https://github.com/andreafio/plane-mcp-server), but uses
FastMCP's `MultiAuth` to feed verified per-request credentials into the official
tools without patching their client or middleware.

## Architecture

- FastMCP `OIDCProxy` owns MCP OAuth 2.1, PKCE S256, discovery, DCR/CIMD,
  consent, encrypted upstream tokens, refresh and revocation.
  The adapter retains Authentik's required `offline_access` scope on refresh,
  including when a client requests only `openid`.
- Authentik authenticates users with OIDC. Use RS256, a signing key, explicit
  redirect URIs, 10-minute access/ID tokens, rotating refresh tokens and a
  restricted application group. Enable passkeys/MFA in its authentication flow.
- A separate authenticated account page links a user's Plane PAT. It uses
  Authlib authorization code + PKCE, nonce verification, issuer/audience checking,
  Secure/HttpOnly/SameSite cookies, CSRF checks, and atomic single-use login state.
- The identity key is a SHA-256 digest of the verified `[issuer, subject]` pair.
  Plane validates the submitted PAT and membership before it is stored.
- PATs, portal sessions and login state are Fernet-encrypted in dedicated Redis.
  The encryption and signing keys must be backed up separately from Redis.
- Each authenticated MCP request gets its own copy of the upstream API-key
  context. No global Plane token is configured. The Plane API remains the source
  of truth for workspace/project permissions, token expiration and revocation.
- Unlinked OAuth users can discover tools and call `identity`, but cannot run
  Plane tools. The `identity` tool never takes or returns a credential.
- Legacy `Authorization: Bearer plane_api_...` and raw PAT headers remain supported
  on `/mcp`; missing workspace headers use the configured default. OAuth workspace
  selection comes from configuration, never from an untrusted request header.

## Configuration

Required environment variables:

| Variable | Meaning |
|---|---|
| COMMUNITY_PUBLIC_URL | HTTPS origin, e.g. `https://planner.example.com` |
| COMMUNITY_OIDC_DISCOVERY_URL | Trusted Authentik discovery URL |
| COMMUNITY_OIDC_CLIENT_ID / COMMUNITY_OIDC_CLIENT_SECRET | Confidential OIDC application |
| COMMUNITY_ENCRYPTION_KEY | Fernet key, retained across deployments |
| COMMUNITY_SIGNING_KEY | Independent random signing secret (32+ characters) |
| REDIS_URL | Dedicated persistent Redis connection |
| MCP_DEFAULT_WORKSPACE_SLUG | Workspace the OAuth connection uses |
| PLANE_BASE_URL | Public Plane origin |
| PLANE_INTERNAL_BASE_URL | Internal trusted Plane API origin |

Register these exact Authentik callback URLs:

- `https://planner.example.com/mcp/oauth/callback` (MCP OAuth proxy)
- `https://planner.example.com/mcp/account/callback` (account-link page)

Include the `openid`, `profile`, `email` and `offline_access` scope mappings.
The issuer, audience and signature algorithm are verified. Both callbacks use
PKCE; client authentication uses `client_secret_post` over HTTPS.

Route these paths to the adapter, without stripping their prefixes:

- `/mcp` and `/mcp/*`
- `/.well-known/oauth-authorization-server`
- `/.well-known/oauth-protected-resource` and its `/mcp` variant
- `/authorize`, `/token`, `/register`, `/revoke`, `/consent`

Docker examples are in `deploy/community/`. They publish no database or Redis
ports and do not mount the Docker socket into Authentik. Use the existing HTTPS
proxy and pin image versions/digests. The MCP image installs `uv.lock` frozen.
Keep environment files outside the repository with mode 0600.

## User setup

1. The administrator creates your Authentik account and grants application access.
2. Open `https://planner.example.com/mcp/account` and sign in.
3. Generate a personal API token in Plane and link it in that page. It never goes
   into a chat, MCP tool argument, URL, repository or application log.
4. Add `https://planner.example.com/mcp` to your MCP client with OAuth/sign-in.
5. To disconnect, use the account page. To invalidate the PAT everywhere, revoke
   it in Plane as well. Unlinking affects OAuth; direct PAT clients remain valid
   until Plane revokes or expires their token.

Auth sessions may remain valid until the short access-token lifetime expires when
an identity is disabled at the IdP. Removing the Plane membership/PAT or deleting
the adapter binding blocks subsequent Plane operations independently. Existing
in-flight calls can finish. Both Redis persistence and encryption keys are needed
to retain links across restarts. Portal sessions expire after ten minutes.

## Updating from the official repository

Run `bash scripts/community-sync.sh` from a clean checkout. It fetches the official
`main`, creates a `codex/upstream-...` branch from the fork's `main`, merges, runs
the full test suite, then opens a pull request. Conflicts stop the script; it never
resets the fork, force-pushes, or deploys. Review and merge the PR, then build a new
image and validate before rollout. The GitHub `Community OAuth checks` workflow
also runs on PRs and pushes.

Keep new integration code in the adapter directory. Updates to FastMCP may still
require adapter changes: isolated files avoid textual conflicts, while integration
tests catch behavioral changes. Do not use a destructive mirror/reset operation
to synchronize the customized main branch.

## Validation and rollback

`uv sync --frozen --extra dev && uv run --frozen --extra dev pytest -q` runs upstream tests and
adapter security/compatibility tests. Before promotion, exercise real OAuth with
two separate users, wrong/missing PKCE, refresh, unlink/revocation, persistence,
and legacy PAT clients. Keep the previous MCP container/config available and
switch only the proxy route after validation; rollback is a proxy reload.
