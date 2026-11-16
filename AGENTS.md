# Plane MCP agent guide

## Repository and architecture

- Local project: `/home/caio/repos/plane-mcp-server`. `origin` is `caioarotolo/plane-mcp-server`; `upstream` is `makeplane/plane-mcp-server`. Work on `codex/` branches and open PRs against the fork's `main`. Never push changes to upstream.
- This is a Python MCP server built with FastMCP and the official Plane SDK. Production uses Python 3.11, uv 0.13.5 and the committed `uv.lock`; dependency metadata is in `pyproject.toml`.
- Keep the official tools and entry point compatible. The optional Community adapter lives in `plane_mcp/community/`, its tests in `tests/community/`, deployment files in `deploy/community/`, and architecture/security notes in `docs/COMMUNITY-OAUTH.md`. Run the adapter with `python -m plane_mcp.community`.
- Keep OAuth changes isolated so upstream can be merged regularly. `bash scripts/community-sync.sh` creates a review branch, merges upstream and runs checks **locally** before opening a PR. Do not reset or force-push `main` to synchronize.
- Keep implementation KISS: small changes, existing SDK mechanisms, clear errors and tests for behavior/security changes. Ruff uses a 120-character line limit; follow the existing project style.

## CI and local validation policy

- **CI tests and validation jobs must stay disabled.** GitHub Actions only builds/publishes the production image and deploys it. Do not add or re-enable remote pytest, lint, formatting, type checks, security scanners or other validation jobs unless explicitly requested by the user. PRs must not launch builds or test runners.
- A push, merge or upstream synchronization into `main` automatically deploys `https://planner.openmarkets.com.br/mcp`. Before publishing, agents may run the same checks on the user's local machine. Choose checks relevant to the change, reuse still-valid results, and state what passed, failed or was not run.
- Run the full upstream + adapter suite for OAuth/security changes, SDK/dependency upgrades or substantial upstream synchronization. For documentation/workflow-only changes, validate the edited configuration and diff without rerunning the complete application suite.
- Keep all test source and local tooling. Preserve this policy and inspect newly introduced workflows when merging upstream. Missing local dependencies are not a reason to restore CI checks.
- Production health checks, public availability checks and automatic image recovery remain enabled; these are operational deployment safeguards.

The former CI commands are available locally:

```sh
uv sync --frozen --extra dev
uv run --frozen --extra dev ruff check plane_mcp/community tests/community
uv run --frozen --extra dev ruff format --check plane_mcp/community tests/community
uv run --frozen --extra dev pytest -q
```

For a focused adapter check, use `uv run --frozen --extra dev pytest -q tests/community`. Extend lint/format coverage to other changed Python files. To validate an image locally when relevant:

```sh
docker build -f deploy/community/Dockerfile -t plane-mcp-local .
```

## Authentication and production

- Preserve direct Plane-session OAuth with PKCE S256, explicit consent, CSRF/origin validation, refresh rotation/replay protection and per-user permissions. Keep individual PAT compatibility on the same endpoint.
- Never configure a shared global Plane API token, log credentials, commit `.env` files or weaken authentication to make a check pass. Keep generated credentials encrypted in Redis; retain the encryption key and Redis volume across deployments.
- Production uses the fork's digest-pinned GHCR image and a restricted deployment SSH key. The shared receiver is maintained in the app fork under `deployments/openmarkets/`. Use `/home/caio/plane-mcp-oauth/mcp.sh` on the VPS for Compose operations so `release.compose.json` is included.
- Use `ssh -F /home/caio/.ssh/config contabo-vps` for authorized administration. Do not use production data for local tests or remove production volumes.
- Use skills or plugin-provided tools only when explicitly requested by the user; ordinary workspace, shell and web tools remain available.
