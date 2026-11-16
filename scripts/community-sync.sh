#!/usr/bin/env bash
# Merge upstream on a review branch. Never reset/overwrite the fork's main.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
if [[ -n "$(git status --porcelain)" ]]; then
  echo 'Commit or stash local changes before synchronizing.' >&2
  exit 1
fi
git fetch origin main
git fetch https://github.com/makeplane/plane-mcp-server.git main
upstream_sha=$(git rev-parse FETCH_HEAD)
if git merge-base --is-ancestor "$upstream_sha" origin/main; then
  echo 'The fork already contains the current upstream main.'
  exit 0
fi
sync_branch="codex/upstream-$(date -u +%Y%m%dT%H%M%SZ)"
git switch -c "$sync_branch" origin/main
# Conflicts stop here for human/code review; no force pushes or auto-deploys.
git merge --no-edit "$upstream_sha"
uv sync --frozen --extra dev
uv run --frozen --extra dev ruff check plane_mcp/community tests/community
uv run --frozen --extra dev pytest -q
git push -u origin "$sync_branch"
pr_body=$(mktemp)
trap 'rm -f "$pr_body"' EXIT
cat > "$pr_body" <<'BODY'
Merge the current official Plane MCP changes while preserving the separate Community OAuth adapter.

Validation: frozen dependency install, adapter lint, and the full upstream + Community test suite.
Deployment remains a separate operation after review.
BODY
gh pr create --repo caioarotolo/plane-mcp-server --base main --head "$sync_branch" \
  --title 'Sync official Plane MCP updates' --body-file "$pr_body"
