#!/usr/bin/env bash
set -euo pipefail
umask 077
deploy_tmp=$(mktemp -d)
trap 'rm -rf "$deploy_tmp"' EXIT
printf '%s\n' "$DEPLOY_SSH_KEY" > "$deploy_tmp/key"
printf '%s\n' "$DEPLOY_KNOWN_HOSTS" > "$deploy_tmp/known_hosts"
# Only a commit identifier and an ephemeral registry token reach the receiver.
# The SSH key cannot run a shell, forward ports, upload files or choose images.
printf '%s\n' "$GH_TOKEN" | ssh -T -i "$deploy_tmp/key" -p "$DEPLOY_PORT" \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$deploy_tmp/known_hosts" -o ConnectTimeout=15 \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
  "caio@$DEPLOY_HOST" "deploy $GITHUB_SHA"
