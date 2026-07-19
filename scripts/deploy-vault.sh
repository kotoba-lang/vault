#!/usr/bin/env bash
# deploy-vault.sh — provision + deploy vault.etzhayyim.com.
#
# Idempotent. Safe to re-run; each wrangler command errors gracefully if the
# resource already exists, and we only update wrangler.jsonc when the D1 id is
# missing.
#
# Prereqs:
#   - wrangler installed + authenticated (`wrangler login` or CLOUDFLARE_API_TOKEN).
#   - etzhayyim-auth Worker already deployed (AUTH_SERVICE binding target).
#
# Usage:
#   cd 60-apps/etzhayyim-project-vault
#   ./scripts/deploy-vault.sh
set -euo pipefail

cd "$(dirname "$0")/.."
WORKER_DIR="worker"
WRANGLER="$WORKER_DIR/wrangler.jsonc"

say() { printf '\n\033[1;34m[vault-deploy] %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m[vault-deploy ERROR] %s\033[0m\n' "$*" >&2; exit 1; }

command -v wrangler >/dev/null || fail "wrangler not installed"
command -v jq       >/dev/null || fail "jq not installed (brew install jq)"

# ── 1. D1 database ──────────────────────────────────────────────────────────

say "Step 1/4: ensure D1 database 'etzhayyim-vault' exists"
D1_ID=$(wrangler d1 list --json 2>/dev/null \
  | jq -r '.[] | select(.name == "etzhayyim-vault") | .uuid // empty' | head -n1)

if [[ -z "$D1_ID" ]]; then
  say "  creating etzhayyim-vault ..."
  CREATE_OUT=$(wrangler d1 create etzhayyim-vault 2>&1)
  D1_ID=$(printf '%s\n' "$CREATE_OUT" | grep -oE '"database_id": *"[^"]+"' \
    | head -n1 | sed 's/.*"database_id": *"\([^"]*\)".*/\1/')
  [[ -n "$D1_ID" ]] || fail "could not parse D1 database_id from:\n$CREATE_OUT"
  say "  created D1 id=$D1_ID"
else
  say "  found existing D1 id=$D1_ID"
fi

# Patch wrangler.jsonc if the placeholder is still present or id mismatches.
if grep -q 'REPLACE_WITH_D1_ID' "$WRANGLER"; then
  say "  patching $WRANGLER with D1 id"
  # BSD sed vs GNU sed compatibility.
  if [[ "$(uname)" == "Darwin" ]]; then
    sed -i '' "s/REPLACE_WITH_D1_ID/$D1_ID/" "$WRANGLER"
  else
    sed -i "s/REPLACE_WITH_D1_ID/$D1_ID/" "$WRANGLER"
  fi
fi

# ── 2. Apply D1 migrations ──────────────────────────────────────────────────

say "Step 2/3: apply D1 migrations"
( cd "$WORKER_DIR" && wrangler d1 migrations apply etzhayyim-vault --remote )

# ── 3. Deploy Worker ────────────────────────────────────────────────────────

say "Step 3/3: deploy etzhayyim-vault Worker"
( cd "$WORKER_DIR" && wrangler deploy )

say "done. next: update PDS (atproto.etzhayyim.com) to pick up VAULT_SERVICE binding"
say "  cd 50-infra/cloudflare/workers/atproto && wrangler deploy"
say ""
say "then smoke test with: ./scripts/smoke-vault.sh"
