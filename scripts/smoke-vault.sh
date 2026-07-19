#!/usr/bin/env bash
# smoke-vault.sh — end-to-end test of vault.etzhayyim.com via PDS pipethrough.
#
# Exercises: health → createVault → putItem → listItems → getItem → deleteItem
# Auth: reads session from `etzhayyim auth login` (~/.etzhayyim/auth.json) or etzhayyim_TOKEN.
#
# Assumes: ./deploy-vault.sh already ran successfully AND PDS has been
# redeployed with VAULT_SERVICE binding.
set -euo pipefail

PDS="${PDS_URL:-https://atproto.etzhayyim.com}"
VAULT_DIRECT="${VAULT_URL:-https://vault.etzhayyim.com}"
TEST_NAME="smoke-$(date +%Y%m%d-%H%M%S)"

say()  { printf '\n\033[1;34m[smoke] %s\033[0m\n' "$*"; }
pass() { printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
fail() { printf '  \033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

command -v etzhayyim >/dev/null || fail "etzhayyim CLI not in PATH"
command -v curl >/dev/null || fail "curl not installed"
command -v jq   >/dev/null || fail "jq not installed"

TOKEN="${etzhayyim_TOKEN:-}"
if [[ -z "$TOKEN" ]]; then
  TOKEN=$(etzhayyim auth token 2>/dev/null || true)
fi
[[ -n "$TOKEN" ]] || fail "no auth token (run 'etzhayyim auth login' or set etzhayyim_TOKEN)"

# ── 1. Direct health probe (skips PDS) ──────────────────────────────────────
say "1/7  GET $VAULT_DIRECT/health"
HEALTH=$(curl -sS -o /dev/null -w '%{http_code}' "$VAULT_DIRECT/health" || echo 000)
if [[ "$HEALTH" == "200" ]]; then
  pass "vault worker reachable directly ($HEALTH)"
else
  say "  (skip direct — vault.etzhayyim.com route not configured: $HEALTH). PDS pipethrough path still valid."
fi

# ── 2. Pipethrough via PDS: createVault ─────────────────────────────────────
say "2/7  etzhayyim vault create $TEST_NAME"
CREATE_OUT=$(etzhayyim vault create "$TEST_NAME" --description "smoke test vault" 2>&1)
printf '%s\n' "$CREATE_OUT"
VAULT_ID=$(printf '%s\n' "$CREATE_OUT" | awk '/id:/ {print $2; exit}')
[[ -n "$VAULT_ID" ]] || fail "could not parse vaultId from create output"
pass "vault created: $VAULT_ID"

# ── 3. putItem ──────────────────────────────────────────────────────────────
say "3/7  etzhayyim vault add  (inline secret 'hello-vault-smoke')"
echo -n "hello-vault-smoke" | etzhayyim vault add "$VAULT_ID" SMOKE_ITEM --stdin --content-type text/plain >/dev/null
pass "item added"

# ── 4. listItems ────────────────────────────────────────────────────────────
say "4/7  etzhayyim vault ls $VAULT_ID"
LS_OUT=$(etzhayyim vault ls "$VAULT_ID" --json)
ITEM_COUNT=$(printf '%s' "$LS_OUT" | jq '.total')
[[ "$ITEM_COUNT" -ge 1 ]] || fail "expected >=1 item, got $ITEM_COUNT"
pass "item count = $ITEM_COUNT"

# ── 5. getItem (round-trip decrypt) ─────────────────────────────────────────
say "5/7  etzhayyim vault get $VAULT_ID SMOKE_ITEM"
GOT=$(etzhayyim vault get "$VAULT_ID" SMOKE_ITEM --raw)
[[ "$GOT" == "hello-vault-smoke" ]] || fail "decrypt mismatch: got '$GOT'"
pass "decrypt ok (plaintext matches)"

# ── 6. audit trail ──────────────────────────────────────────────────────────
say "6/7  etzhayyim vault audit $VAULT_ID"
AUDIT=$(etzhayyim vault audit "$VAULT_ID" --json)
EVT=$(printf '%s' "$AUDIT" | jq '.total')
[[ "$EVT" -ge 3 ]] || fail "expected >=3 audit events (create+put+list+get), got $EVT"
pass "audit events = $EVT"

# ── 7. cleanup: deleteItem ──────────────────────────────────────────────────
say "7/7  etzhayyim vault rm  (cleanup)"
ITEM_ID=$(printf '%s' "$LS_OUT" | jq -r '.items[0].itemId')
etzhayyim vault rm "$VAULT_ID" "$ITEM_ID" >/dev/null
pass "item deleted"

say "SMOKE PASS — vault $VAULT_ID is usable."
echo "  (vault record retained — delete with direct D1 query if you want a pristine state.)"
