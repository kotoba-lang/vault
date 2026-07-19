# vault.etzhayyim.com — Zero-Knowledge Secret Manager

DID-native, AT-Protocol-pipethrough secret manager. 1Password-equivalent self-hosted.

## Topology

```
etzhayyim CLI / browser  ──Bearer JWT (AT session or Service Auth lxm)──▶  atproto.etzhayyim.com (PDS)
                                                                              │ pipethrough
                                                                              ▼
                                                                       vault.etzhayyim.com (this Worker)
                                                                              │
                                       ┌──────────────────────────────────────┴────────────┐
                                       ▼                                                   ▼
                                  D1 VAULT_DB                               AUTH_SERVICE binding
                                  (vaults / members / items /               (DID verification)
                                   ciphertext BLOB / access_events)
```

**Server stores ciphertext + wrapped keys + metadata only.** Plaintext / vaultKey / memberDeviceKey never reach the server (zero-knowledge).
**Storage is D1-only.** Per-item ciphertext is hard-capped at **900 KB** (staying safely under D1's effective ~1 MB BLOB cell limit). Large file attachments (photos, PDFs) are out of scope for V1 — use a dedicated blob store if that changes.

## Crypto Model

- `vaultKey` = AES-256, random per vault, **never seen by server**
- `memberDeviceKey` = HKDF(WebAuthn PRF) **client-side** (browser passkey) or macOS Keychain (etzhayyim CLI)
- `wrappedVaultKey[member]` = AES-key-wrap(vaultKey, memberDeviceKey) — stored per member in `vault_members`
- `itemKey` = AES-256, random per item
- `wrappedItemKey` = AES-key-wrap(itemKey, vaultKey) — stored per item
- `ciphertext` = AES-256-GCM(itemKey, plaintext)

Sharing = X3DH (`com.etzhayyim.signal.getPrekeyBundle(recipientDid)`) → derive sharedSecret → wrap vaultKey to recipient → `addMember`.

## Storage

| Layer | Storage | Schema |
|---|---|---|
| Vault metadata | D1 `vaults` | id, name, created_by, timestamps |
| Membership + wrapped keys | D1 `vault_members` | (vault_id, did) PK + wrapped_vault_key + role |
| Items (ciphertext ≤900 KB) | D1 `vault_items.ciphertext` BLOB | inline; server rejects larger with `ItemTooLarge` |
| Audit | D1 `access_events` (plus AT Record canonical, P7 follow-up) | append-only |

`MAX_CIPHERTEXT_BYTES = 900_000` enforced in `handlers.ts handlePutItem`.

## NSIDs (`com.etzhayyim.vault.*`)

| NSID | Method | Required role |
|---|---|---|
| `createVault` | POST | (any caller) |
| `listVaults` | GET | reader of vault |
| `putItem` | POST | reader+ |
| `getItem` | GET | reader+ |
| `listItems` | GET | reader+ |
| `deleteItem` | POST | admin+ |
| `addMember` | POST | admin+ |
| `removeMember` | POST | admin+ |
| `rotateVaultKey` | POST | admin+ |
| `listAccessEvents` | GET | admin+ |
| `injectWorkerSecret` | POST | admin+ (server-side decrypt with caller-supplied ephemeral vaultKey, one-shot) |

Lexicon JSON: `00-contracts/lexicons/com/etzhayyim/vault/*.json`

## Auth

Delegated to `AUTH_SERVICE` binding (`etzhayyim-auth`):
- `Authorization: Bearer <jwt>` → AT session HS256, ES256 Service Auth, or API key (`sk_live_*`)
- `X-Active-DID: did:web:...` → switch to sub-actor DID per request
- For programmatic agents (Claude Code), use `etzhayyim agent-token --lxm com.etzhayyim.vault.getItem --ttl 60` to mint scoped Service Auth JWT

Vault role enforcement is **per-NSID** against `vault_members` table.

## Bindings

| Binding | Type | Purpose |
|---|---|---|
| `VAULT_DB` | D1 | vaults / members / items (ciphertext ≤900 KB inline) / access_events |
| `AUTH_SERVICE` | service binding | DID/JWT verification |
| `CF_API_TOKEN` | secrets store | for `injectWorkerSecret` → CF Workers Secret PUT |
| `CF_ACCOUNT_ID` | secrets store | account id for CF API calls |

## Deploy

```bash
# Initial: provision D1
wrangler d1 create etzhayyim-vault              # capture id → wrangler.jsonc
wrangler d1 migrations apply etzhayyim-vault    # applies migrations/0001_init.sql

cd 60-apps/etzhayyim-project-vault/worker
etzhayyim deploy   # or: wrangler deploy
```

PDS pipethrough: ensure `50-infra/cloudflare/workers/atproto/wrangler.jsonc` has
`{ "binding": "VAULT_SERVICE", "service": "etzhayyim-vault" }` and that
`com.etzhayyim.vault.*` NSIDs route to it from `pds-dispatch.ts`.

## Client

- TS: `@etzhayyim/wproto` exports `vaultGet/vaultSet/vaultShare/vaultRotate` (P4)
- CLI: `etzhayyim vault create/add/get/list/share/rotate/audit/run/inject` (P5)
- Browser: WebAuthn PRF extension to derive `memberDeviceKey` (browser-native, no npm deps)
- etzhayyim CLI: macOS Keychain stores `memberDeviceKey` per device (`security add-generic-password` wrapper)

## Comparison vs 1Password

| Axis | 1Password | vault.etzhayyim.com |
|---|---|---|
| Identity | email + master pw + Secret Key | DID + Passkey (PRF) |
| Zero-knowledge | proprietary SRP + PBKDF2 | WebAuthn PRF + AES key-wrap |
| Sharing | proprietary RSA wrap | Signal X3DH (forward secrecy) |
| Audit | proprietary | D1 (+ AT Record canonical follow-up) |
| Federation | × | AT Protocol DIDs |
| Cost | $8/u/月 | self-host (CF + B2 + D1 free tier) |
| Recovery | Emergency Kit (PDF) | did:plc rotation (ADR-0014) |
| Open standards | × | WebAuthn + AT Protocol + Signal |

## Prohibited Patterns

- **Server-side plaintext persistence禁止** — `injectWorkerSecret` の ephemeralVaultKey は CF API call 後に必ず drop。新規にキャッシュ・ログ・graph 投影しない
- **vaultKey の server fetch 禁止** — server がフェッチ可能になると zero-knowledge violation
- **wrapped key を public AT Record に書く禁止** — wrapped key は D1 のみ。AT Record は audit (event metadata) のみ federable
- **role escalation auto-grant 禁止** — `addMember` でも reader/admin/owner は明示指定が必要
