-- vault.etzhayyim.ai D1 schema (zero-knowledge secret manager).
-- Server stores ciphertext + wrapped keys + metadata only.
-- Plaintext / vaultKey / memberDeviceKey never leave client.

CREATE TABLE IF NOT EXISTS vaults (
  id           TEXT PRIMARY KEY,        -- ULID
  name         TEXT NOT NULL,
  description  TEXT,
  created_by   TEXT NOT NULL,           -- caller DID
  created_at   TEXT NOT NULL,           -- ISO 8601
  updated_at   TEXT NOT NULL,
  deleted_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_vaults_created_by ON vaults(created_by);

CREATE TABLE IF NOT EXISTS vault_members (
  vault_id              TEXT NOT NULL,
  did                   TEXT NOT NULL,
  wrapped_vault_key     TEXT NOT NULL,  -- AES-key-wrap(vaultKey, memberDeviceKey), base64url
  member_device_key_id  TEXT NOT NULL,  -- passkey credentialId | X3DH bundle hash
  role                  TEXT NOT NULL,  -- owner | admin | reader
  added_by              TEXT NOT NULL,
  added_at              TEXT NOT NULL,
  removed_at            TEXT,
  PRIMARY KEY (vault_id, did)
);
CREATE INDEX IF NOT EXISTS idx_vault_members_did ON vault_members(did);

CREATE TABLE IF NOT EXISTS vault_items (
  id               TEXT PRIMARY KEY,    -- ULID
  vault_id         TEXT NOT NULL,
  name             TEXT NOT NULL,       -- plaintext label (search/dedup)
  wrapped_item_key TEXT NOT NULL,       -- AES-key-wrap(itemKey, vaultKey), base64url
  ciphertext       BLOB NOT NULL,       -- AES-256-GCM ciphertext (size hard-capped at 900KB)
  iv               TEXT NOT NULL,       -- AES-GCM IV (12 bytes), base64url
  mac              TEXT,                -- AES-GCM auth tag, base64url (informational; included in ciphertext for AES-GCM)
  content_type     TEXT,
  labels_json      TEXT,                -- JSON array of strings
  size             INTEGER NOT NULL,
  created_by       TEXT NOT NULL,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  deleted_at       TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_items_name ON vault_items(vault_id, name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_vault_items_vault ON vault_items(vault_id, deleted_at);

CREATE TABLE IF NOT EXISTS access_events (
  id        TEXT PRIMARY KEY,           -- ULID
  did       TEXT NOT NULL,              -- caller DID
  action    TEXT NOT NULL,              -- createVault | putItem | getItem | deleteItem | addMember | removeMember | rotateVaultKey | injectWorkerSecret | listItems | listAccessEvents
  vault_id  TEXT NOT NULL,
  item_id   TEXT,
  ts        TEXT NOT NULL,
  lxm       TEXT,                       -- Service Auth JWT lxm claim, audit trail
  ip_hash   TEXT                        -- SHA-256(ip || salt), privacy-preserving
);
CREATE INDEX IF NOT EXISTS idx_access_events_vault ON access_events(vault_id, ts);
CREATE INDEX IF NOT EXISTS idx_access_events_did ON access_events(did, ts);
