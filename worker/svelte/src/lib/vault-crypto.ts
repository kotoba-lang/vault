// Zero-knowledge vault crypto using Web Crypto API.
// vaultKey (AES-256) is derived client-side and never sent to the server.
// The server stores only ciphertext + wrapped keys.

const ENC = "AES-GCM";
const WRAP = "AES-KW";
const KEY_LEN = 256;

// ── Key derivation ──────────────────────────────────────────────────────────

export async function deriveDeviceKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 210_000, hash: "SHA-256" },
    base,
    { name: WRAP, length: KEY_LEN },
    false, ["wrapKey", "unwrapKey"]
  );
}

export function randomSalt(): Uint8Array { return crypto.getRandomValues(new Uint8Array(16)); }

// ── Vault key ───────────────────────────────────────────────────────────────

export async function generateVaultKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: ENC, length: KEY_LEN }, true, ["encrypt", "decrypt"]);
}

export async function wrapKey(key: CryptoKey, wrappingKey: CryptoKey): Promise<string> {
  const buf = await crypto.subtle.wrapKey("raw", key, wrappingKey, WRAP);
  return b64url(new Uint8Array(buf));
}

export async function unwrapVaultKey(wrapped: string, deviceKey: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.unwrapKey(
    "raw", from64url(wrapped), deviceKey, WRAP,
    { name: ENC, length: KEY_LEN }, true, ["encrypt", "decrypt"]
  );
}

// ── Item encryption ─────────────────────────────────────────────────────────

export interface EncryptedItem {
  wrappedItemKey: string; // AES-key-wrap(itemKey, vaultKey)
  ciphertext: string;     // AES-256-GCM, base64url
  iv: string;             // 12-byte IV, base64url
  mac: string;            // GCM auth tag (last 16 bytes), base64url
}

export async function encryptSecret(secret: string, vaultKey: CryptoKey): Promise<EncryptedItem> {
  const itemKey = await crypto.subtle.generateKey({ name: ENC, length: KEY_LEN }, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const raw = await crypto.subtle.encrypt({ name: ENC, iv }, itemKey, new TextEncoder().encode(secret));
  const buf = new Uint8Array(raw);
  // GCM appends 16-byte auth tag at end
  const ct = buf.slice(0, buf.length - 16);
  const mac = buf.slice(buf.length - 16);
  const wrappedItemKey = await wrapKey(itemKey, vaultKey);
  return { wrappedItemKey, ciphertext: b64url(new Uint8Array(raw)), iv: b64url(iv), mac: b64url(mac) };
}

export async function decryptSecret(item: EncryptedItem, vaultKey: CryptoKey): Promise<string> {
  const itemKey = await crypto.subtle.unwrapKey(
    "raw", from64url(item.wrappedItemKey), vaultKey, WRAP,
    { name: ENC, length: KEY_LEN }, false, ["decrypt"]
  );
  const iv = from64url(item.iv);
  const ct = from64url(item.ciphertext);
  const plain = await crypto.subtle.decrypt({ name: ENC, iv }, itemKey, ct);
  return new TextDecoder().decode(plain);
}

// ── base64url helpers ───────────────────────────────────────────────────────

export function b64url(buf: Uint8Array): string {
  return btoa(String.fromCharCode(...buf)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
export function from64url(s: string): Uint8Array {
  const b = s.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b), c => c.charCodeAt(0));
}

// ── Session key cache (IndexedDB) ───────────────────────────────────────────

const DB_NAME = "etzhayyim-vault-keys";
const STORE = "vault-keys";

async function openDb(): Promise<IDBDatabase> {
  return new Promise((res, rej) => {
    const r = indexedDB.open(DB_NAME, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}

export async function cacheVaultKey(vaultId: string, key: CryptoKey): Promise<void> {
  const db = await openDb();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(key, vaultId);
    tx.oncomplete = () => res();
    tx.onerror = () => rej(tx.error);
  });
}

export async function getCachedVaultKey(vaultId: string): Promise<CryptoKey | null> {
  const db = await openDb();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(vaultId);
    req.onsuccess = () => res(req.result ?? null);
    req.onerror = () => rej(req.error);
  });
}
