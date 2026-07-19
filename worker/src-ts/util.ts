// util.ts — small helpers (ULID, base64url, JSON response, audit append).

export function nowISO(): string {
  return new Date().toISOString();
}

// ULID (Crockford base32, 26 chars: 10 ts + 16 random). RFC-style monotonic enough for our needs.
const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export function ulid(): string {
  const ts = Date.now();
  const tsChars: string[] = [];
  let t = ts;
  for (let i = 0; i < 10; i++) {
    tsChars.unshift(ULID_ALPHABET[t % 32]);
    t = Math.floor(t / 32);
  }
  const rand = new Uint8Array(10);
  crypto.getRandomValues(rand);
  const randChars: string[] = [];
  for (let i = 0; i < 16; i++) {
    randChars.push(ULID_ALPHABET[rand[i % 10] % 32]);
  }
  return tsChars.join("") + randChars.join("");
}

export function b64urlDecode(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64urlEncode(buf: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      // Vault API is browser-callable from yoro; allow CORS for vault.etzhayyim.com consumers.
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Active-DID",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    },
  });
}

export function err(status: number, code: string, message: string): Response {
  return json({ error: code, message }, status);
}
