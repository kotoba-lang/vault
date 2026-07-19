// auth.ts — caller DID extraction + vault role checks.
//
// Trust chain:
//   1. Bearer JWT in Authorization header → AUTH_SERVICE /xrpc/com.etzhayyim.auth.authenticate
//      returns { level: "session"|"internal", did, lxm? }
//   2. Service binding caller (level=internal) bypasses session check.
//   3. Vault role (owner|admin|reader) is enforced per NSID against vault_members.

export interface CallerCtx {
  did: string;          // canonical actor DID
  level: "session" | "internal";
  lxm?: string;         // Service Auth JWT lxm claim (audit trail)
  ipHash: string;       // SHA-256(ip || salt), used for access_events
}

export interface VaultRole {
  vaultId: string;
  role: "owner" | "admin" | "reader";
}

export class AuthError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

export async function authenticate(req: Request, env: { AUTH_SERVICE: Fetcher; VAULT_AUDIT_HASH_SALT: string }): Promise<CallerCtx> {
  const authz = req.headers.get("authorization") ?? "";
  if (!authz.startsWith("Bearer ")) {
    throw new AuthError(401, "AuthMissing", "Authorization: Bearer <jwt> required");
  }
  // Delegate verification to AUTH_SERVICE (handles AT session HS256 + ES256 Service Auth + API key).
  const activeDid = req.headers.get("x-active-did");
  const verifyRes = await env.AUTH_SERVICE.fetch("https://authn.etzhayyim.com/xrpc/com.etzhayyim.auth.authenticate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      authorization: authz,
      xActiveDid: activeDid && activeDid.startsWith("did:") ? activeDid : undefined,
      context: "vault",
    }),
  });
  if (!verifyRes.ok) {
    throw new AuthError(401, "AuthInvalid", `auth verification failed: ${verifyRes.status}`);
  }
  const verified = await verifyRes.json() as { did?: string; level?: string; lxm?: string };
  if (!verified.did || !verified.level) {
    throw new AuthError(401, "AuthInvalid", "auth response missing did/level");
  }

  const ip = req.headers.get("cf-connecting-ip") ?? "0.0.0.0";
  const ipHash = await sha256Hex(ip + ":" + env.VAULT_AUDIT_HASH_SALT);

  return {
    did: verified.did,
    level: verified.level === "internal" ? "internal" : "session",
    lxm: verified.lxm,
    ipHash,
  };
}

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function requireVaultRole(
  db: D1Database,
  caller: CallerCtx,
  vaultId: string,
  required: ("owner" | "admin" | "reader")[],
): Promise<VaultRole> {
  const row = await db
    .prepare(`SELECT role FROM vault_members WHERE vault_id = ? AND did = ? AND removed_at IS NULL LIMIT 1`)
    .bind(vaultId, caller.did)
    .first<{ role: "owner" | "admin" | "reader" }>();
  if (!row) throw new AuthError(403, "VaultAccessDenied", "caller is not a member of this vault");
  if (!required.includes(row.role)) {
    throw new AuthError(403, "VaultRoleInsufficient", `role ${row.role} cannot perform this action; required: ${required.join("|")}`);
  }
  return { vaultId, role: row.role };
}
