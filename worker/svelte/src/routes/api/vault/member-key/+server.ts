// Returns the wrapped vault key + salt for the authenticated member.
// Used by the client to unlock the vault with their password.
import { json, error } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";

type Env = { VAULT_DB?: D1Database; AUTHN_URL?: string };

async function getCallerDid(event: { request: Request }, env: Env): Promise<string | null> {
  const authnUrl = (env.AUTHN_URL ?? "https://authn.etzhayyim.com").replace(/\/$/, "");
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 4000);
    const r = await fetch(`${authnUrl}/api/auth/whoami`, {
      headers: { cookie: event.request.headers.get("cookie") ?? "" },
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    if (!r.ok) return null;
    const body = await r.json() as { anon?: boolean; did?: string };
    return body.anon ? null : (body.did ?? null);
  } catch { return null; }
}

export const GET: RequestHandler = async (event) => {
  const env = (event.platform as { env?: Env } | undefined)?.env ?? {};
  const db = env.VAULT_DB;
  if (!db) throw error(503, "Database not configured");

  const did = await getCallerDid(event, env);
  if (!did) throw error(401, "Unauthorized");

  const vaultId = event.url.searchParams.get("vaultId");
  if (!vaultId) throw error(400, "Missing vaultId");

  const row = await db.prepare(
    "SELECT wrapped_vault_key, member_device_key_id FROM vault_members WHERE vault_id = ? AND did = ? AND removed_at IS NULL"
  ).bind(vaultId, did).first<{ wrapped_vault_key: string; member_device_key_id: string }>();

  if (!row) throw error(404, "Not a member of this vault");

  return json({ wrappedVaultKey: row.wrapped_vault_key, saltB64: row.member_device_key_id }, {
    headers: { "cache-control": "no-store" }
  });
};
