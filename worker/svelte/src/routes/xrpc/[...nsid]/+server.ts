import { json, error } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";

type Env = { VAULT_DB?: D1Database; AUTHN_URL?: string };

function ulid(): string {
  const t = Date.now().toString(36).toUpperCase().padStart(10, "0");
  const r = Array.from(crypto.getRandomValues(new Uint8Array(10)), b =>
    "0123456789ABCDEFGHJKMNPQRSTVWXYZ"[b % 32]
  ).join("");
  return t + r;
}

function now(): string { return new Date().toISOString(); }

function noStore(body: unknown, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  headers.set("cache-control", "no-store");
  headers.set("content-type", "application/json");
  return new Response(JSON.stringify(body), { ...init, headers });
}

async function getCallerDid(request: Request, env: Env): Promise<string | null> {
  const authnUrl = (env.AUTHN_URL ?? "https://authn.etzhayyim.com").replace(/\/$/, "");
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 4000);
    const r = await fetch(`${authnUrl}/api/auth/whoami`, {
      headers: { cookie: request.headers.get("cookie") ?? "" },
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    if (!r.ok) return null;
    const body = await r.json() as { anon?: boolean; did?: string };
    return body.anon ? null : (body.did ?? null);
  } catch { return null; }
}

async function logAccess(db: D1Database, did: string, action: string, vaultId: string, itemId?: string) {
  await db.prepare(
    "INSERT INTO access_events (id, did, action, vault_id, item_id, ts) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(ulid(), did, action, vaultId, itemId ?? null, now()).run().catch(() => { /* non-fatal */ });
}

// ── Handlers ────────────────────────────────────────────────────────────────

async function handleCreateVault(db: D1Database, did: string, input: Record<string, unknown>) {
  const name = input.name as string;
  const description = input.description as string | undefined;
  const wrappedVaultKey = input.wrappedVaultKey as string;
  const memberDeviceKeyId = input.memberDeviceKeyId as string;

  if (!name?.trim()) throw error(400, "name is required");
  if (!wrappedVaultKey) throw error(400, "wrappedVaultKey is required");
  if (!memberDeviceKeyId) throw error(400, "memberDeviceKeyId is required");

  const vaultId = ulid();
  const ts = now();

  await db.batch([
    db.prepare("INSERT INTO vaults (id, name, description, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(vaultId, name.trim(), description ?? null, did, ts, ts),
    db.prepare("INSERT INTO vault_members (vault_id, did, wrapped_vault_key, member_device_key_id, role, added_by, added_at) VALUES (?, ?, ?, ?, 'owner', ?, ?)")
      .bind(vaultId, did, wrappedVaultKey, memberDeviceKeyId, did, ts),
  ]);

  await logAccess(db, did, "createVault", vaultId);
  return noStore({ vaultId, createdAt: ts });
}

async function handleListVaults(db: D1Database, did: string) {
  const rows = await db.prepare(`
    SELECT v.id, v.name, v.description, v.created_at, vm.role
    FROM vaults v
    JOIN vault_members vm ON vm.vault_id = v.id AND vm.did = ? AND vm.removed_at IS NULL
    WHERE v.deleted_at IS NULL
    ORDER BY v.created_at DESC
  `).bind(did).all<{ id: string; name: string; description: string | null; created_at: string; role: string }>();

  const vaults = (rows.results ?? []).map(r => ({
    vaultId: r.id, name: r.name, description: r.description ?? undefined,
    createdAt: r.created_at, role: r.role,
  }));
  return noStore({ vaults });
}

async function handlePutItem(db: D1Database, did: string, input: Record<string, unknown>) {
  const vaultId = input.vaultId as string;
  const itemName = input.itemName as string;
  const wrappedItemKey = input.wrappedItemKey as string;
  const ciphertext = input.ciphertext as string;
  const iv = input.iv as string;
  const mac = (input.mac as string | undefined) ?? null;
  const contentType = (input.contentType as string | undefined) ?? null;
  const labels = input.labels as string[] | undefined;

  if (!vaultId || !itemName?.trim() || !wrappedItemKey || !ciphertext || !iv)
    throw error(400, "Missing required fields");

  // Verify membership
  const member = await db.prepare(
    "SELECT role FROM vault_members WHERE vault_id = ? AND did = ? AND removed_at IS NULL"
  ).bind(vaultId, did).first<{ role: string }>();
  if (!member) throw error(403, "Not a member of this vault");

  const itemId = ulid();
  const ts = now();
  const ctBuf = Uint8Array.from(atob(ciphertext.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  const size = ctBuf.length;

  await db.prepare(`
    INSERT INTO vault_items (id, vault_id, name, wrapped_item_key, ciphertext, iv, mac, content_type, labels_json, size, created_by, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (vault_id, name) WHERE deleted_at IS NULL DO UPDATE SET
      wrapped_item_key = excluded.wrapped_item_key, ciphertext = excluded.ciphertext,
      iv = excluded.iv, mac = excluded.mac, size = excluded.size, updated_at = excluded.updated_at
  `).bind(itemId, vaultId, itemName.trim(), wrappedItemKey, ciphertext, iv, mac, contentType,
      labels ? JSON.stringify(labels) : null, size, did, ts, ts).run();

  await logAccess(db, did, "putItem", vaultId, itemId);
  return noStore({ itemId, createdAt: ts, size });
}

async function handleListItems(db: D1Database, did: string, vaultId: string) {
  const member = await db.prepare(
    "SELECT role FROM vault_members WHERE vault_id = ? AND did = ? AND removed_at IS NULL"
  ).bind(vaultId, did).first();
  if (!member) throw error(403, "Not a member of this vault");

  const rows = await db.prepare(`
    SELECT id, name, content_type, labels_json, size, created_at, updated_at
    FROM vault_items WHERE vault_id = ? AND deleted_at IS NULL ORDER BY name
  `).bind(vaultId).all<{ id: string; name: string; content_type: string | null; labels_json: string | null; size: number; created_at: string; updated_at: string }>();

  const items = (rows.results ?? []).map(r => ({
    itemId: r.id, name: r.name,
    contentType: r.content_type ?? undefined,
    labels: r.labels_json ? JSON.parse(r.labels_json) as string[] : undefined,
    size: r.size, createdAt: r.created_at, updatedAt: r.updated_at,
  }));
  return noStore({ items });
}

async function handleGetItem(db: D1Database, did: string, itemId: string, vaultId: string) {
  const member = await db.prepare(
    "SELECT role FROM vault_members WHERE vault_id = ? AND did = ? AND removed_at IS NULL"
  ).bind(vaultId, did).first();
  if (!member) throw error(403, "Not a member of this vault");

  const row = await db.prepare(`
    SELECT id, name, content_type, labels_json, size, created_at, updated_at,
           wrapped_item_key, ciphertext, iv, mac
    FROM vault_items WHERE id = ? AND vault_id = ? AND deleted_at IS NULL
  `).bind(itemId, vaultId).first<{
    id: string; name: string; content_type: string | null; labels_json: string | null;
    size: number; created_at: string; updated_at: string;
    wrapped_item_key: string; ciphertext: string; iv: string; mac: string | null;
  }>();
  if (!row) throw error(404, "Item not found");

  await logAccess(db, did, "getItem", vaultId, itemId);
  return noStore({
    itemId: row.id, name: row.name,
    contentType: row.content_type ?? undefined,
    labels: row.labels_json ? JSON.parse(row.labels_json) as string[] : undefined,
    size: row.size, createdAt: row.created_at, updatedAt: row.updated_at,
    wrappedItemKey: row.wrapped_item_key, ciphertext: row.ciphertext,
    iv: row.iv, mac: row.mac ?? undefined,
  });
}

async function handleDeleteItem(db: D1Database, did: string, input: Record<string, unknown>) {
  const { itemId, vaultId } = input as { itemId: string; vaultId: string };
  if (!itemId || !vaultId) throw error(400, "itemId and vaultId required");

  const member = await db.prepare(
    "SELECT role FROM vault_members WHERE vault_id = ? AND did = ? AND removed_at IS NULL"
  ).bind(vaultId, did).first<{ role: string }>();
  if (!member) throw error(403, "Not a member of this vault");

  await db.prepare("UPDATE vault_items SET deleted_at = ? WHERE id = ? AND vault_id = ?")
    .bind(now(), itemId, vaultId).run();

  await logAccess(db, did, "deleteItem", vaultId, itemId);
  return noStore({ ok: true });
}

// ── Dispatcher ───────────────────────────────────────────────────────────────

export const POST: RequestHandler = async (event) => {
  const env = (event.platform as { env?: Env } | undefined)?.env ?? {};
  const db = env.VAULT_DB;
  if (!db) return noStore({ error: "Database not configured" }, { status: 503 });

  const did = await getCallerDid(event.request, env);
  if (!did) return noStore({ error: "Unauthorized" }, { status: 401 });

  const nsid = event.params.nsid;
  let input: Record<string, unknown> = {};
  try { input = await event.request.json() as Record<string, unknown>; } catch { /* empty body ok */ }

  switch (nsid) {
    case "com.etzhayyim.vault.createVault": return handleCreateVault(db, did, input);
    case "com.etzhayyim.vault.putItem":     return handlePutItem(db, did, input);
    case "com.etzhayyim.vault.deleteItem":  return handleDeleteItem(db, did, input);
    default: return noStore({ error: `Unknown method: ${nsid}` }, { status: 404 });
  }
};

export const GET: RequestHandler = async (event) => {
  const env = (event.platform as { env?: Env } | undefined)?.env ?? {};
  const db = env.VAULT_DB;
  if (!db) return noStore({ error: "Database not configured" }, { status: 503 });

  const did = await getCallerDid(event.request, env);
  if (!did) return noStore({ error: "Unauthorized" }, { status: 401 });

  const nsid = event.params.nsid;
  const p = event.url.searchParams;

  switch (nsid) {
    case "com.etzhayyim.vault.listVaults":  return handleListVaults(db, did);
    case "com.etzhayyim.vault.listItems":   return handleListItems(db, did, p.get("vaultId") ?? "");
    case "com.etzhayyim.vault.getItem":     return handleGetItem(db, did, p.get("itemId") ?? "", p.get("vaultId") ?? "");
    default: return noStore({ error: `Unknown method: ${nsid}` }, { status: 404 });
  }
};

export const OPTIONS: RequestHandler = async () =>
  new Response(null, {
    status: 204,
    headers: {
      "access-control-allow-origin": "https://vault.etzhayyim.com",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": "content-type",
    },
  });
