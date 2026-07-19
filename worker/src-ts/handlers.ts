// handlers.ts — XRPC handler implementations for com.etzhayyim.vault.* (10 NSIDs).
//
// All ciphertext / wrapped keys are opaque blobs to the server; we never
// decrypt or inspect them. The server owns: schema, ACL (vault_members),
// audit (access_events). Storage is D1 only; individual ciphertext is
// hard-capped at MAX_CIPHERTEXT_BYTES (900KB) to stay safely under D1's
// effective ~1MB BLOB cell limit. Large file attachments are out of scope.

import type { Env } from "./index";
import { authenticate, requireVaultRole, AuthError } from "./auth";
import { audit } from "./audit";
import { nowISO, ulid, b64urlDecode, b64urlEncode, json, err } from "./util";

/** Upper bound on per-item ciphertext size stored inline in D1. */
const MAX_CIPHERTEXT_BYTES = 900_000;

// ── createVault ──────────────────────────────────────────────────────────────

export async function handleCreateVault(req: Request, env: Env): Promise<Response> {
  const caller = await authenticate(req, env);
  const body = (await req.json()) as {
    name?: string;
    description?: string;
    wrappedVaultKey?: string;
    memberDeviceKeyId?: string;
  };
  if (!body.name || !body.wrappedVaultKey || !body.memberDeviceKeyId) {
    return err(400, "InvalidRequest", "name, wrappedVaultKey, memberDeviceKeyId required");
  }
  const vaultId = ulid();
  const ts = nowISO();
  const db = env.VAULT_DB;
  await db.batch([
    db.prepare(
      `INSERT INTO vaults (id, name, description, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(vaultId, body.name, body.description ?? null, caller.did, ts, ts),
    db.prepare(
      `INSERT INTO vault_members (vault_id, did, wrapped_vault_key, member_device_key_id, role, added_by, added_at)
       VALUES (?, ?, ?, ?, 'owner', ?, ?)`,
    ).bind(vaultId, caller.did, body.wrappedVaultKey, body.memberDeviceKeyId, caller.did, ts),
  ]);
  await audit(db, caller, "createVault", vaultId, null);
  return json({ vaultId, createdAt: ts });
}

// ── listVaults ───────────────────────────────────────────────────────────────

export async function handleListVaults(req: Request, env: Env): Promise<Response> {
  const caller = await authenticate(req, env);
  const url = new URL(req.url);
  const limit = clampInt(url.searchParams.get("limit"), 1, 200, 50);
  const offset = clampInt(url.searchParams.get("offset"), 0, 1_000_000, 0);
  const db = env.VAULT_DB;

  const totalRow = await db
    .prepare(
      `SELECT COUNT(*) AS c
       FROM vault_members vm JOIN vaults v ON v.id = vm.vault_id
       WHERE vm.did = ? AND vm.removed_at IS NULL AND v.deleted_at IS NULL`,
    )
    .bind(caller.did)
    .first<{ c: number }>();
  const total = totalRow?.c ?? 0;

  const rows = await db
    .prepare(
      `SELECT v.id AS vault_id, v.name, v.description, vm.wrapped_vault_key, vm.member_device_key_id, vm.role, v.created_at,
              (SELECT COUNT(*) FROM vault_members WHERE vault_id = v.id AND removed_at IS NULL) AS member_count,
              (SELECT COUNT(*) FROM vault_items WHERE vault_id = v.id AND deleted_at IS NULL) AS item_count
       FROM vault_members vm JOIN vaults v ON v.id = vm.vault_id
       WHERE vm.did = ? AND vm.removed_at IS NULL AND v.deleted_at IS NULL
       ORDER BY v.updated_at DESC
       LIMIT ? OFFSET ?`,
    )
    .bind(caller.did, limit, offset)
    .all<{
      vault_id: string; name: string; description: string | null;
      wrapped_vault_key: string; member_device_key_id: string;
      role: string; created_at: string; member_count: number; item_count: number;
    }>();

  const vaults = (rows.results ?? []).map((r) => ({
    vaultId: r.vault_id,
    name: r.name,
    description: r.description ?? "",
    wrappedVaultKey: r.wrapped_vault_key,
    memberDeviceKeyId: r.member_device_key_id,
    role: r.role,
    memberCount: r.member_count,
    itemCount: r.item_count,
    createdAt: r.created_at,
  }));
  return json({ vaults, total, limit, offset });
}

// ── putItem ──────────────────────────────────────────────────────────────────

export async function handlePutItem(req: Request, env: Env): Promise<Response> {
  const caller = await authenticate(req, env);
  const body = (await req.json()) as {
    vaultId?: string; itemName?: string;
    wrappedItemKey?: string; ciphertext?: string;
    iv?: string; mac?: string; contentType?: string; labels?: string[];
  };
  if (!body.vaultId || !body.itemName || !body.wrappedItemKey || !body.iv || !body.ciphertext) {
    return err(400, "InvalidRequest", "vaultId, itemName, wrappedItemKey, iv, ciphertext required");
  }
  await requireVaultRole(env.VAULT_DB, caller, body.vaultId, ["owner", "admin", "reader"]);

  const ciphertextBlob = b64urlDecode(body.ciphertext);
  if (ciphertextBlob.length > MAX_CIPHERTEXT_BYTES) {
    return err(
      413, "ItemTooLarge",
      `ciphertext ${ciphertextBlob.length} bytes exceeds MAX_CIPHERTEXT_BYTES (${MAX_CIPHERTEXT_BYTES}). Split the secret into multiple items or store large files elsewhere.`,
    );
  }
  const size = ciphertextBlob.length;

  // Upsert by (vault_id, name) — soft-delete previous version if present.
  const ts = nowISO();
  const itemId = ulid();
  const labelsJson = body.labels ? JSON.stringify(body.labels) : null;
  const db = env.VAULT_DB;

  // Mark any existing live item with same name as deleted (atomic via batch).
  await db.batch([
    db.prepare(
      `UPDATE vault_items SET deleted_at = ? WHERE vault_id = ? AND name = ? AND deleted_at IS NULL`,
    ).bind(ts, body.vaultId, body.itemName),
    db.prepare(
      `INSERT INTO vault_items
         (id, vault_id, name, wrapped_item_key, ciphertext, iv, mac, content_type, labels_json, size, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      itemId, body.vaultId, body.itemName, body.wrappedItemKey,
      ciphertextBlob, body.iv, body.mac ?? null,
      body.contentType ?? null, labelsJson, size, caller.did, ts, ts,
    ),
  ]);
  await audit(db, caller, "putItem", body.vaultId, itemId);
  return json({ itemId, createdAt: ts, size });
}

// ── getItem ──────────────────────────────────────────────────────────────────

export async function handleGetItem(req: Request, env: Env): Promise<Response> {
  const caller = await authenticate(req, env);
  const url = new URL(req.url);
  const vaultId = url.searchParams.get("vaultId") ?? "";
  const itemId = url.searchParams.get("itemId");
  const itemName = url.searchParams.get("itemName");
  if (!vaultId || (!itemId && !itemName)) {
    return err(400, "InvalidRequest", "vaultId required; one of itemId|itemName required");
  }
  await requireVaultRole(env.VAULT_DB, caller, vaultId, ["owner", "admin", "reader"]);

  const db = env.VAULT_DB;
  const itemRow = itemId
    ? await db.prepare(
        `SELECT id, name, wrapped_item_key, ciphertext, iv, mac, content_type, labels_json, created_at, updated_at
         FROM vault_items WHERE id = ? AND vault_id = ? AND deleted_at IS NULL LIMIT 1`,
      ).bind(itemId, vaultId).first()
    : await db.prepare(
        `SELECT id, name, wrapped_item_key, ciphertext, iv, mac, content_type, labels_json, created_at, updated_at
         FROM vault_items WHERE name = ? AND vault_id = ? AND deleted_at IS NULL LIMIT 1`,
      ).bind(itemName, vaultId).first();
  if (!itemRow) return err(404, "ItemNotFound", "vault item not found");
  const item = itemRow as Record<string, unknown>;

  const memberRow = await db
    .prepare(
      `SELECT wrapped_vault_key FROM vault_members WHERE vault_id = ? AND did = ? AND removed_at IS NULL LIMIT 1`,
    )
    .bind(vaultId, caller.did)
    .first<{ wrapped_vault_key: string }>();
  // requireVaultRole already ensured membership; defensive null-check only.
  if (!memberRow) return err(403, "VaultAccessDenied", "membership lost between checks");

  // Materialise inline ciphertext (BLOB → b64url) or pass through CID ref.
  let ciphertextB64: string | undefined;
  if (item.ciphertext != null) {
    const buf = item.ciphertext instanceof ArrayBuffer
      ? new Uint8Array(item.ciphertext)
      : new Uint8Array(item.ciphertext as ArrayBufferLike);
    ciphertextB64 = b64urlEncode(buf);
  }

  await audit(db, caller, "getItem", vaultId, item.id as string);
  return json({
    itemId: item.id,
    itemName: item.name,
    wrappedItemKey: item.wrapped_item_key,
    wrappedVaultKey: memberRow.wrapped_vault_key,
    ciphertext: ciphertextB64,
    iv: item.iv,
    mac: item.mac ?? undefined,
    contentType: item.content_type ?? undefined,
    labels: item.labels_json ? JSON.parse(item.labels_json as string) : [],
    createdAt: item.created_at,
    updatedAt: item.updated_at,
  });
}

// ── listItems ────────────────────────────────────────────────────────────────

export async function handleListItems(req: Request, env: Env): Promise<Response> {
  const caller = await authenticate(req, env);
  const url = new URL(req.url);
  const vaultId = url.searchParams.get("vaultId") ?? "";
  if (!vaultId) return err(400, "InvalidRequest", "vaultId required");
  const limit = clampInt(url.searchParams.get("limit"), 1, 500, 100);
  const offset = clampInt(url.searchParams.get("offset"), 0, 1_000_000, 0);
  const labelFilter = url.searchParams.get("labelFilter");
  await requireVaultRole(env.VAULT_DB, caller, vaultId, ["owner", "admin", "reader"]);

  const db = env.VAULT_DB;
  const totalRow = await db
    .prepare(`SELECT COUNT(*) AS c FROM vault_items WHERE vault_id = ? AND deleted_at IS NULL`)
    .bind(vaultId)
    .first<{ c: number }>();
  const total = totalRow?.c ?? 0;

  const rows = await db
    .prepare(
      `SELECT id, name, content_type, labels_json, size, created_at, updated_at
       FROM vault_items WHERE vault_id = ? AND deleted_at IS NULL
       ORDER BY name ASC LIMIT ? OFFSET ?`,
    )
    .bind(vaultId, limit, offset)
    .all<{
      id: string; name: string; content_type: string | null;
      labels_json: string | null; size: number;
      created_at: string; updated_at: string;
    }>();

  let items = (rows.results ?? []).map((r) => ({
    itemId: r.id,
    itemName: r.name,
    contentType: r.content_type ?? "",
    labels: r.labels_json ? (JSON.parse(r.labels_json) as string[]) : [],
    size: r.size,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  }));
  if (labelFilter) items = items.filter((i) => i.labels.includes(labelFilter));
  await audit(db, caller, "listItems", vaultId, null);
  return json({ items, total, limit, offset });
}

// ── deleteItem ───────────────────────────────────────────────────────────────

export async function handleDeleteItem(req: Request, env: Env): Promise<Response> {
  const caller = await authenticate(req, env);
  const body = (await req.json()) as { vaultId?: string; itemId?: string };
  if (!body.vaultId || !body.itemId) return err(400, "InvalidRequest", "vaultId, itemId required");
  await requireVaultRole(env.VAULT_DB, caller, body.vaultId, ["owner", "admin"]);

  const ts = nowISO();
  const db = env.VAULT_DB;
  const result = await db
    .prepare(`UPDATE vault_items SET deleted_at = ? WHERE id = ? AND vault_id = ? AND deleted_at IS NULL`)
    .bind(ts, body.itemId, body.vaultId)
    .run();
  if ((result.meta?.changes ?? 0) === 0) return err(404, "ItemNotFound", "vault item not found");
  await audit(db, caller, "deleteItem", body.vaultId, body.itemId);
  return json({ deleted: true, deletedAt: ts });
}

// ── addMember ────────────────────────────────────────────────────────────────

export async function handleAddMember(req: Request, env: Env): Promise<Response> {
  const caller = await authenticate(req, env);
  const body = (await req.json()) as {
    vaultId?: string; memberDid?: string;
    wrappedVaultKey?: string; memberDeviceKeyId?: string; role?: string;
  };
  if (!body.vaultId || !body.memberDid || !body.wrappedVaultKey || !body.memberDeviceKeyId) {
    return err(400, "InvalidRequest", "vaultId, memberDid, wrappedVaultKey, memberDeviceKeyId required");
  }
  await requireVaultRole(env.VAULT_DB, caller, body.vaultId, ["owner", "admin"]);
  const role = body.role && ["owner", "admin", "reader"].includes(body.role) ? body.role : "reader";

  const ts = nowISO();
  const db = env.VAULT_DB;
  await db
    .prepare(
      `INSERT INTO vault_members (vault_id, did, wrapped_vault_key, member_device_key_id, role, added_by, added_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(vault_id, did) DO UPDATE SET
         wrapped_vault_key = excluded.wrapped_vault_key,
         member_device_key_id = excluded.member_device_key_id,
         role = excluded.role,
         removed_at = NULL,
         added_by = excluded.added_by,
         added_at = excluded.added_at`,
    )
    .bind(body.vaultId, body.memberDid, body.wrappedVaultKey, body.memberDeviceKeyId, role, caller.did, ts)
    .run();
  await audit(db, caller, "addMember", body.vaultId, null);
  return json({ memberId: `${body.vaultId}:${body.memberDid}`, addedAt: ts });
}

// ── removeMember ─────────────────────────────────────────────────────────────

export async function handleRemoveMember(req: Request, env: Env): Promise<Response> {
  const caller = await authenticate(req, env);
  const body = (await req.json()) as { vaultId?: string; memberDid?: string };
  if (!body.vaultId || !body.memberDid) return err(400, "InvalidRequest", "vaultId, memberDid required");
  await requireVaultRole(env.VAULT_DB, caller, body.vaultId, ["owner", "admin"]);

  // Disallow removing the last owner.
  const owners = await env.VAULT_DB
    .prepare(`SELECT COUNT(*) AS c FROM vault_members WHERE vault_id = ? AND role = 'owner' AND removed_at IS NULL`)
    .bind(body.vaultId)
    .first<{ c: number }>();
  const target = await env.VAULT_DB
    .prepare(`SELECT role FROM vault_members WHERE vault_id = ? AND did = ? AND removed_at IS NULL`)
    .bind(body.vaultId, body.memberDid)
    .first<{ role: string }>();
  if (target?.role === "owner" && (owners?.c ?? 0) <= 1) {
    return err(409, "LastOwner", "cannot remove last owner");
  }

  const ts = nowISO();
  const db = env.VAULT_DB;
  const result = await db
    .prepare(`UPDATE vault_members SET removed_at = ? WHERE vault_id = ? AND did = ? AND removed_at IS NULL`)
    .bind(ts, body.vaultId, body.memberDid)
    .run();
  if ((result.meta?.changes ?? 0) === 0) return err(404, "MemberNotFound", "member not found");

  const itemCountRow = await db
    .prepare(`SELECT COUNT(*) AS c FROM vault_items WHERE vault_id = ? AND deleted_at IS NULL`)
    .bind(body.vaultId)
    .first<{ c: number }>();
  await audit(db, caller, "removeMember", body.vaultId, null);
  return json({
    removed: true,
    removedAt: ts,
    rotationRecommended: (itemCountRow?.c ?? 0) > 0,
  });
}

// ── rotateVaultKey ───────────────────────────────────────────────────────────

export async function handleRotateVaultKey(req: Request, env: Env): Promise<Response> {
  const caller = await authenticate(req, env);
  const body = (await req.json()) as {
    vaultId?: string;
    newWrappedVaultKeys?: { memberDid: string; wrappedVaultKey: string; memberDeviceKeyId: string }[];
    rewrappedItemKeys?: { itemId: string; wrappedItemKey: string }[];
  };
  if (!body.vaultId || !Array.isArray(body.newWrappedVaultKeys) || !Array.isArray(body.rewrappedItemKeys)) {
    return err(400, "InvalidRequest", "vaultId, newWrappedVaultKeys[], rewrappedItemKeys[] required");
  }
  await requireVaultRole(env.VAULT_DB, caller, body.vaultId, ["owner", "admin"]);

  const ts = nowISO();
  const db = env.VAULT_DB;
  const stmts: D1PreparedStatement[] = [];
  for (const m of body.newWrappedVaultKeys) {
    if (!m.memberDid || !m.wrappedVaultKey || !m.memberDeviceKeyId) {
      return err(400, "InvalidRequest", "each newWrappedVaultKey entry needs memberDid + wrappedVaultKey + memberDeviceKeyId");
    }
    stmts.push(
      db.prepare(
        `UPDATE vault_members
           SET wrapped_vault_key = ?, member_device_key_id = ?
         WHERE vault_id = ? AND did = ? AND removed_at IS NULL`,
      ).bind(m.wrappedVaultKey, m.memberDeviceKeyId, body.vaultId, m.memberDid),
    );
  }
  for (const it of body.rewrappedItemKeys) {
    if (!it.itemId || !it.wrappedItemKey) {
      return err(400, "InvalidRequest", "each rewrappedItemKey entry needs itemId + wrappedItemKey");
    }
    stmts.push(
      db.prepare(
        `UPDATE vault_items SET wrapped_item_key = ?, updated_at = ?
         WHERE id = ? AND vault_id = ? AND deleted_at IS NULL`,
      ).bind(it.wrappedItemKey, ts, it.itemId, body.vaultId),
    );
  }
  if (stmts.length > 0) await db.batch(stmts);
  await audit(db, caller, "rotateVaultKey", body.vaultId, null);
  return json({
    rotated: true,
    rotatedAt: ts,
    memberCount: body.newWrappedVaultKeys.length,
    itemCount: body.rewrappedItemKeys.length,
  });
}

// ── listAccessEvents ─────────────────────────────────────────────────────────

export async function handleListAccessEvents(req: Request, env: Env): Promise<Response> {
  const caller = await authenticate(req, env);
  const url = new URL(req.url);
  const vaultId = url.searchParams.get("vaultId") ?? "";
  if (!vaultId) return err(400, "InvalidRequest", "vaultId required");
  await requireVaultRole(env.VAULT_DB, caller, vaultId, ["owner", "admin"]);
  const itemId = url.searchParams.get("itemId");
  const since = url.searchParams.get("since");
  const limit = clampInt(url.searchParams.get("limit"), 1, 500, 100);
  const offset = clampInt(url.searchParams.get("offset"), 0, 1_000_000, 0);

  const conds: string[] = ["vault_id = ?"];
  const binds: unknown[] = [vaultId];
  if (itemId) { conds.push("item_id = ?"); binds.push(itemId); }
  if (since)  { conds.push("ts >= ?");     binds.push(since); }

  const where = conds.join(" AND ");
  const db = env.VAULT_DB;
  const totalRow = await db.prepare(`SELECT COUNT(*) AS c FROM access_events WHERE ${where}`).bind(...binds).first<{ c: number }>();
  const total = totalRow?.c ?? 0;

  const rows = await db
    .prepare(`SELECT id, did, action, vault_id, item_id, ts, lxm, ip_hash FROM access_events WHERE ${where} ORDER BY ts DESC LIMIT ? OFFSET ?`)
    .bind(...binds, limit, offset)
    .all<{
      id: string; did: string; action: string; vault_id: string;
      item_id: string | null; ts: string; lxm: string | null; ip_hash: string;
    }>();

  const events = (rows.results ?? []).map((r) => ({
    eventId: r.id,
    did: r.did,
    action: r.action,
    vaultId: r.vault_id,
    itemId: r.item_id ?? undefined,
    ts: r.ts,
    lxm: r.lxm ?? undefined,
    ipHash: r.ip_hash,
  }));
  await audit(db, caller, "listAccessEvents", vaultId, null);
  return json({ events, total, limit, offset });
}

// ── injectWorkerSecret ───────────────────────────────────────────────────────

export async function handleInjectWorkerSecret(req: Request, env: Env): Promise<Response> {
  const caller = await authenticate(req, env);
  const body = (await req.json()) as {
    vaultId?: string; itemId?: string; workerName?: string;
    secretName?: string; ephemeralVaultKey?: string;
  };
  if (!body.vaultId || !body.itemId || !body.workerName || !body.secretName || !body.ephemeralVaultKey) {
    return err(400, "InvalidRequest", "vaultId, itemId, workerName, secretName, ephemeralVaultKey required");
  }
  await requireVaultRole(env.VAULT_DB, caller, body.vaultId, ["owner", "admin"]);

  const db = env.VAULT_DB;
  const item = await db
    .prepare(
      `SELECT wrapped_item_key, ciphertext, iv FROM vault_items
       WHERE id = ? AND vault_id = ? AND deleted_at IS NULL LIMIT 1`,
    )
    .bind(body.itemId, body.vaultId)
    .first<{ wrapped_item_key: string; ciphertext: ArrayBuffer | null; iv: string }>();
  if (!item) return err(404, "ItemNotFound", "vault item not found");

  // Server-side decrypt with caller-provided ephemeral vaultKey (zero-knowledge violation
  // is bounded: caller supplies the unwrapped key in this single request, server zeroizes after CF call).
  const vaultKeyRaw = b64urlDecode(body.ephemeralVaultKey);
  const vaultKey = await crypto.subtle.importKey(
    "raw", vaultKeyRaw, { name: "AES-KW" }, false, ["unwrapKey"],
  );
  const itemKeyWrapped = b64urlDecode(item.wrapped_item_key);
  const itemKey = await crypto.subtle.unwrapKey(
    "raw", itemKeyWrapped, vaultKey, { name: "AES-KW" },
    { name: "AES-GCM" }, false, ["decrypt"],
  );
  if (!item.ciphertext) return err(500, "ItemCorrupt", "item has no ciphertext");
  const ciphertextBuf = new Uint8Array(item.ciphertext);
  const iv = b64urlDecode(item.iv);
  const plaintextBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, itemKey, ciphertextBuf);
  const plaintext = new TextDecoder().decode(plaintextBuf);

  // Best-effort zeroization (JS doesn't guarantee, but at least drop refs).
  vaultKeyRaw.fill(0);

  // PUT to Cloudflare Worker secret via REST API.
  const cfToken = await env.CF_API_TOKEN.get();
  const cfAccount = await env.CF_ACCOUNT_ID.get();
  if (!cfToken || !cfAccount) {
    return err(503, "CFConfigMissing", "CF_API_TOKEN / CF_ACCOUNT_ID not configured");
  }
  const cfUrl = `https://api.cloudflare.com/client/v4/accounts/${cfAccount}/workers/scripts/${body.workerName}/secrets`;
  const cfRes = await fetch(cfUrl, {
    method: "PUT",
    headers: { "Authorization": `Bearer ${cfToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: body.secretName, text: plaintext, type: "secret_text" }),
  });

  await audit(db, caller, "injectWorkerSecret", body.vaultId, body.itemId);
  return json({
    injected: cfRes.ok,
    injectedAt: nowISO(),
    cfResponseStatus: cfRes.status,
  }, cfRes.ok ? 200 : 502);
}

// ── helpers ──────────────────────────────────────────────────────────────────

function clampInt(s: string | null, min: number, max: number, dflt: number): number {
  if (!s) return dflt;
  const n = parseInt(s, 10);
  if (isNaN(n)) return dflt;
  return Math.max(min, Math.min(max, n));
}

export { AuthError };
