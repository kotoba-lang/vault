// audit.ts — append-only access_events writer.

import { nowISO, ulid } from "./util";
import type { CallerCtx } from "./auth";

export type AuditAction =
  | "createVault"
  | "putItem"
  | "getItem"
  | "deleteItem"
  | "addMember"
  | "removeMember"
  | "rotateVaultKey"
  | "injectWorkerSecret"
  | "listItems"
  | "listVaults"
  | "listAccessEvents";

export async function audit(
  db: D1Database,
  caller: CallerCtx,
  action: AuditAction,
  vaultId: string,
  itemId: string | null,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO access_events (id, did, action, vault_id, item_id, ts, lxm, ip_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(ulid(), caller.did, action, vaultId, itemId, nowISO(), caller.lxm ?? null, caller.ipHash)
    .run();
}
