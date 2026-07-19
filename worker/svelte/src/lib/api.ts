// XRPC client for vault operations.

export interface VaultInfo {
  vaultId: string;
  name: string;
  description?: string;
  createdAt: string;
  role: string;
}

export interface VaultItem {
  itemId: string;
  name: string;
  contentType?: string;
  labels?: string[];
  size: number;
  createdAt: string;
  updatedAt: string;
  wrappedItemKey?: string;
  ciphertext?: string;
  iv?: string;
  mac?: string;
}

async function xrpc<T>(method: string, body: unknown): Promise<T> {
  const r = await fetch(`/xrpc/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({ error: r.statusText })) as { error?: string };
    throw new Error(err.error ?? r.statusText);
  }
  return r.json() as Promise<T>;
}

async function xrpcGet<T>(method: string, params: Record<string, string>): Promise<T> {
  const qs = new URLSearchParams(params).toString();
  const r = await fetch(`/xrpc/${method}${qs ? "?" + qs : ""}`, {
    credentials: "include",
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({ error: r.statusText })) as { error?: string };
    throw new Error(err.error ?? r.statusText);
  }
  return r.json() as Promise<T>;
}

export function createVault(args: {
  name: string;
  description?: string;
  wrappedVaultKey: string;
  memberDeviceKeyId: string;
}) {
  return xrpc<{ vaultId: string; createdAt: string }>("com.etzhayyim.vault.createVault", args);
}

export function listVaults() {
  return xrpcGet<{ vaults: VaultInfo[] }>("com.etzhayyim.vault.listVaults", {});
}

export function putItem(args: {
  vaultId: string;
  itemName: string;
  wrappedItemKey: string;
  ciphertext: string;
  iv: string;
  mac?: string;
  contentType?: string;
  labels?: string[];
}) {
  return xrpc<{ itemId: string; createdAt: string; size: number }>("com.etzhayyim.vault.putItem", args);
}

export function listItems(vaultId: string) {
  return xrpcGet<{ items: VaultItem[] }>("com.etzhayyim.vault.listItems", { vaultId });
}

export function getItem(itemId: string, vaultId: string) {
  return xrpcGet<VaultItem & { wrappedItemKey: string; ciphertext: string; iv: string }>(
    "com.etzhayyim.vault.getItem", { itemId, vaultId }
  );
}

export function deleteItem(args: { itemId: string; vaultId: string }) {
  return xrpc<{ ok: boolean }>("com.etzhayyim.vault.deleteItem", args);
}
