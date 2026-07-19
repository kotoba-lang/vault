// vault.etzhayyim.com — Cloudflare Worker entry point.
//
// Zero-knowledge secret manager. All ciphertext + wrapped keys are opaque to
// this Worker; client (etzhayyim CLI / browser) handles AES-GCM + AES-key-wrap.
// Identity is delegated to AUTH_SERVICE (auth.etzhayyim.com).
//
// Routes (XRPC):
//   POST /xrpc/com.etzhayyim.vault.createVault
//   GET  /xrpc/com.etzhayyim.vault.listVaults
//   POST /xrpc/com.etzhayyim.vault.putItem
//   GET  /xrpc/com.etzhayyim.vault.getItem
//   GET  /xrpc/com.etzhayyim.vault.listItems
//   POST /xrpc/com.etzhayyim.vault.deleteItem
//   POST /xrpc/com.etzhayyim.vault.addMember
//   POST /xrpc/com.etzhayyim.vault.removeMember
//   POST /xrpc/com.etzhayyim.vault.rotateVaultKey
//   GET  /xrpc/com.etzhayyim.vault.listAccessEvents
//   POST /xrpc/com.etzhayyim.vault.injectWorkerSecret
//
// Health: GET /health

import { AuthError } from "./auth";
import { err } from "./util";
import {
  handleCreateVault, handleListVaults,
  handlePutItem, handleGetItem, handleListItems, handleDeleteItem,
  handleAddMember, handleRemoveMember, handleRotateVaultKey,
  handleListAccessEvents, handleInjectWorkerSecret,
} from "./handlers";

export interface Env {
  VAULT_DB: D1Database;
  AUTH_SERVICE: Fetcher;
  VAULT_AUDIT_HASH_SALT: string;
  CF_API_TOKEN: { get(): Promise<string | null> };
  CF_ACCOUNT_ID: { get(): Promise<string | null> };
}

interface RouteEntry {
  method: "GET" | "POST";
  handler: (req: Request, env: Env) => Promise<Response>;
}

const ROUTES: Record<string, RouteEntry> = {
  "/xrpc/com.etzhayyim.vault.createVault":        { method: "POST", handler: handleCreateVault },
  "/xrpc/com.etzhayyim.vault.listVaults":         { method: "GET",  handler: handleListVaults },
  "/xrpc/com.etzhayyim.vault.putItem":            { method: "POST", handler: handlePutItem },
  "/xrpc/com.etzhayyim.vault.getItem":            { method: "GET",  handler: handleGetItem },
  "/xrpc/com.etzhayyim.vault.listItems":          { method: "GET",  handler: handleListItems },
  "/xrpc/com.etzhayyim.vault.deleteItem":         { method: "POST", handler: handleDeleteItem },
  "/xrpc/com.etzhayyim.vault.addMember":          { method: "POST", handler: handleAddMember },
  "/xrpc/com.etzhayyim.vault.removeMember":       { method: "POST", handler: handleRemoveMember },
  "/xrpc/com.etzhayyim.vault.rotateVaultKey":     { method: "POST", handler: handleRotateVaultKey },
  "/xrpc/com.etzhayyim.vault.listAccessEvents":   { method: "GET",  handler: handleListAccessEvents },
  "/xrpc/com.etzhayyim.vault.injectWorkerSecret": { method: "POST", handler: handleInjectWorkerSecret },
};

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const { pathname } = url;
    const method = req.method;

    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Active-DID",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    if (method === "GET" && pathname === "/health") {
      return new Response("ok", { status: 200 });
    }

    const route = ROUTES[pathname];
    if (!route) return err(404, "NotFound", `unknown route: ${method} ${pathname}`);
    if (route.method !== method) return err(405, "MethodNotAllowed", `${pathname} requires ${route.method}`);

    try {
      return await route.handler(req, env);
    } catch (e) {
      if (e instanceof AuthError) return err(e.status, e.code, e.message);
      console.error(`vault handler error ${pathname}:`, e);
      const msg = e instanceof Error ? e.message : String(e);
      return err(500, "InternalError", msg);
    }
  },
};
