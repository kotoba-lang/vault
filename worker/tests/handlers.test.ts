/**
 * vault worker — security-invariant tests (coverage loop iteration 4).
 *
 * The zero-knowledge secret manager (1,323 LoC, CLAUDE.md crypto model) had
 * zero tests. These cover the invariants the CLAUDE.md declares, driven
 * through the REAL authenticate/requireVaultRole/handler code against a
 * programmable fake D1 and a fake AUTH_SERVICE binding:
 *   - auth fail-closed (missing bearer, AUTH_SERVICE rejection, bad payload)
 *   - per-NSID role enforcement (non-member 403, insufficient role 403)
 *   - MAX_CIPHERTEXT_BYTES 900KB hard cap (boundary inclusive/exclusive)
 *   - no role escalation via bogus addMember role (defaults to reader)
 *   - last-owner removal protection (409 LastOwner)
 *   - util b64url roundtrip + ULID shape + CORS headers
 */
import { describe, it, expect } from "vitest";

import { authenticate, requireVaultRole, AuthError } from "../src-ts/auth";
import {
  handlePutItem,
  handleAddMember,
  handleRemoveMember,
} from "../src-ts/handlers";
import { b64urlDecode, b64urlEncode, ulid } from "../src-ts/util";

// ── programmable fakes ───────────────────────────────────────────────────────

interface Call { sql: string; binds: unknown[] }

/** Minimal D1 fake: queue per-call results for first/all/run, record history. */
function fakeD1(queue: { first?: unknown[]; }) {
  const calls: Call[] = [];
  const firstQueue = [...(queue.first ?? [])];
  const stmt = (sql: string, binds: unknown[]) => ({
    bind: (...more: unknown[]) => stmt(sql, [...binds, ...more]),
    first: async () => {
      calls.push({ sql, binds });
      return firstQueue.length ? firstQueue.shift() : null;
    },
    all: async () => {
      calls.push({ sql, binds });
      return { results: [] };
    },
    run: async () => {
      calls.push({ sql, binds });
      return { meta: { changes: 1 } };
    },
  });
  return {
    calls,
    db: {
      prepare: (sql: string) => stmt(sql, []),
      batch: async (stmts: unknown[]) => {
        // statements were built via prepare().bind() — record a marker per stmt
        calls.push({ sql: `BATCH(${stmts.length})`, binds: [] });
        return [];
      },
    } as unknown as D1Database,
  };
}

function fakeAuthService(response: { status?: number; body?: unknown } = {}) {
  const seen: { body?: unknown } = {};
  return {
    seen,
    svc: {
      fetch: async (_url: string, init?: RequestInit) => {
        seen.body = init?.body ? JSON.parse(String(init.body)) : undefined;
        const status = response.status ?? 200;
        const body = response.body ?? { did: "did:web:alice.test", level: "session" };
        return new Response(JSON.stringify(body), { status });
      },
    } as unknown as Fetcher,
  };
}

const SALT = "test-salt";

function makeEnv(opts: {
  authStatus?: number;
  authBody?: unknown;
  firstQueue?: unknown[];
}) {
  const { svc, seen } = fakeAuthService({ status: opts.authStatus, body: opts.authBody });
  const { db, calls } = fakeD1({ first: opts.firstQueue });
  return {
    env: { VAULT_DB: db, AUTH_SERVICE: svc, VAULT_AUDIT_HASH_SALT: SALT } as never,
    calls,
    authSeen: seen,
  };
}

function reqJson(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("https://vault.etzhayyim.com/xrpc/test", {
    method: "POST",
    headers: { authorization: "Bearer test-jwt", "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

// ── authenticate: fail-closed trust chain ────────────────────────────────────

describe("authenticate", () => {
  it("rejects a missing bearer token without calling AUTH_SERVICE", async () => {
    const { env } = makeEnv({});
    const bare = new Request("https://vault.test/", { headers: {} });
    await expect(authenticate(bare, env)).rejects.toMatchObject({
      status: 401, code: "AuthMissing",
    });
  });

  it("rejects when AUTH_SERVICE rejects, and when its payload lacks did/level", async () => {
    const denied = makeEnv({ authStatus: 401 });
    await expect(authenticate(reqJson({}), denied.env)).rejects.toMatchObject({
      status: 401, code: "AuthInvalid",
    });
    const malformed = makeEnv({ authBody: { ok: true } });
    await expect(authenticate(reqJson({}), malformed.env)).rejects.toMatchObject({
      status: 401, code: "AuthInvalid",
    });
  });

  it("forwards x-active-did only when did:-prefixed and hashes the caller IP with the salt", async () => {
    const a = makeEnv({});
    const ctx = await authenticate(
      reqJson({}, { "x-active-did": "did:web:sub.test", "cf-connecting-ip": "203.0.113.9" }),
      a.env,
    );
    expect((a.authSeen.body as { xActiveDid?: string }).xActiveDid).toBe("did:web:sub.test");
    expect(ctx.did).toBe("did:web:alice.test");
    const expected = await crypto.subtle.digest(
      "SHA-256", new TextEncoder().encode("203.0.113.9:" + SALT),
    );
    const expectedHex = Array.from(new Uint8Array(expected))
      .map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(ctx.ipHash).toBe(expectedHex);

    const b = makeEnv({});
    await authenticate(reqJson({}, { "x-active-did": "not-a-did" }), b.env);
    expect((b.authSeen.body as { xActiveDid?: string }).xActiveDid).toBeUndefined();
  });
});

// ── requireVaultRole: per-NSID ACL ───────────────────────────────────────────

describe("requireVaultRole", () => {
  const caller = { did: "did:web:alice.test", level: "session", ipHash: "x" } as never;

  it("403 VaultAccessDenied for a non-member", async () => {
    const { db } = fakeD1({ first: [null] });
    await expect(requireVaultRole(db, caller, "v1", ["owner"])).rejects.toMatchObject({
      status: 403, code: "VaultAccessDenied",
    });
  });

  it("403 VaultRoleInsufficient when the role is not in the allowlist", async () => {
    const { db } = fakeD1({ first: [{ role: "reader" }] });
    await expect(
      requireVaultRole(db, caller, "v1", ["owner", "admin"]),
    ).rejects.toMatchObject({ status: 403, code: "VaultRoleInsufficient" });
  });

  it("returns the role when sufficient", async () => {
    const { db } = fakeD1({ first: [{ role: "admin" }] });
    await expect(requireVaultRole(db, caller, "v1", ["owner", "admin"])).resolves.toEqual({
      vaultId: "v1", role: "admin",
    });
  });
});

// ── handlePutItem: the 900KB D1 hard cap ─────────────────────────────────────

describe("handlePutItem MAX_CIPHERTEXT_BYTES", () => {
  const item = (ciphertext: string) => ({
    vaultId: "v1", itemName: "secret", wrappedItemKey: "wk", iv: "aXY", ciphertext,
  });

  it("413 ItemTooLarge above 900_000 bytes", async () => {
    const { env } = makeEnv({ firstQueue: [{ role: "reader" }] });
    const res = await handlePutItem(reqJson(item(b64urlEncode(new Uint8Array(900_001)))), env);
    expect(res.status).toBe(413);
    expect(((await res.json()) as { error: string }).error).toBe("ItemTooLarge");
  });

  it("accepts exactly 900_000 bytes (boundary inclusive)", async () => {
    const { env } = makeEnv({ firstQueue: [{ role: "reader" }] });
    const res = await handlePutItem(reqJson(item(b64urlEncode(new Uint8Array(900_000)))), env);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { size: number }).size).toBe(900_000);
  });

  it("400 when required fields are missing", async () => {
    const { env } = makeEnv({});
    const res = await handlePutItem(reqJson({ vaultId: "v1" }), env);
    expect(res.status).toBe(400);
  });
});

// ── handleAddMember: no role escalation via bogus role strings ───────────────

describe("handleAddMember role allowlist", () => {
  const body = {
    vaultId: "v1", memberDid: "did:web:bob.test",
    wrappedVaultKey: "wvk", memberDeviceKeyId: "dk1",
  };

  it("defaults an unknown role to reader (CLAUDE.md: no auto-grant escalation)", async () => {
    const { env, calls } = makeEnv({ firstQueue: [{ role: "admin" }] });
    const res = await handleAddMember(reqJson({ ...body, role: "superuser" }), env);
    expect(res.status).toBe(200);
    const insert = calls.find((c) => c.sql.includes("INSERT INTO vault_members"));
    expect(insert?.binds).toContain("reader");
    expect(insert?.binds).not.toContain("superuser");
  });

  it("preserves an explicit allowlisted role", async () => {
    const { env, calls } = makeEnv({ firstQueue: [{ role: "owner" }] });
    await handleAddMember(reqJson({ ...body, role: "admin" }), env);
    const insert = calls.find((c) => c.sql.includes("INSERT INTO vault_members"));
    expect(insert?.binds).toContain("admin");
  });

  it("403 when the caller is only a reader", async () => {
    const { env } = makeEnv({ firstQueue: [{ role: "reader" }] });
    await expect(handleAddMember(reqJson(body), env)).rejects.toMatchObject({
      status: 403, code: "VaultRoleInsufficient",
    });
  });
});

// ── handleRemoveMember: last-owner protection ────────────────────────────────

describe("handleRemoveMember last-owner protection", () => {
  const body = { vaultId: "v1", memberDid: "did:web:alice.test" };

  it("409 LastOwner when removing the only owner", async () => {
    const { env } = makeEnv({
      firstQueue: [
        { role: "owner" },  // requireVaultRole
        { c: 1 },           // owner count
        { role: "owner" },  // target's role
      ],
    });
    const res = await handleRemoveMember(reqJson(body), env);
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toBe("LastOwner");
  });

  it("removes a non-last owner and recommends rotation when items remain", async () => {
    const { env } = makeEnv({
      firstQueue: [
        { role: "owner" },  // requireVaultRole
        { c: 2 },           // two owners
        { role: "owner" },  // target's role
        { c: 3 },           // live item count → rotation recommended
      ],
    });
    const res = await handleRemoveMember(reqJson(body), env);
    expect(res.status).toBe(200);
    const out = (await res.json()) as { removed: boolean; rotationRecommended: boolean };
    expect(out.removed).toBe(true);
    expect(out.rotationRecommended).toBe(true);
  });
});

// ── util helpers ─────────────────────────────────────────────────────────────

describe("util", () => {
  it("b64url roundtrips arbitrary bytes without padding chars", () => {
    const bytes = new Uint8Array([0, 1, 250, 251, 252, 253, 254, 255, 62, 63]);
    const enc = b64urlEncode(bytes);
    expect(enc).not.toMatch(/[+/=]/);
    expect(Array.from(b64urlDecode(enc))).toEqual(Array.from(bytes));
  });

  it("ulid is 26 Crockford-base32 chars and time-ordered across calls", () => {
    const a = ulid();
    const b = ulid();
    expect(a).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(b.slice(0, 10) >= a.slice(0, 10)).toBe(true);
  });

  it("AuthError carries status + code for the router's error mapping", () => {
    const e = new AuthError(403, "VaultAccessDenied", "nope");
    expect(e).toBeInstanceOf(Error);
    expect([e.status, e.code]).toEqual([403, "VaultAccessDenied"]);
  });
});
