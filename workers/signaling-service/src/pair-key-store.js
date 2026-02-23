const DEFAULT_MAX_REDEEMS = 6;
const MAX_MAX_REDEEMS = 32;

function json(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

async function readJsonBody(request) {
  try {
    const body = await request.json();
    if (body && typeof body === "object" && !Array.isArray(body)) {
      return body;
    }
    return {};
  } catch {
    return {};
  }
}

function normalizePairKey(value) {
  return String(value || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
}

function parsePositiveInt(value, fallback) {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) {
    return fallback;
  }
  return Math.floor(num);
}

function pickOwnerClaims(rawClaims) {
  const claims = rawClaims && typeof rawClaims === "object" ? rawClaims : {};
  return {
    sub: String(claims.sub || "").trim(),
    provider: String(claims.provider || "pair_key").trim() || "pair_key",
    email: String(claims.email || "").trim(),
    name: String(claims.name || "").trim(),
    picture: String(claims.picture || "").trim(),
    hd: String(claims.hd || "").trim(),
    username: String(claims.username || "").trim(),
  };
}

async function sha256Hex(value) {
  const data = new TextEncoder().encode(String(value || ""));
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function pairKeyRecordId(pairKeyNormalized) {
  const keyHash = await sha256Hex(`agent-huddle:pair-key:${pairKeyNormalized}`);
  return `pair-key:${keyHash}`;
}

export class PairKeyStore {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/issue") {
      const body = await readJsonBody(request);
      const normalized = normalizePairKey(body.pairKey);
      if (normalized.length < 6) {
        return json({ error: "invalid-pair-key" }, 400);
      }

      const expiresAtMs = Number(body.expiresAtMs);
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
        return json({ error: "invalid-expiry" }, 400);
      }

      const ownerClaims = pickOwnerClaims(body.ownerClaims);
      if (!ownerClaims.sub) {
        return json({ error: "missing-owner-sub" }, 400);
      }

      const requestedMaxRedeems = parsePositiveInt(body.maxRedeems, DEFAULT_MAX_REDEEMS);
      const maxRedeems = Math.max(1, Math.min(MAX_MAX_REDEEMS, requestedMaxRedeems));
      const recordId = await pairKeyRecordId(normalized);

      const record = {
        version: 1,
        normalized,
        ownerClaims,
        issuedAtMs: Date.now(),
        expiresAtMs,
        redeemCount: 0,
        maxRedeems,
        lastRedeemedAtMs: null,
      };

      await this.state.storage.put(recordId, record);
      return json({
        ok: true,
        expiresAt: new Date(expiresAtMs).toISOString(),
        maxRedeems,
      });
    }

    if (request.method === "POST" && url.pathname === "/redeem") {
      const body = await readJsonBody(request);
      const normalized = normalizePairKey(body.pairKey);
      if (normalized.length < 6) {
        return json({ error: "invalid-pair-key" }, 400);
      }

      const recordId = await pairKeyRecordId(normalized);
      const record = await this.state.storage.get(recordId);
      if (!record || typeof record !== "object") {
        return json({ error: "pair-key-not-found" }, 404);
      }

      const nowMs = Date.now();
      const expiresAtMs = Number(record.expiresAtMs || 0);
      if (!Number.isFinite(expiresAtMs) || nowMs >= expiresAtMs) {
        await this.state.storage.delete(recordId);
        return json({ error: "pair-key-expired" }, 410);
      }

      const maxRedeems = parsePositiveInt(record.maxRedeems, DEFAULT_MAX_REDEEMS);
      const redeemCount = parsePositiveInt(record.redeemCount, 0);
      if (redeemCount >= maxRedeems) {
        return json({ error: "pair-key-redeem-limit-reached" }, 429);
      }

      const updated = {
        ...record,
        redeemCount: redeemCount + 1,
        lastRedeemedAtMs: nowMs,
      };
      await this.state.storage.put(recordId, updated);

      return json({
        ok: true,
        expiresAt: new Date(expiresAtMs).toISOString(),
        expiresInSec: Math.max(1, Math.floor((expiresAtMs - nowMs) / 1000)),
        redeemCount: updated.redeemCount,
        maxRedeems,
        ownerClaims: pickOwnerClaims(updated.ownerClaims),
      });
    }

    return json({ error: "not-found" }, 404);
  }
}
