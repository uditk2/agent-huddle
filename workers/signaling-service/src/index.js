import { renderPairingFlowSvg } from "./pairing-flow-svg.js";
import { PairKeyStore } from "./pair-key-store.js";

const DEFAULT_SESSION_TTL_SEC = 60 * 60;
const DEFAULT_TURN_TTL_SEC = 10 * 60;
const DEFAULT_PAIR_KEY_TTL_SEC = 10 * 60;
const DEFAULT_PAIR_KEY_MAX_REDEEMS = 6;
const GOOGLE_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo";
const GOOGLE_TOKEN_EXCHANGE_URL = "https://oauth2.googleapis.com/token";
const GITHUB_USER_API_URL = "https://api.github.com/user";
const GITHUB_USER_EMAILS_API_URL = "https://api.github.com/user/emails";
const GITHUB_REPO_URL = "https://github.com/uditk2/agent-huddle";

export { PairKeyStore };

export class SignalingRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.peers = new Map();
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname !== "/connect") {
      return json({ error: "not-found" }, 404);
    }

    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return json({ error: "websocket-upgrade-required" }, 426);
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();

    const requestedPeerId = sanitizePeerId(url.searchParams.get("peerId"));
    const peerId = requestedPeerId || makeShortId();

    if (this.peers.has(peerId)) {
      this.send(server, { type: "error", error: "peer-id-in-use" });
      server.close(1008, "peer-id-in-use");
      return new Response(null, { status: 101, webSocket: client });
    }

    this.peers.set(peerId, server);

    this.send(server, {
      type: "welcome",
      peerId,
      peers: [...this.peers.keys()].filter((id) => id !== peerId),
      ts: nowIso(),
    });

    this.broadcast(
      {
        type: "peer-joined",
        peerId,
        ts: nowIso(),
      },
      peerId,
    );

    server.addEventListener("message", (event) => {
      this.handlePeerMessage(peerId, event.data);
    });

    const cleanup = () => {
      if (!this.peers.has(peerId)) {
        return;
      }
      this.peers.delete(peerId);
      this.broadcast(
        {
          type: "peer-left",
          peerId,
          ts: nowIso(),
        },
        peerId,
      );
    };

    server.addEventListener("close", cleanup);
    server.addEventListener("error", cleanup);

    return new Response(null, { status: 101, webSocket: client });
  }

  handlePeerMessage(fromPeerId, rawData) {
    let text;
    if (typeof rawData === "string") {
      text = rawData;
    } else if (rawData instanceof ArrayBuffer) {
      text = new TextDecoder().decode(rawData);
    } else {
      text = String(rawData);
    }

    let message;
    try {
      message = JSON.parse(text);
    } catch {
      this.sendTo(fromPeerId, {
        type: "error",
        error: "invalid-json",
        ts: nowIso(),
      });
      return;
    }

    if (!message || typeof message !== "object") {
      return;
    }

    if (message.type === "ping") {
      this.sendTo(fromPeerId, {
        type: "pong",
        ts: nowIso(),
      });
      return;
    }

    if (message.type === "list") {
      this.sendTo(fromPeerId, {
        type: "peers",
        peers: [...this.peers.keys()].filter((id) => id !== fromPeerId),
        ts: nowIso(),
      });
      return;
    }

    if (message.type === "offer" || message.type === "answer" || message.type === "ice") {
      const target = sanitizePeerId(message.target);
      if (!target) {
        this.sendTo(fromPeerId, {
          type: "error",
          error: "missing-target",
          ts: nowIso(),
        });
        return;
      }
      if (!this.peers.has(target)) {
        this.sendTo(fromPeerId, {
          type: "error",
          error: "target-not-found",
          target,
          ts: nowIso(),
        });
        return;
      }

      this.sendTo(target, {
        type: message.type,
        from: fromPeerId,
        payload: message.payload ?? null,
        ts: nowIso(),
      });
      return;
    }

    if (message.type === "broadcast") {
      this.broadcast(
        {
          type: "broadcast",
          from: fromPeerId,
          payload: message.payload ?? null,
          ts: nowIso(),
        },
        fromPeerId,
      );
      return;
    }

    this.sendTo(fromPeerId, {
      type: "error",
      error: "unsupported-message-type",
      messageType: String(message.type ?? ""),
      ts: nowIso(),
    });
  }

  broadcast(payload, excludePeerId = null) {
    const data = JSON.stringify(payload);
    for (const [peerId, ws] of this.peers.entries()) {
      if (excludePeerId && peerId === excludePeerId) {
        continue;
      }
      try {
        ws.send(data);
      } catch {
        this.peers.delete(peerId);
      }
    }
  }

  sendTo(peerId, payload) {
    const ws = this.peers.get(peerId);
    if (!ws) {
      return;
    }
    this.send(ws, payload);
  }

  send(ws, payload) {
    try {
      ws.send(JSON.stringify(payload));
    } catch {
      // Ignore send failures; peer cleanup happens on close/error.
    }
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }), env, request);
    }

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      return html(renderHomepage(url.origin));
    }

    if (request.method === "GET" && url.pathname === "/assets/pairing-flow.svg") {
      return svg(renderPairingFlowSvg());
    }

    if (request.method === "GET" && url.pathname === "/login") {
      const clientId = String(env.GOOGLE_OAUTH_CLIENT_ID || "").trim();
      return html(renderLoginPage(url.origin, clientId));
    }

    if (request.method === "GET" && url.pathname === "/pair") {
      return html(renderPairPage(url.origin));
    }

    if (request.method === "GET" && url.pathname === "/health") {
      return withCors(
        json({
          ok: true,
          service: "agent-huddle-signaling",
          time: nowIso(),
        }),
        env,
        request,
      );
    }

    if (request.method === "POST" && url.pathname === "/api/auth/login") {
      const users = parseUsers(env.SIGNALING_USERS_JSON);
      const body = await readJsonBody(request);

      const username = typeof body.username === "string" ? body.username.trim() : "";
      const password = typeof body.password === "string" ? body.password : "";

      if (!username || !password) {
        return withCors(json({ error: "missing-username-or-password" }, 400), env, request);
      }

      const expectedPassword = users.get(username);
      if (!expectedPassword || !constantTimeEqual(expectedPassword, password)) {
        return withCors(json({ error: "invalid-credentials" }, 401), env, request);
      }

      const ttlSec = parsePositiveInt(env.SIGNALING_SESSION_TTL_SEC, DEFAULT_SESSION_TTL_SEC);
      const token = await signJwt(
        {
          sub: username,
          scope: "user",
        },
        ttlSec,
        env.SIGNALING_JWT_SECRET,
      );

      return withCors(
        json({
          accessToken: token,
          tokenType: "Bearer",
          expiresInSec: ttlSec,
          user: {
            id: username,
            provider: "password",
          },
        }),
        env,
        request,
      );
    }

    if (request.method === "POST" && url.pathname === "/api/auth/google") {
      if (!env.SIGNALING_JWT_SECRET) {
        return withCors(json({ error: "server-misconfigured", detail: "SIGNALING_JWT_SECRET missing" }, 500), env, request);
      }

      const clientId = String(env.GOOGLE_OAUTH_CLIENT_ID || "").trim();
      if (!clientId) {
        return withCors(json({ error: "server-misconfigured", detail: "GOOGLE_OAUTH_CLIENT_ID missing" }, 500), env, request);
      }

      const body = await readJsonBody(request);
      const idTokenFromBody = typeof body.idToken === "string" ? body.idToken.trim() : "";

      let idToken = idTokenFromBody;
      if (!idToken) {
        const code = typeof body.code === "string" ? body.code.trim() : "";
        if (!code) {
          return withCors(json({ error: "missing-google-id-token-or-code" }, 400), env, request);
        }

        const clientSecret = String(env.GOOGLE_OAUTH_CLIENT_SECRET || "").trim();
        if (!clientSecret) {
          return withCors(json({ error: "server-misconfigured", detail: "GOOGLE_OAUTH_CLIENT_SECRET missing" }, 500), env, request);
        }

        const redirectUri = typeof body.redirectUri === "string" && body.redirectUri.trim()
          ? body.redirectUri.trim()
          : String(env.GOOGLE_OAUTH_REDIRECT_URI || "").trim();
        if (!redirectUri) {
          return withCors(json({ error: "missing-redirect-uri", detail: "Provide body.redirectUri or GOOGLE_OAUTH_REDIRECT_URI" }, 400), env, request);
        }

        const exchange = await exchangeGoogleAuthCode({
          code,
          redirectUri,
          clientId,
          clientSecret,
        });

        if (!exchange.ok) {
          return withCors(json({ error: "google-code-exchange-failed", detail: exchange.detail }, exchange.status), env, request);
        }
        idToken = exchange.idToken;
      }

      const verified = await verifyGoogleIdToken({
        idToken,
        expectedAud: clientId,
      });
      if (!verified.ok) {
        return withCors(json({ error: "google-id-token-invalid", detail: verified.detail }, verified.status), env, request);
      }

      const profile = verified.profile;
      const allowedDomains = parseCsvSet(env.GOOGLE_OAUTH_ALLOWED_DOMAINS || "");
      if (allowedDomains.size > 0) {
        const hostedDomain = String(profile.hd || "").trim().toLowerCase();
        if (!hostedDomain || !allowedDomains.has(hostedDomain)) {
          return withCors(
            json(
              {
                error: "google-domain-not-allowed",
                detail: "User hosted domain is not in GOOGLE_OAUTH_ALLOWED_DOMAINS",
              },
              403,
            ),
            env,
            request,
          );
        }
      }

      const ttlSec = parsePositiveInt(env.SIGNALING_SESSION_TTL_SEC, DEFAULT_SESSION_TTL_SEC);
      const sub = `google:${profile.sub}`;
      const token = await signJwt(
        {
          sub,
          scope: "user",
          provider: "google",
          email: profile.email || "",
          name: profile.name || "",
          picture: profile.picture || "",
          hd: profile.hd || "",
        },
        ttlSec,
        env.SIGNALING_JWT_SECRET,
      );

      return withCors(
        json({
          accessToken: token,
          tokenType: "Bearer",
          expiresInSec: ttlSec,
          user: {
            id: sub,
            provider: "google",
            email: profile.email || null,
            name: profile.name || null,
            picture: profile.picture || null,
            hd: profile.hd || null,
          },
        }),
        env,
        request,
      );
    }

    if (request.method === "POST" && url.pathname === "/api/auth/github") {
      if (!env.SIGNALING_JWT_SECRET) {
        return withCors(json({ error: "server-misconfigured", detail: "SIGNALING_JWT_SECRET missing" }, 500), env, request);
      }

      const body = await readJsonBody(request);
      const githubAccessToken = typeof body.githubAccessToken === "string" ? body.githubAccessToken.trim() : "";
      if (!githubAccessToken) {
        return withCors(json({ error: "missing-github-access-token" }, 400), env, request);
      }

      const verified = await verifyGithubAccessToken(githubAccessToken);
      if (!verified.ok) {
        return withCors(json({ error: "github-token-invalid", detail: verified.detail }, verified.status), env, request);
      }

      const profile = verified.profile;
      const ttlSec = parsePositiveInt(env.SIGNALING_SESSION_TTL_SEC, DEFAULT_SESSION_TTL_SEC);
      const sub = `github:${profile.id}`;
      const token = await signJwt(
        {
          sub,
          scope: "user",
          provider: "github",
          username: profile.login || "",
          email: profile.email || "",
          name: profile.name || "",
          picture: profile.avatarUrl || "",
        },
        ttlSec,
        env.SIGNALING_JWT_SECRET,
      );

      return withCors(
        json({
          accessToken: token,
          tokenType: "Bearer",
          expiresInSec: ttlSec,
          user: {
            id: sub,
            provider: "github",
            username: profile.login || null,
            email: profile.email || null,
            name: profile.name || null,
            picture: profile.avatarUrl || null,
          },
        }),
        env,
        request,
      );
    }

    if (request.method === "GET" && url.pathname === "/api/auth/me") {
      const auth = await requireUser(request, env);
      if (auth.errorResponse) {
        return withCors(auth.errorResponse, env, request);
      }
      return withCors(
        json({
          user: {
            id: auth.claims.sub,
            scope: auth.claims.scope,
            provider: auth.claims.provider || "password",
            email: auth.claims.email || null,
            name: auth.claims.name || null,
            picture: auth.claims.picture || null,
            hd: auth.claims.hd || null,
          },
        }),
        env,
        request,
      );
    }

    if (request.method === "POST" && url.pathname === "/api/pair-key/issue") {
      const auth = await requireUser(request, env);
      if (auth.errorResponse) {
        return withCors(auth.errorResponse, env, request);
      }

      const body = await readJsonBody(request);
      const ttlSec = parsePositiveInt(body.ttlSec, parsePositiveInt(env.PAIR_KEY_TTL_SEC, DEFAULT_PAIR_KEY_TTL_SEC));
      const maxRedeems = parsePositiveInt(body.maxRedeems, parsePositiveInt(env.PAIR_KEY_MAX_REDEEMS, DEFAULT_PAIR_KEY_MAX_REDEEMS));
      const pairKey = generatePairKey();
      const nowMs = Date.now();
      const expiresAtMs = nowMs + ttlSec * 1000;
      const storeIssued = await issuePairKeyRecord(env, {
        pairKey,
        expiresAtMs,
        maxRedeems,
        ownerClaims: {
          sub: auth.claims.sub,
          provider: auth.claims.provider || "password",
          email: auth.claims.email || "",
          name: auth.claims.name || "",
          picture: auth.claims.picture || "",
          hd: auth.claims.hd || "",
          username: auth.claims.username || "",
        },
      });

      if (!storeIssued.ok) {
        return withCors(json({ error: storeIssued.error, detail: storeIssued.detail }, storeIssued.status), env, request);
      }

      return withCors(
        json({
          pairKey,
          expiresInSec: ttlSec,
          expiresAt: new Date(expiresAtMs).toISOString(),
          maxRedeems,
          note: "Use this one-time code on both machines to auto-match in hosted pairing.",
        }),
        env,
        request,
      );
    }

    if (request.method === "POST" && url.pathname === "/api/turn/credentials") {
      const auth = await requireUser(request, env);
      if (auth.errorResponse) {
        return withCors(auth.errorResponse, env, request);
      }

      const body = await readJsonBody(request);
      const ttlSec = parsePositiveInt(body.ttlSec, parsePositiveInt(env.TURN_DEFAULT_TTL_SEC, DEFAULT_TURN_TTL_SEC));
      const customIdentifier = typeof body.customIdentifier === "string" && body.customIdentifier.trim()
        ? body.customIdentifier.trim()
        : auth.claims.sub;

      const turn = await generateTurnCredentials(env, {
        ttlSec,
        customIdentifier,
      });

      if (turn.error) {
        return withCors(json(turn, turn.status || 500), env, request);
      }

      return withCors(json(turn), env, request);
    }

    if (
      request.method === "POST" &&
      (url.pathname === "/api/connect" || url.pathname === "/api/rendezvous")
    ) {
      const response = await handlePairKeyConnect(request, url, env);
      return withCors(response, env, request);
    }

    if (request.method === "POST" && url.pathname === "/api/sessions") {
      const auth = await requireUser(request, env);
      if (auth.errorResponse) {
        return withCors(auth.errorResponse, env, request);
      }

      const body = await readJsonBody(request);
      const sessionId = crypto.randomUUID();
      const peerId = sanitizePeerId(body.peerId) || `${auth.claims.sub}-${makeShortId()}`;
      const joinTtlSec = parsePositiveInt(body.joinTtlSec, parsePositiveInt(env.SIGNALING_SESSION_TTL_SEC, DEFAULT_SESSION_TTL_SEC));

      const joinToken = await signJwt(
        {
          sub: auth.claims.sub,
          scope: "ws",
          sid: sessionId,
          pid: peerId,
        },
        joinTtlSec,
        env.SIGNALING_JWT_SECRET,
      );

      const wsUrl = buildWsUrl(url, sessionId, joinToken, peerId);
      const autoTurn = (env.TURN_AUTO_ON_SESSION || "true").toLowerCase() !== "false";

      let turn = null;
      if (autoTurn) {
        const turnTtlSec = parsePositiveInt(body.turnTtlSec, parsePositiveInt(env.TURN_DEFAULT_TTL_SEC, DEFAULT_TURN_TTL_SEC));
        const result = await generateTurnCredentials(env, {
          ttlSec: turnTtlSec,
          customIdentifier: buildTurnIdentifier(auth.claims.sub, sessionId),
        });
        if (!result.error) {
          turn = result;
        }
      }

      return withCors(
        json({
          sessionId,
          peerId,
          joinToken,
          joinExpiresInSec: joinTtlSec,
          wsUrl,
          turn,
        }),
        env,
        request,
      );
    }

    if (request.method === "POST" && url.pathname.startsWith("/api/sessions/") && url.pathname.endsWith("/join")) {
      const auth = await requireUser(request, env);
      if (auth.errorResponse) {
        return withCors(auth.errorResponse, env, request);
      }

      const sessionId = extractSessionId(url.pathname, "join");
      if (!sessionId) {
        return withCors(json({ error: "invalid-session-id" }, 400), env, request);
      }

      const body = await readJsonBody(request);
      const peerId = sanitizePeerId(body.peerId) || `${auth.claims.sub}-${makeShortId()}`;
      const joinTtlSec = parsePositiveInt(body.joinTtlSec, parsePositiveInt(env.SIGNALING_SESSION_TTL_SEC, DEFAULT_SESSION_TTL_SEC));

      const joinToken = await signJwt(
        {
          sub: auth.claims.sub,
          scope: "ws",
          sid: sessionId,
          pid: peerId,
        },
        joinTtlSec,
        env.SIGNALING_JWT_SECRET,
      );

      const wsUrl = buildWsUrl(url, sessionId, joinToken, peerId);

      return withCors(
        json({
          sessionId,
          peerId,
          joinToken,
          joinExpiresInSec: joinTtlSec,
          wsUrl,
        }),
        env,
        request,
      );
    }

    if (request.method === "GET" && url.pathname.startsWith("/api/sessions/") && url.pathname.endsWith("/ws")) {
      const sessionId = extractSessionId(url.pathname, "ws");
      if (!sessionId) {
        return withCors(json({ error: "invalid-session-id" }, 400), env, request);
      }

      if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
        return withCors(json({ error: "websocket-upgrade-required" }, 426), env, request);
      }

      const token = url.searchParams.get("token") || "";
      if (!token) {
        return withCors(json({ error: "missing-token" }, 401), env, request);
      }

      const verified = await verifyJwt(token, env.SIGNALING_JWT_SECRET);
      if (!verified.ok) {
        return withCors(json({ error: "invalid-token", detail: verified.error }, 401), env, request);
      }

      const claims = verified.payload;
      if (claims.scope !== "ws" || claims.sid !== sessionId) {
        return withCors(json({ error: "token-scope-or-session-mismatch" }, 403), env, request);
      }

      const peerId = sanitizePeerId(claims.pid) || `${claims.sub || "peer"}-${makeShortId()}`;
      const roomId = env.SIGNALING_ROOM.idFromName(sessionId);
      const stub = env.SIGNALING_ROOM.get(roomId);

      const roomUrl = new URL("https://room/connect");
      roomUrl.searchParams.set("peerId", peerId);

      const proxyReq = new Request(roomUrl.toString(), {
        method: "GET",
        headers: request.headers,
      });

      return stub.fetch(proxyReq);
    }

    return withCors(json({ error: "not-found" }, 404), env, request);
  },
};

function parseUsers(rawJson) {
  const out = new Map();
  if (!rawJson) {
    return out;
  }

  try {
    const parsed = JSON.parse(rawJson);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return out;
    }

    for (const [username, value] of Object.entries(parsed)) {
      if (typeof value === "string") {
        out.set(username, value);
      } else if (value && typeof value === "object" && typeof value.password === "string") {
        out.set(username, value.password);
      }
    }
  } catch {
    return out;
  }

  return out;
}

async function requireUser(request, env) {
  if (!env.SIGNALING_JWT_SECRET) {
    return {
      errorResponse: json({ error: "server-misconfigured", detail: "SIGNALING_JWT_SECRET missing" }, 500),
    };
  }

  const token = extractBearerToken(request);
  if (!token) {
    return {
      errorResponse: json({ error: "missing-bearer-token" }, 401),
    };
  }

  const verified = await verifyJwt(token, env.SIGNALING_JWT_SECRET);
  if (!verified.ok) {
    return {
      errorResponse: json({ error: "invalid-token", detail: verified.error }, 401),
    };
  }

  return {
    claims: verified.payload,
  };
}

async function callPairKeyStore(env, path, payload) {
  if (!env.PAIR_KEY_STORE) {
    return {
      ok: false,
      status: 500,
      body: { error: "server-misconfigured", detail: "PAIR_KEY_STORE binding missing" },
    };
  }

  const id = env.PAIR_KEY_STORE.idFromName("global");
  const stub = env.PAIR_KEY_STORE.get(id);
  const response = await stub.fetch(
    new Request(`https://pair-key-store${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload || {}),
    }),
  );
  const body = await response.json().catch(() => ({}));
  return {
    ok: response.ok,
    status: response.status,
    body,
  };
}

async function issuePairKeyRecord(env, payload) {
  const result = await callPairKeyStore(env, "/issue", payload);
  if (!result.ok) {
    return {
      ok: false,
      status: result.status || 500,
      error: result.body?.error || "pair-key-store-issue-failed",
      detail: result.body?.detail || result.body || null,
    };
  }
  return {
    ok: true,
    status: 200,
    body: result.body || {},
  };
}

async function redeemPairKeyRecord(env, payload) {
  const result = await callPairKeyStore(env, "/redeem", payload);
  if (!result.ok) {
    return {
      ok: false,
      status: result.status || 500,
      error: result.body?.error || "pair-key-store-redeem-failed",
      detail: result.body?.detail || result.body || null,
      body: result.body || {},
    };
  }
  return {
    ok: true,
    status: 200,
    body: result.body || {},
  };
}

function clampInt(value, min, max) {
  const n = Number(value);
  const lo = Number.isFinite(min) ? min : 1;
  const hi = Number.isFinite(max) ? max : lo;
  if (!Number.isFinite(n) || n <= 0) {
    return lo;
  }
  return Math.max(lo, Math.min(Math.floor(n), hi));
}

async function handlePairKeyConnect(request, url, env) {
  if (!env.SIGNALING_JWT_SECRET) {
    return json({ error: "server-misconfigured", detail: "SIGNALING_JWT_SECRET missing" }, 500);
  }

  const body = await readJsonBody(request);
  const rawPassKey = typeof body.passKey === "string" ? body.passKey.trim() : "";
  if (!rawPassKey) {
    return json({ error: "missing-pass-key" }, 400);
  }

  const normalizedPassKey = normalizePassKey(rawPassKey);
  if (normalizedPassKey.length < 6) {
    return json({ error: "pass-key-too-short" }, 400);
  }

  const redeemed = await redeemPairKeyRecord(env, { pairKey: normalizedPassKey });
  if (!redeemed.ok) {
    return json({ error: redeemed.error, detail: redeemed.detail }, redeemed.status);
  }

  const ownerClaims = redeemed.body?.ownerClaims && typeof redeemed.body.ownerClaims === "object"
    ? redeemed.body.ownerClaims
    : {};
  const ownerSub = String(ownerClaims.sub || "").trim();
  const ownerKey = ownerSub || `pair-key:${normalizedPassKey.slice(-8)}`;
  const safeSubject = toPeerSlug(ownerKey);

  const sessionId = await deriveRendezvousSessionId(normalizedPassKey);
  const peerId = sanitizePeerId(body.peerId) || `${safeSubject}-${makeShortId()}`;

  const configuredConnectTtl = parsePositiveInt(env.PAIR_KEY_CONNECT_TTL_SEC, DEFAULT_PAIR_KEY_TTL_SEC);
  const requestedJoinTtl = parsePositiveInt(body.joinTtlSec, configuredConnectTtl);
  const remainingSec = parsePositiveInt(redeemed.body?.expiresInSec, configuredConnectTtl);
  const joinTtlSec = clampInt(requestedJoinTtl, 1, Math.min(configuredConnectTtl, remainingSec));

  const joinToken = await signJwt(
    {
      sub: ownerKey,
      scope: "ws",
      sid: sessionId,
      pid: peerId,
      provider: ownerClaims.provider || "pair_key",
      email: ownerClaims.email || "",
      name: ownerClaims.name || "",
      picture: ownerClaims.picture || "",
      hd: ownerClaims.hd || "",
      username: ownerClaims.username || "",
    },
    joinTtlSec,
    env.SIGNALING_JWT_SECRET,
  );

  const wsUrl = buildWsUrl(url, sessionId, joinToken, peerId);
  const autoTurn = (env.TURN_AUTO_ON_SESSION || "true").toLowerCase() !== "false";

  let turn = null;
  if (autoTurn) {
    const requestedTurnTtl = parsePositiveInt(body.turnTtlSec, parsePositiveInt(env.TURN_DEFAULT_TTL_SEC, DEFAULT_TURN_TTL_SEC));
    const turnTtlSec = clampInt(requestedTurnTtl, 1, joinTtlSec);
    const result = await generateTurnCredentials(env, {
      ttlSec: turnTtlSec,
      customIdentifier: buildTurnIdentifier(ownerKey, sessionId),
    });
    if (!result.error) {
      turn = result;
    }
  }

  return json({
    sessionId,
    peerId,
    joinToken,
    joinExpiresInSec: joinTtlSec,
    wsUrl,
    turn,
    matchmaking: {
      passKeyValid: true,
      redeemCount: Number(redeemed.body?.redeemCount || 0),
      maxRedeems: Number(redeemed.body?.maxRedeems || 0),
      expiresAt: redeemed.body?.expiresAt || null,
    },
  });
}

function extractBearerToken(request) {
  const raw = request.headers.get("authorization") || "";
  const match = raw.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return "";
  }
  return match[1].trim();
}

async function generateTurnCredentials(env, { ttlSec, customIdentifier }) {
  const apiToken = env.CLOUDFLARE_TURN_API_TOKEN || "";
  const keyId = env.CLOUDFLARE_TURN_KEY_ID || "";

  if (!apiToken || !keyId) {
    return {
      error: "turn-not-configured",
      status: 503,
      detail: "Missing CLOUDFLARE_TURN_API_TOKEN or CLOUDFLARE_TURN_KEY_ID",
    };
  }

  const endpoint = `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(
    keyId,
  )}/credentials/generate-ice-servers`;

  const payload = {
    ttl: ttlSec,
    customIdentifier,
  };

  let response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
    });
  } catch (error) {
    return {
      error: "turn-api-request-failed",
      status: 502,
      detail: String(error?.message || error),
    };
  }

  let body = {};
  try {
    body = await response.json();
  } catch {
    body = {};
  }

  if (!response.ok) {
    return {
      error: "turn-api-error",
      status: response.status,
      detail: body,
    };
  }

  const iceServers = Array.isArray(body.iceServers)
    ? body.iceServers
    : Array.isArray(body.ice_servers)
      ? body.ice_servers
      : [];

  if (!iceServers.length) {
    return {
      error: "turn-api-empty-response",
      status: 502,
      detail: body,
    };
  }

  return {
    iceServers,
    ttlSec,
    provider: "cloudflare-turn",
  };
}

async function verifyGithubAccessToken(githubAccessToken) {
  const headers = {
    Authorization: `Bearer ${githubAccessToken}`,
    Accept: "application/vnd.github+json",
    "User-Agent": "agent-huddle-signaling",
    "X-GitHub-Api-Version": "2022-11-28",
  };

  let profileResponse;
  try {
    profileResponse = await fetch(GITHUB_USER_API_URL, {
      method: "GET",
      headers,
    });
  } catch (error) {
    return {
      ok: false,
      status: 502,
      detail: String(error?.message || error),
    };
  }

  let profileBody = {};
  try {
    profileBody = await profileResponse.json();
  } catch {
    profileBody = {};
  }

  if (!profileResponse.ok) {
    return {
      ok: false,
      status: 401,
      detail: profileBody,
    };
  }

  const id = profileBody?.id;
  const login = typeof profileBody?.login === "string" ? profileBody.login : "";
  const name = typeof profileBody?.name === "string" ? profileBody.name : "";
  const avatarUrl = typeof profileBody?.avatar_url === "string" ? profileBody.avatar_url : "";
  let email = typeof profileBody?.email === "string" ? profileBody.email.trim().toLowerCase() : "";

  if (!id || !login) {
    return {
      ok: false,
      status: 401,
      detail: "github-profile-missing-id-or-login",
    };
  }

  if (!email) {
    try {
      const emailResp = await fetch(GITHUB_USER_EMAILS_API_URL, {
        method: "GET",
        headers,
      });
      if (emailResp.ok) {
        const emailBody = await emailResp.json().catch(() => []);
        if (Array.isArray(emailBody)) {
          const preferred =
            emailBody.find((item) => item?.primary && item?.verified && typeof item?.email === "string") ||
            emailBody.find((item) => item?.verified && typeof item?.email === "string");
          if (preferred?.email) {
            email = String(preferred.email).trim().toLowerCase();
          }
        }
      }
    } catch {
      // Ignore email enrichment failures.
    }
  }

  return {
    ok: true,
    status: 200,
    profile: {
      id: String(id),
      login,
      name,
      email,
      avatarUrl,
    },
  };
}

async function exchangeGoogleAuthCode({ code, redirectUri, clientId, clientSecret }) {
  const payload = new URLSearchParams({
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
  });

  let response;
  try {
    response = await fetch(GOOGLE_TOKEN_EXCHANGE_URL, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      body: payload.toString(),
    });
  } catch (error) {
    return {
      ok: false,
      status: 502,
      detail: String(error?.message || error),
    };
  }

  let body = {};
  try {
    body = await response.json();
  } catch {
    body = {};
  }

  if (!response.ok) {
    return {
      ok: false,
      status: response.status,
      detail: body,
    };
  }

  const idToken = typeof body.id_token === "string" ? body.id_token.trim() : "";
  if (!idToken) {
    return {
      ok: false,
      status: 502,
      detail: "Google token exchange response missing id_token",
    };
  }

  return {
    ok: true,
    status: 200,
    idToken,
  };
}

function normalizePassKey(value) {
  return String(value || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
}

function toPeerSlug(value) {
  const slug = String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+/, "")
    .replace(/-+$/, "");
  if (!slug) {
    return "peer";
  }
  return slug.slice(0, 24);
}

function buildTurnIdentifier(subject, sessionId) {
  const left = toPeerSlug(subject || "user");
  const right = String(sessionId || "")
    .replace(/[^a-zA-Z0-9_-]/g, "")
    .slice(-20);
  const joined = right ? `${left}-${right}` : left;
  return joined.slice(0, 48);
}

async function sha256Hex(value) {
  const data = new TextEncoder().encode(String(value || ""));
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function deriveRendezvousSessionId(normalizedPassKey) {
  const hex = await sha256Hex(`agent-huddle:${normalizedPassKey}`);
  return `pk-${hex.slice(0, 40)}`;
}

function generatePairKey() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let raw = "";
  for (let i = 0; i < 12; i += 1) {
    const idx = Math.floor(Math.random() * alphabet.length);
    raw += alphabet[idx];
  }
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
}

async function verifyGoogleIdToken({ idToken, expectedAud }) {
  const tokenInfoUrl = new URL(GOOGLE_TOKENINFO_URL);
  tokenInfoUrl.searchParams.set("id_token", idToken);

  let response;
  try {
    response = await fetch(tokenInfoUrl.toString(), {
      method: "GET",
    });
  } catch (error) {
    return {
      ok: false,
      status: 502,
      detail: String(error?.message || error),
    };
  }

  let body = {};
  try {
    body = await response.json();
  } catch {
    body = {};
  }

  if (!response.ok) {
    return {
      ok: false,
      status: 401,
      detail: body,
    };
  }

  const aud = String(body.aud || "");
  if (!aud || aud !== expectedAud) {
    return {
      ok: false,
      status: 401,
      detail: "google-aud-mismatch",
    };
  }

  const sub = String(body.sub || "").trim();
  if (!sub) {
    return {
      ok: false,
      status: 401,
      detail: "google-sub-missing",
    };
  }

  const expSec = Number(body.exp);
  const nowSec = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(expSec) || expSec <= nowSec) {
    return {
      ok: false,
      status: 401,
      detail: "google-token-expired",
    };
  }

  const email = String(body.email || "").trim().toLowerCase();
  const emailVerified = body.email_verified === true || body.email_verified === "true";
  if (email && !emailVerified) {
    return {
      ok: false,
      status: 401,
      detail: "google-email-not-verified",
    };
  }

  return {
    ok: true,
    status: 200,
    profile: {
      sub,
      email,
      name: String(body.name || "").trim(),
      picture: String(body.picture || "").trim(),
      hd: String(body.hd || "").trim().toLowerCase(),
    },
  };
}

function buildWsUrl(url, sessionId, token, peerId) {
  const wsScheme = url.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = new URL(`${wsScheme}//${url.host}/api/sessions/${sessionId}/ws`);
  wsUrl.searchParams.set("token", token);
  wsUrl.searchParams.set("peerId", peerId);
  return wsUrl.toString();
}

function extractSessionId(pathname, suffix) {
  const prefix = "/api/sessions/";
  if (!pathname.startsWith(prefix)) {
    return "";
  }

  const tail = pathname.slice(prefix.length);
  const marker = `/${suffix}`;
  if (!tail.endsWith(marker)) {
    return "";
  }

  return tail.slice(0, -marker.length);
}

function sanitizePeerId(value) {
  if (typeof value !== "string") {
    return "";
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return "";
  }
  if (trimmed.length > 64) {
    return "";
  }
  if (!/^[a-zA-Z0-9._-]+$/.test(trimmed)) {
    return "";
  }
  return trimmed;
}

function makeShortId() {
  return crypto.randomUUID().split("-")[0];
}

async function readJsonBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function renderHomepage(origin) {
  const loginUrl = `${origin}/login`;
  const flowSvgUrl = `${origin}/assets/pairing-flow.svg`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Agent Huddle</title>
  <meta name="description" content="Connect machines with different capabilities and run one coordinated workflow through MCP." />
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 128 128'%3E%3Crect width='128' height='128' rx='26' fill='%23243138'/%3E%3Cpath d='M27 80c19-38 57-38 76 0' stroke='%23f3b965' stroke-width='10' stroke-linecap='round' fill='none'/%3E%3Ccircle cx='64' cy='52' r='14' fill='%232f7f77'/%3E%3C/svg%3E" />
  <style>
    @import url("https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,600;9..144,700&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap");

    :root {
      --sand: #f4eee3;
      --paper: #fffaf0;
      --ink: #243138;
      --muted: #5a696f;
      --line: #d9cec0;
      --card: rgba(255, 250, 240, 0.88);
      --shadow: 0 18px 45px rgba(44, 35, 26, 0.14);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      color: var(--ink);
      font-family: "Plus Jakarta Sans", "Avenir Next", "Segoe UI", sans-serif;
      background:
        radial-gradient(1000px 580px at 8% -10%, rgba(243, 185, 101, 0.42), transparent 66%),
        radial-gradient(760px 460px at 95% 0%, rgba(47, 127, 119, 0.18), transparent 65%),
        linear-gradient(160deg, #f8f1e6 0%, #efe3d4 52%, #ece2d7 100%);
      min-height: 100vh;
    }

    .texture::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(120deg, rgba(36,49,56,0.03) 25%, transparent 25%, transparent 50%, rgba(36,49,56,0.03) 50%, rgba(36,49,56,0.03) 75%, transparent 75%, transparent);
      background-size: 14px 14px;
      opacity: 0.28;
    }

    .orb {
      position: fixed;
      border-radius: 999px;
      filter: blur(2px);
      opacity: 0.45;
      pointer-events: none;
      animation: float 16s ease-in-out infinite;
    }

    .orb.a {
      width: 220px;
      height: 220px;
      right: 10%;
      top: 18%;
      background: rgba(47,127,119,0.24);
    }

    .orb.b {
      width: 140px;
      height: 140px;
      left: 7%;
      bottom: 12%;
      background: rgba(211,106,79,0.24);
      animation-delay: -7s;
    }

    .wrap {
      position: relative;
      max-width: 1040px;
      margin: 0 auto;
      padding: 28px 20px 48px;
    }

    .topbar {
      display: flex;
      justify-content: flex-start;
      align-items: center;
      gap: 14px;
      margin-bottom: 24px;
      animation: rise 700ms ease both;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border: 1px solid rgba(36,49,56,0.18);
      border-radius: 999px;
      padding: 8px 14px;
      color: var(--muted);
      background: rgba(255,255,255,0.55);
      backdrop-filter: blur(6px);
      font-size: 13px;
      letter-spacing: 0.03em;
    }

    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #1f9b63;
      box-shadow: 0 0 0 6px rgba(31,155,99,0.12);
    }

    .hero {
      display: grid;
      grid-template-columns: 1.2fr 0.8fr;
      gap: 18px;
    }

    .panel {
      border: 1px solid var(--line);
      border-radius: 22px;
      padding: 24px;
      background: var(--card);
      backdrop-filter: blur(2px);
      box-shadow: var(--shadow);
      animation: rise 820ms ease both;
    }

    .hero h1 {
      margin: 0;
      line-height: 1.05;
      font-size: clamp(2rem, 5vw, 3.6rem);
      letter-spacing: -0.03em;
      font-weight: 720;
      font-family: "Fraunces", "Iowan Old Style", "Book Antiqua", serif;
      max-width: 13ch;
    }

    .hero p {
      margin-top: 12px;
      margin-bottom: 0;
      color: var(--muted);
      font-size: 1.02rem;
      line-height: 1.58;
      max-width: 64ch;
    }

    .cta {
      margin-top: 22px;
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 9px;
      text-decoration: none;
      border-radius: 12px;
      border: 1px solid transparent;
      padding: 11px 16px;
      font-weight: 600;
      transition: transform 150ms ease, box-shadow 150ms ease;
    }

    .btn:hover {
      transform: translateY(-1px);
      box-shadow: 0 8px 22px rgba(27, 37, 43, 0.16);
    }

    .btn.main {
      background: linear-gradient(135deg, #2f7f77, #3a8f84);
      color: white;
    }

    .benefits {
      margin-top: 16px;
      display: grid;
      gap: 10px;
    }

    .benefit {
      border: 1px dashed rgba(60,78,86,0.28);
      border-radius: 12px;
      background: rgba(255,255,255,0.72);
      padding: 10px 12px;
      color: #51636a;
      font-size: 0.93rem;
      line-height: 1.45;
    }

    .right h2 {
      margin: 0;
      line-height: 1.15;
      font-size: 1.22rem;
      letter-spacing: -0.01em;
      color: #395058;
    }

    .right p {
      margin-top: 14px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(255,255,255,0.68);
      padding: 10px;
    }

    .footer {
      margin-top: 20px;
      color: #617178;
      font-size: 0.88rem;
      animation: rise 1.05s ease both;
    }

    .footer a {
      color: #2e6f68;
      text-decoration: none;
      border-bottom: 1px solid rgba(46,111,104,0.3);
    }

    @keyframes rise {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }

    @keyframes float {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-14px); }
    }

    @media (max-width: 860px) {
      .hero {
        grid-template-columns: 1fr;
      }
      .wrap {
        padding: 20px 14px 30px;
      }
      .panel {
        border-radius: 16px;
      }
    }
  </style>
</head>
<body class="texture">
  <div class="orb a"></div>
  <div class="orb b"></div>
  <main class="wrap">
    <div class="topbar">
      <div class="badge"><span class="dot"></span> Agent Huddle</div>
    </div>

    <section class="hero">
      <article class="panel">
        <h1>One task. Multiple machines. Combined capability.</h1>
        <p>
          Different machines have different strengths: one might have browser access, one might have internal
          network reach, one might have GPU or local files. Agent Huddle lets MCP agents bridge those machines
          into one coordinated workflow so you can complete tasks that were blocked on a single machine.
        </p>
        <div class="benefits">
          <div class="benefit">Use resources across environments without manual offer/answer steps.</div>
          <div class="benefit">Fail over automatically from direct P2P to TURN relay when networks are restrictive.</div>
          <div class="benefit">Keep operator flow simple: login once, get code, paste code in MCP.</div>
        </div>
        <div class="cta">
          <a class="btn main" href="${loginUrl}" target="_blank" rel="noreferrer">Get Started</a>
        </div>
      </article>

      <aside class="panel right">
        <h2>Quick Start Flow</h2>
        <p>Authenticate, get one-time code on the post-login pairing page, then paste the code in MCP on both machines.</p>
        <div aria-label="Pairing flow diagram">
          <img src="${flowSvgUrl}" alt="Pairing flow: login, post-login code issue, MCP pairing, signaling and TURN between two machines." />
        </div>
      </aside>
    </section>

    <footer class="footer">
      Source: <a href="${GITHUB_REPO_URL}" target="_blank" rel="noreferrer">github.com/uditk2/agent-huddle</a>
    </footer>
  </main>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderLoginPage(origin, googleClientId) {
  const escapedOrigin = escapeHtml(origin);
  const clientIdJson = JSON.stringify(String(googleClientId || ""));
  const missingClientId = !googleClientId;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Agent Huddle Login</title>
  <meta name="description" content="Google login to mint an Agent Huddle signaling access token." />
  <script src="https://accounts.google.com/gsi/client" async defer></script>
  <style>
    :root {
      --bg: #f4efe5;
      --card: #fffaf2;
      --ink: #243138;
      --muted: #5a686d;
      --line: #d8ccbc;
      --accent: #2f7f77;
      --warn: #ab4e3c;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      font-family: "Plus Jakarta Sans", "Avenir Next", "Segoe UI", sans-serif;
      background:
        radial-gradient(900px 500px at 5% -15%, rgba(243, 185, 101, 0.35), transparent 65%),
        linear-gradient(160deg, #f8f2e8 0%, #efe4d6 52%, #ece2d7 100%);
      display: grid;
      place-items: center;
      padding: 20px;
    }
    .card {
      width: min(760px, 100%);
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 18px;
      box-shadow: 0 14px 34px rgba(35, 28, 20, 0.14);
      padding: 24px;
    }
    h1 {
      margin: 0;
      line-height: 1.08;
      font-size: clamp(1.8rem, 4vw, 2.6rem);
      letter-spacing: -0.03em;
    }
    p {
      margin: 12px 0 0;
      color: var(--muted);
      line-height: 1.55;
    }
    .row { margin-top: 18px; }
    .status {
      margin-top: 12px;
      min-height: 20px;
      font-size: 0.95rem;
      color: var(--muted);
    }
    .status.error { color: var(--warn); }
    .token-box {
      margin-top: 16px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #fff;
      padding: 10px;
    }
    .pair-code {
      width: 100%;
      border: 0;
      outline: 0;
      font: 700 1.6rem/1.2 "SFMono-Regular", Menlo, Consolas, monospace;
      letter-spacing: 0.08em;
      color: #1f3a44;
      text-align: center;
      background: transparent;
      padding: 10px 0;
    }
    textarea {
      width: 100%;
      min-height: 136px;
      border: 0;
      outline: 0;
      resize: vertical;
      font: 500 0.9rem/1.45 "SFMono-Regular", Menlo, Consolas, monospace;
      color: #1f3a44;
      background: transparent;
    }
    .actions {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 10px;
    }
    button, a.btn {
      appearance: none;
      border: 1px solid transparent;
      border-radius: 10px;
      padding: 10px 14px;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
    }
    .copy-btn {
      background: var(--accent);
      color: #fff;
    }
    .back-btn {
      background: #fff;
      border-color: #c8b8a6;
      color: #314048;
    }
    .helper {
      margin-top: 10px;
      font: 500 0.84rem/1.5 "SFMono-Regular", Menlo, Consolas, monospace;
      color: #42565f;
      background: rgba(36, 49, 56, 0.05);
      border-radius: 8px;
      padding: 8px 10px;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .warn {
      margin-top: 14px;
      padding: 10px 12px;
      border-radius: 10px;
      border: 1px solid rgba(171,78,60,0.35);
      background: rgba(171,78,60,0.08);
      color: #7f2f22;
      font-size: 0.92rem;
    }
  </style>
</head>
<body>
  <main class="card">
    <h1>Login To Agent Huddle</h1>
    <p>Sign in with Google, then continue to the post-login pairing page where the one-time code is generated.</p>
    <div class="row" id="google-btn"></div>
    <div class="status" id="status">Waiting for Google sign-in.</div>
    <div class="actions">
      <a class="btn back-btn" href="${escapedOrigin}/">Back To Home</a>
    </div>
    ${missingClientId ? '<div class="warn">Google OAuth client id is missing on server. Set GOOGLE_OAUTH_CLIENT_ID in Worker secrets.</div>' : ""}
  </main>
  <script>
    const googleClientId = ${clientIdJson};
    const statusEl = document.getElementById("status");
    const tokenStorageKey = "agentHuddleAccessToken";

    function setStatus(message, isError = false) {
      statusEl.textContent = message;
      statusEl.classList.toggle("error", Boolean(isError));
    }

    async function handleGoogleCredential(response) {
      const idToken = response && response.credential ? String(response.credential) : "";
      if (!idToken) {
        setStatus("Google credential was empty.", true);
        return;
      }
      setStatus("Exchanging Google credential with Agent Huddle...");
      try {
        const resp = await fetch("/api/auth/google", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ idToken }),
        });
        const body = await resp.json().catch(() => ({}));
        if (!resp.ok || !body.accessToken) {
          setStatus("Login failed: " + JSON.stringify(body), true);
          return;
        }
        sessionStorage.setItem(tokenStorageKey, String(body.accessToken));
        setStatus("Login successful. Redirecting to pairing page...");
        window.location.href = "${escapedOrigin}/pair";
      } catch (error) {
        setStatus("Login request failed: " + String(error && error.message ? error.message : error), true);
      }
    }

    window.addEventListener("load", () => {
      if (!googleClientId) {
        setStatus("Google login is not configured on this environment.", true);
        return;
      }
      if (!(window.google && window.google.accounts && window.google.accounts.id)) {
        setStatus("Google sign-in script failed to load. Refresh and try again.", true);
        return;
      }
      window.google.accounts.id.initialize({
        client_id: googleClientId,
        callback: handleGoogleCredential,
        auto_select: false,
        cancel_on_tap_outside: true,
      });
      window.google.accounts.id.renderButton(
        document.getElementById("google-btn"),
        { theme: "outline", size: "large", shape: "pill", text: "signin_with", width: 280 },
      );
      window.google.accounts.id.prompt();
    });
  </script>
</body>
</html>`;
}

function renderPairPage(origin) {
  const escapedOrigin = escapeHtml(origin);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Agent Huddle Pairing</title>
  <meta name="description" content="Post-login page for issuing and using one-time pairing codes." />
  <style>
    :root {
      --bg: #f4efe5;
      --card: #fffaf2;
      --ink: #243138;
      --muted: #5a686d;
      --line: #d8ccbc;
      --accent: #2f7f77;
      --warn: #ab4e3c;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      font-family: "Plus Jakarta Sans", "Avenir Next", "Segoe UI", sans-serif;
      background:
        radial-gradient(900px 500px at 5% -15%, rgba(243, 185, 101, 0.35), transparent 65%),
        linear-gradient(160deg, #f8f2e8 0%, #efe4d6 52%, #ece2d7 100%);
      display: grid;
      place-items: center;
      padding: 20px;
    }
    .card {
      width: min(760px, 100%);
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 18px;
      box-shadow: 0 14px 34px rgba(35, 28, 20, 0.14);
      padding: 24px;
    }
    h1 {
      margin: 0;
      line-height: 1.08;
      font-size: clamp(1.8rem, 4vw, 2.6rem);
      letter-spacing: -0.03em;
    }
    p {
      margin: 12px 0 0;
      color: var(--muted);
      line-height: 1.55;
    }
    .status {
      margin-top: 12px;
      min-height: 20px;
      font-size: 0.95rem;
      color: var(--muted);
    }
    .status.error { color: var(--warn); }
    .token-box {
      margin-top: 16px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #fff;
      padding: 10px;
    }
    .pair-code {
      width: 100%;
      border: 0;
      outline: 0;
      font: 700 1.6rem/1.2 "SFMono-Regular", Menlo, Consolas, monospace;
      letter-spacing: 0.08em;
      color: #1f3a44;
      text-align: center;
      background: transparent;
      padding: 10px 0;
    }
    textarea {
      width: 100%;
      min-height: 136px;
      border: 0;
      outline: 0;
      resize: vertical;
      font: 500 0.9rem/1.45 "SFMono-Regular", Menlo, Consolas, monospace;
      color: #1f3a44;
      background: transparent;
      margin-top: 10px;
    }
    .actions {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 10px;
    }
    button, a.btn {
      appearance: none;
      border: 1px solid transparent;
      border-radius: 10px;
      padding: 10px 14px;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
    }
    .copy-btn {
      background: var(--accent);
      color: #fff;
    }
    .back-btn {
      background: #fff;
      border-color: #c8b8a6;
      color: #314048;
    }
    .helper {
      margin-top: 10px;
      font: 500 0.84rem/1.5 "SFMono-Regular", Menlo, Consolas, monospace;
      color: #42565f;
      background: rgba(36, 49, 56, 0.05);
      border-radius: 8px;
      padding: 8px 10px;
      white-space: pre-wrap;
      word-break: break-word;
    }
  </style>
</head>
<body>
  <main class="card">
    <h1>Pair Machines</h1>
    <p>Use the one-time code below on both machines. Signaling and TURN are handled through Agent Huddle.</p>
    <div class="status" id="status">Checking login session...</div>
    <div class="token-box">
      <input id="pair-key" class="pair-code" readonly placeholder="---- ---- ----" />
      <div class="actions">
        <button class="copy-btn" id="copy-pair-key" type="button">Copy Code</button>
        <button class="copy-btn" id="refresh-pair-key" type="button">Refresh Code</button>
        <button class="back-btn" id="logout-btn" type="button">Sign Out</button>
        <a class="btn back-btn" href="${escapedOrigin}/">Back To Home</a>
      </div>
      <pre class="helper" id="helper">Use this same code on both machines in MCP pair_with_code flow.</pre>
      <textarea id="token" readonly placeholder="Agent Huddle access token (setup/admin use only)."></textarea>
    </div>
  </main>
  <script>
    const tokenStorageKey = "agentHuddleAccessToken";
    const statusEl = document.getElementById("status");
    const tokenEl = document.getElementById("token");
    const pairKeyEl = document.getElementById("pair-key");
    const helperEl = document.getElementById("helper");
    const copyPairBtn = document.getElementById("copy-pair-key");
    const refreshPairBtn = document.getElementById("refresh-pair-key");
    const logoutBtn = document.getElementById("logout-btn");
    let accessToken = "";

    function setStatus(message, isError = false) {
      statusEl.textContent = message;
      statusEl.classList.toggle("error", Boolean(isError));
    }

    function setPairKey(pairKey) {
      pairKeyEl.value = pairKey;
      helperEl.textContent = "Use this same code on both machines in MCP pair_with_code flow.";
    }

    async function issuePairKey() {
      if (!accessToken) {
        setStatus("No login token found. Redirecting to login...", true);
        window.location.href = "${escapedOrigin}/login";
        return;
      }
      setStatus("Generating one-time code...");
      try {
        const resp = await fetch("/api/pair-key/issue", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "authorization": "Bearer " + accessToken,
          },
          body: JSON.stringify({ ttlSec: 600 }),
        });
        const body = await resp.json().catch(() => ({}));
        if (!resp.ok || !body.pairKey) {
          if (resp.status === 401) {
            sessionStorage.removeItem(tokenStorageKey);
            setStatus("Session expired. Redirecting to login...", true);
            window.location.href = "${escapedOrigin}/login";
            return;
          }
          setStatus("Code generation failed: " + JSON.stringify(body), true);
          return;
        }
        setPairKey(String(body.pairKey));
        setStatus("Code ready. Paste this code in both MCP chats.");
      } catch (error) {
        setStatus("Code generation failed: " + String(error && error.message ? error.message : error), true);
      }
    }

    copyPairBtn.addEventListener("click", async () => {
      if (!pairKeyEl.value) {
        setStatus("No code available to copy yet.", true);
        return;
      }
      try {
        await navigator.clipboard.writeText(pairKeyEl.value);
        setStatus("Code copied to clipboard.");
      } catch {
        pairKeyEl.select();
        setStatus("Clipboard copy failed; code selected for manual copy.", true);
      }
    });

    refreshPairBtn.addEventListener("click", async () => {
      await issuePairKey();
    });

    logoutBtn.addEventListener("click", () => {
      sessionStorage.removeItem(tokenStorageKey);
      window.location.href = "${escapedOrigin}/login";
    });

    window.addEventListener("load", async () => {
      accessToken = sessionStorage.getItem(tokenStorageKey) || "";
      tokenEl.value = accessToken;
      await issuePairKey();
    });
  </script>
</body>
</html>`;
}

function parsePositiveInt(value, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) {
    return fallback;
  }
  return Math.floor(n);
}

function parseCsvSet(raw) {
  return new Set(
    String(raw || "")
      .split(",")
      .map((part) => part.trim().toLowerCase())
      .filter(Boolean),
  );
}

function json(payload, status = 200) {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function html(markup, status = 200) {
  return new Response(markup, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function svg(markup, status = 200) {
  return new Response(markup, {
    status,
    headers: {
      "content-type": "image/svg+xml; charset=utf-8",
      "cache-control": "public, max-age=300",
    },
  });
}

function withCors(response, env, request) {
  const origin = request.headers.get("origin") || "*";
  const allowedOrigin = resolveAllowedOrigin(origin, env.ALLOWED_ORIGINS || "*");

  response.headers.set("access-control-allow-origin", allowedOrigin);
  response.headers.set("access-control-allow-methods", "GET,POST,OPTIONS");
  response.headers.set("access-control-allow-headers", "authorization,content-type");
  response.headers.set("access-control-max-age", "86400");
  response.headers.set("vary", "origin");

  return response;
}

function resolveAllowedOrigin(origin, configValue) {
  const raw = String(configValue || "*").trim();
  if (!raw || raw === "*") {
    return "*";
  }

  const list = raw
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);

  if (!list.length) {
    return "*";
  }

  if (origin && list.includes(origin)) {
    return origin;
  }

  return list[0];
}

function nowIso(ms = Date.now()) {
  return new Date(ms).toISOString();
}

async function signJwt(payload, ttlSec, secret) {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + ttlSec;
  const header = { alg: "HS256", typ: "JWT" };
  const body = {
    ...payload,
    iat,
    exp,
  };

  const encodedHeader = base64UrlEncodeString(JSON.stringify(header));
  const encodedBody = base64UrlEncodeString(JSON.stringify(body));
  const signingInput = `${encodedHeader}.${encodedBody}`;

  const signature = await hmacSha256(signingInput, secret);
  return `${signingInput}.${base64UrlEncodeBytes(signature)}`;
}

async function verifyJwt(token, secret) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) {
    return { ok: false, error: "jwt-format-invalid" };
  }

  const [headerPart, payloadPart, signaturePart] = parts;

  let header;
  let payload;

  try {
    header = JSON.parse(base64UrlDecodeToString(headerPart));
    payload = JSON.parse(base64UrlDecodeToString(payloadPart));
  } catch {
    return { ok: false, error: "jwt-json-invalid" };
  }

  if (header.alg !== "HS256") {
    return { ok: false, error: "jwt-alg-unsupported" };
  }

  const signingInput = `${headerPart}.${payloadPart}`;
  const expected = base64UrlEncodeBytes(await hmacSha256(signingInput, secret));

  if (!constantTimeEqual(expected, signaturePart)) {
    return { ok: false, error: "jwt-signature-invalid" };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp <= nowSec) {
    return { ok: false, error: "jwt-expired" };
  }

  return { ok: true, payload };
}

async function hmacSha256(input, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(input));
  return new Uint8Array(signature);
}

function constantTimeEqual(a, b) {
  const strA = String(a || "");
  const strB = String(b || "");

  const len = Math.max(strA.length, strB.length);
  let mismatch = strA.length ^ strB.length;

  for (let i = 0; i < len; i += 1) {
    const ca = i < strA.length ? strA.charCodeAt(i) : 0;
    const cb = i < strB.length ? strB.charCodeAt(i) : 0;
    mismatch |= ca ^ cb;
  }

  return mismatch === 0;
}

function base64UrlEncodeString(value) {
  return base64UrlEncodeBytes(new TextEncoder().encode(value));
}

function base64UrlEncodeBytes(bytes) {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecodeToString(value) {
  const padded = String(value)
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");

  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}
