const DEFAULT_SESSION_TTL_SEC = 60 * 60;
const DEFAULT_TURN_TTL_SEC = 10 * 60;
const GOOGLE_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo";
const GOOGLE_TOKEN_EXCHANGE_URL = "https://oauth2.googleapis.com/token";

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
          customIdentifier: `${auth.claims.sub}:${sessionId}`,
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
