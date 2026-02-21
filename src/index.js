#!/usr/bin/env node

import crypto from "node:crypto";
import process from "node:process";

import cors from "cors";
import express from "express";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const PASSKEY_TTL_MS = 10 * 60 * 1000;
const KEEPALIVE_PING_MS = 20 * 1000;
const KEEPALIVE_TIMEOUT_MS = 90 * 1000;
const SESSION_SWEEP_MS = 30 * 1000;
const CLOSED_SESSION_RETENTION_MS = 60 * 60 * 1000;

const HTTP_HOST = process.env.WEBRTC_MCP_HTTP_HOST || "127.0.0.1";
const HTTP_PORT = Number(process.env.WEBRTC_MCP_HTTP_PORT || 8787);
const PUBLIC_BASE_URL = (process.env.WEBRTC_MCP_PUBLIC_BASE_URL || "").trim().replace(/\/+$/, "");
const ADMIN_TOKEN = process.env.WEBRTC_MCP_ADMIN_TOKEN || "";
const SHELL_CMD = process.env.WEBRTC_MCP_SHELL || process.env.SHELL || "/bin/bash";
const SHELL_ARGS = parseArgs(process.env.WEBRTC_MCP_SHELL_ARGS || "-li");
const SHELL_CWD = process.env.WEBRTC_MCP_WORKDIR || process.cwd();

const ICE_SERVERS = parseIceServers(
  process.env.WEBRTC_MCP_ICE_SERVERS ||
    JSON.stringify([{ urls: ["stun:stun.l.google.com:19302"] }]),
);

let runtimeHttpPort = HTTP_PORT;
let wrtcCtor = null;
let wrtcLoadError = null;
let nodePtyModule = null;
let nodePtyLoadError = null;

const sessions = new Map();
const passIndex = new Map();
let activePassSessionId = null;
let activePassKey = null;

const issueSchema = z.object({
  label: z.string().trim().max(120).optional(),
});

const connectSchema = z.object({
  passKey: z.string().trim().min(4).max(128),
  offerSdp: z.string().min(10),
  label: z.string().trim().max(120).optional(),
});

const revokeSchema = z.object({
  sessionId: z.string().uuid(),
});

function log(message, details) {
  if (details === undefined) {
    console.error(`[webrtc-terminal-mcp] ${message}`);
    return;
  }
  console.error(`[webrtc-terminal-mcp] ${message}`, details);
}

function parseArgs(argString) {
  if (!argString.trim()) return [];
  return argString.trim().split(/\s+/);
}

function parseIceServers(raw) {
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) throw new Error("ICE servers must be an array");
    return parsed;
  } catch (error) {
    throw new Error(`Invalid WEBRTC_MCP_ICE_SERVERS JSON: ${error.message}`);
  }
}

function encodeBlob(payload) {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

function decodeBlob(blob, label = "blob") {
  try {
    let normalized = blob.trim();
    const prefixed = normalized.match(/^[A-Z_]+=(.+)$/s);
    if (prefixed && prefixed[1]) {
      normalized = prefixed[1].trim();
    }
    const text = Buffer.from(normalized, "base64url").toString("utf8");
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`Invalid ${label}: ${formatError(error)}`);
  }
}

function formatError(error) {
  if (!error) return "unknown error";
  if (error instanceof Error) return error.message;
  return String(error);
}

async function resolveRTCPeerConnectionCtor() {
  if (wrtcCtor) return wrtcCtor;
  if (wrtcLoadError) throw wrtcLoadError;

  try {
    const wrtcImport = await import("@roamhq/wrtc");
    const wrtcAny = {
      ...(wrtcImport.default ?? {}),
      ...wrtcImport,
    };
    const ctor = wrtcAny.RTCPeerConnection;
    if (!ctor) {
      throw new Error("Unable to load RTCPeerConnection from @roamhq/wrtc");
    }
    wrtcCtor = ctor;
    return wrtcCtor;
  } catch (error) {
    wrtcLoadError = error;
    throw error;
  }
}

async function resolveNodePty() {
  if (nodePtyModule) return nodePtyModule;
  if (nodePtyLoadError) throw nodePtyLoadError;

  try {
    nodePtyModule = await import("node-pty");
    return nodePtyModule;
  } catch (error) {
    nodePtyLoadError = error;
    throw error;
  }
}

function normalizePassKey(value) {
  return value.toUpperCase().replace(/[^A-Z0-9]/g, "");
}

function hashPassKey(passKey) {
  return crypto.createHash("sha256").update(normalizePassKey(passKey)).digest("hex");
}

function generatePassKey() {
  for (;;) {
    const base = crypto.randomBytes(9).toString("base64url").toUpperCase().replace(/[^A-Z0-9]/g, "");
    if (base.length >= 12) {
      return `${base.slice(0, 4)}-${base.slice(4, 8)}-${base.slice(8, 12)}`;
    }
  }
}

function nowIso(ms = Date.now()) {
  return new Date(ms).toISOString();
}

function compactSession(session) {
  return {
    sessionId: session.sessionId,
    label: session.label,
    status: session.status,
    issuedAt: nowIso(session.issuedAt),
    expiresAt: nowIso(session.expiresAt),
    consumedAt: session.consumedAt ? nowIso(session.consumedAt) : null,
    connectedAt: session.connectedAt ? nowIso(session.connectedAt) : null,
    closedAt: session.closedAt ? nowIso(session.closedAt) : null,
    closeReason: session.closeReason,
    source: session.source,
  };
}

function issuePassKey({ label, source = "http" } = {}) {
  const sessionId = crypto.randomUUID();
  const passKey = generatePassKey();
  const passHash = hashPassKey(passKey);
  const issuedAt = Date.now();
  const expiresAt = issuedAt + PASSKEY_TTL_MS;

  const session = {
    sessionId,
    label: label || "",
    source,
    issuedAt,
    expiresAt,
    consumedAt: null,
    connectedAt: null,
    closedAt: null,
    closeReason: null,
    status: "issued",
    passHash,
    peerConnection: null,
    channel: null,
    terminal: null,
    lastPongAt: null,
    keepaliveTimer: null,
    closing: false,
  };

  sessions.set(sessionId, session);
  passIndex.set(passHash, sessionId);

  return {
    session,
    passKey,
  };
}

function isSessionUsableForPass(session) {
  if (!session) return false;
  if (session.status !== "issued") return false;
  if (session.consumedAt) return false;
  if (session.closing) return false;
  if (Date.now() > session.expiresAt) return false;
  return true;
}

function getActivePassSession() {
  if (!activePassSessionId) return null;
  return sessions.get(activePassSessionId) || null;
}

function setActivePass(session, passKey) {
  activePassSessionId = session.sessionId;
  activePassKey = passKey;
}

function ensureActivePassKey({ source = "auto", label = "active-pass" } = {}) {
  const active = getActivePassSession();
  if (active && activePassKey && isSessionUsableForPass(active)) {
    return { session: active, passKey: activePassKey, reused: true };
  }

  const issued = issuePassKey({ source, label });
  setActivePass(issued.session, issued.passKey);
  return { session: issued.session, passKey: issued.passKey, reused: false };
}

function rotateActivePassKey({ source = "auto-rotate", label = "active-pass-rotate" } = {}) {
  const active = getActivePassSession();
  if (active && isSessionUsableForPass(active)) {
    closeSession(active, "passkey-rotated");
  }
  const issued = issuePassKey({ source, label });
  setActivePass(issued.session, issued.passKey);
  return issued;
}

function closeSession(session, reason = "closed") {
  if (!session || session.closing) return;
  session.closing = true;
  session.status = "closed";
  session.closeReason = reason;
  session.closedAt = Date.now();

  if (session.sessionId === activePassSessionId) {
    activePassSessionId = null;
    activePassKey = null;
  }

  passIndex.delete(session.passHash);

  if (session.keepaliveTimer) {
    clearInterval(session.keepaliveTimer);
    session.keepaliveTimer = null;
  }

  if (session.channel) {
    try {
      if (session.channel.readyState === "open") {
        session.channel.close();
      }
    } catch {
      // noop
    }
    session.channel = null;
  }

  if (session.terminal) {
    try {
      session.terminal.kill();
    } catch {
      // noop
    }
    session.terminal = null;
  }

  if (session.peerConnection) {
    try {
      session.peerConnection.close();
    } catch {
      // noop
    }
    session.peerConnection = null;
  }

  log(`session ${session.sessionId} closed (${reason})`);
}

function sendChannel(session, payload) {
  if (!session.channel || session.channel.readyState !== "open") return;
  try {
    session.channel.send(JSON.stringify(payload));
  } catch (error) {
    log(`failed to send channel message to ${session.sessionId}: ${error.message}`);
  }
}

function startKeepalive(session) {
  session.lastPongAt = Date.now();
  session.keepaliveTimer = setInterval(() => {
    const idleFor = Date.now() - (session.lastPongAt ?? 0);
    if (idleFor > KEEPALIVE_TIMEOUT_MS) {
      closeSession(session, "keepalive-timeout");
      return;
    }
    sendChannel(session, { type: "ping", ts: Date.now() });
  }, KEEPALIVE_PING_MS);
  session.keepaliveTimer.unref?.();
}

async function startTerminal(session) {
  if (session.terminal) return;
  const nodePty = await resolveNodePty();

  const term = nodePty.spawn(SHELL_CMD, SHELL_ARGS, {
    name: "xterm-256color",
    cols: 120,
    rows: 36,
    cwd: SHELL_CWD,
    env: {
      ...process.env,
      TERM: "xterm-256color",
    },
  });

  term.onData((data) => {
    sendChannel(session, { type: "stdout", data });
  });

  term.onExit(({ exitCode, signal }) => {
    sendChannel(session, {
      type: "exit",
      exitCode,
      signal,
    });
    closeSession(session, `terminal-exit:${exitCode}`);
  });

  session.terminal = term;
}

function handleChannelData(session, rawMessage) {
  const text = typeof rawMessage === "string" ? rawMessage : rawMessage?.toString("utf8") ?? "";

  let message;
  try {
    message = JSON.parse(text);
  } catch {
    if (session.terminal) {
      session.terminal.write(text);
    }
    return;
  }

  if (!message || typeof message !== "object") return;

  if (message.type === "pong") {
    session.lastPongAt = Date.now();
    return;
  }

  if (message.type === "ping") {
    sendChannel(session, { type: "pong", ts: Date.now() });
    return;
  }

  if (message.type === "stdin" && typeof message.data === "string") {
    if (session.terminal) {
      session.terminal.write(message.data);
    }
    return;
  }

  if (
    message.type === "resize" &&
    Number.isInteger(message.cols) &&
    Number.isInteger(message.rows) &&
    session.terminal
  ) {
    try {
      session.terminal.resize(message.cols, message.rows);
    } catch {
      // noop
    }
  }
}

function attachDataChannel(session, channel) {
  session.channel = channel;

  channel.onopen = () => {
    session.status = "connected";
    session.connectedAt = Date.now();
    startTerminal(session).catch((error) => {
      sendChannel(session, {
        type: "error",
        error: `terminal-start-failed:${formatError(error)}`,
      });
      closeSession(session, `terminal-start-failed:${formatError(error)}`);
    });
    startKeepalive(session);
    sendChannel(session, {
      type: "hello",
      sessionId: session.sessionId,
      message: "terminal-ready",
    });
  };

  channel.onmessage = (event) => {
    handleChannelData(session, event.data);
  };

  channel.onerror = () => {
    closeSession(session, "datachannel-error");
  };

  channel.onclose = () => {
    closeSession(session, "datachannel-closed");
  };
}

async function waitForIceGatheringComplete(peerConnection, timeoutMs = 5000) {
  if (peerConnection.iceGatheringState === "complete") return;

  await new Promise((resolve, reject) => {
    const onChange = () => {
      if (peerConnection.iceGatheringState === "complete") {
        clearTimeout(timeoutId);
        peerConnection.removeEventListener("icegatheringstatechange", onChange);
        resolve();
      }
    };

    const timeoutId = setTimeout(() => {
      peerConnection.removeEventListener("icegatheringstatechange", onChange);
      reject(new Error("Timed out while gathering ICE candidates"));
    }, timeoutMs);

    peerConnection.addEventListener("icegatheringstatechange", onChange);
  });
}

function verifyAdmin(req) {
  if (!ADMIN_TOKEN) return true;
  const bearer = req.header("authorization")?.replace(/^Bearer\s+/i, "").trim();
  const headerToken = req.header("x-admin-token");
  return bearer === ADMIN_TOKEN || headerToken === ADMIN_TOKEN;
}

function requireAdmin(req, res, next) {
  if (!verifyAdmin(req)) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  next();
}

function consumeSessionFromPassKey(passKey) {
  const passHash = hashPassKey(passKey);
  const sessionId = passIndex.get(passHash);

  if (!sessionId) {
    return { error: "invalid-passkey" };
  }

  const session = sessions.get(sessionId);
  if (!session) {
    passIndex.delete(passHash);
    return { error: "invalid-passkey" };
  }

  if (Date.now() > session.expiresAt) {
    closeSession(session, "passkey-expired");
    ensureActivePassKey({ source: "auto-after-expire", label: "active-pass" });
    return { error: "expired-passkey" };
  }

  if (session.consumedAt) {
    return { error: "passkey-already-used" };
  }

  session.consumedAt = Date.now();
  session.status = "connecting";
  passIndex.delete(passHash);

  if (session.sessionId === activePassSessionId) {
    // Keep a fresh one-time key available for the next requester.
    rotateActivePassKey({ source: "auto-after-consume", label: "active-pass" });
  }

  return { session };
}

function setupPeerHandlers(session, peerConnection) {
  peerConnection.ondatachannel = (event) => {
    attachDataChannel(session, event.channel);
  };

  peerConnection.onconnectionstatechange = () => {
    const state = peerConnection.connectionState;
    if (state === "failed") {
      closeSession(session, "peer-failed");
      return;
    }
    if (state === "closed") {
      closeSession(session, "peer-closed");
    }
  };
}

async function connectOffer({ passKey, offerSdp, label }) {
  let RTCPeerConnectionCtor;
  try {
    RTCPeerConnectionCtor = await resolveRTCPeerConnectionCtor();
  } catch (error) {
    return {
      error: "webrtc-unavailable",
      status: 503,
      detail: formatError(error),
    };
  }

  const consumed = consumeSessionFromPassKey(passKey);
  if (consumed.error) {
    return { error: consumed.error, status: 401 };
  }

  const session = consumed.session;
  if (label && !session.label) {
    session.label = label;
  }

  try {
    const peerConnection = new RTCPeerConnectionCtor({ iceServers: ICE_SERVERS });
    session.peerConnection = peerConnection;
    setupPeerHandlers(session, peerConnection);

    await peerConnection.setRemoteDescription({
      type: "offer",
      sdp: offerSdp,
    });

    const answer = await peerConnection.createAnswer();
    await peerConnection.setLocalDescription(answer);
    await waitForIceGatheringComplete(peerConnection);

    return {
      session,
      answerSdp: peerConnection.localDescription?.sdp,
    };
  } catch (error) {
    closeSession(session, `connect-failed:${error.message}`);
    return {
      error: "connect-failed",
      status: 400,
      detail: error.message,
    };
  }
}

function sweepSessions() {
  const now = Date.now();
  for (const session of sessions.values()) {
    if (!session.consumedAt && now > session.expiresAt) {
      closeSession(session, "passkey-expired");
    }

    if (session.status === "closed" && session.closedAt && now - session.closedAt > CLOSED_SESSION_RETENTION_MS) {
      sessions.delete(session.sessionId);
    }
  }

  ensureActivePassKey({ source: "auto-sweep", label: "active-pass" });
}

function getConnectUrl() {
  if (PUBLIC_BASE_URL) {
    return `${PUBLIC_BASE_URL}/api/connect`;
  }
  return `http://${HTTP_HOST}:${runtimeHttpPort}/api/connect`;
}

function listenHttp(app, port) {
  return new Promise((resolve, reject) => {
    const server = app.listen(port, HTTP_HOST);
    const onError = (error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve(server);
    };
    server.once("error", onError);
    server.once("listening", onListening);
  });
}

async function buildHttpServer() {
  const app = express();
  app.disable("x-powered-by");
  app.use(cors());
  app.use(express.json({ limit: "2mb" }));
  app.use((_, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  });

  app.get("/health", (_, res) => {
    res.json({
      ok: true,
      sessions: sessions.size,
      time: nowIso(),
    });
  });

  app.get("/api/config", (_, res) => {
    res.json({
      httpHost: HTTP_HOST,
      httpPort: runtimeHttpPort,
      publicBaseUrl: PUBLIC_BASE_URL || null,
      connectEndpoint: getConnectUrl(),
      iceServers: ICE_SERVERS,
      keepalivePingMs: KEEPALIVE_PING_MS,
      keepaliveTimeoutMs: KEEPALIVE_TIMEOUT_MS,
      passkeyTtlMs: PASSKEY_TTL_MS,
    });
  });

  app.post("/api/passkeys/issue", requireAdmin, (req, res) => {
    const parsed = issueSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: "invalid-body", detail: parsed.error.flatten() });
      return;
    }

    const { session, passKey } = issuePassKey({
      label: parsed.data.label,
      source: "http",
    });

    res.status(201).json({
      sessionId: session.sessionId,
      passKey,
      issuedAt: nowIso(session.issuedAt),
      expiresAt: nowIso(session.expiresAt),
    });
  });

  app.get("/api/passkeys/latest", requireAdmin, (_, res) => {
    res.json(activePassPayload());
  });

  app.post("/api/passkeys/rotate", requireAdmin, (_, res) => {
    const issued = rotateActivePassKey({ source: "http-rotate", label: "active-pass" });
    res.status(201).json({
      sessionId: issued.session.sessionId,
      passKey: issued.passKey,
      issuedAt: nowIso(issued.session.issuedAt),
      expiresAt: nowIso(issued.session.expiresAt),
      connectEndpoint: getConnectUrl(),
    });
  });

  app.post("/api/connect", async (req, res) => {
    const parsed = connectSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: "invalid-body", detail: parsed.error.flatten() });
      return;
    }

    const result = await connectOffer(parsed.data);

    if (result.error) {
      res.status(result.status || 400).json({
        error: result.error,
        detail: result.detail,
      });
      return;
    }

    res.status(200).json({
      sessionId: result.session.sessionId,
      answerSdp: result.answerSdp,
      expiresAt: nowIso(result.session.expiresAt),
    });
  });

  app.get("/api/sessions", requireAdmin, (_, res) => {
    const all = [...sessions.values()].map(compactSession);
    res.json({
      count: all.length,
      sessions: all,
    });
  });

  app.get("/api/sessions/:sessionId", requireAdmin, (req, res) => {
    const session = sessions.get(req.params.sessionId);
    if (!session) {
      res.status(404).json({ error: "not-found" });
      return;
    }
    res.json({ session: compactSession(session) });
  });

  app.post("/api/sessions/revoke", requireAdmin, (req, res) => {
    const parsed = revokeSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: "invalid-body", detail: parsed.error.flatten() });
      return;
    }

    const session = sessions.get(parsed.data.sessionId);
    if (!session) {
      res.status(404).json({ error: "not-found" });
      return;
    }

    closeSession(session, "revoked");
    res.json({ ok: true, session: compactSession(session) });
  });

  app.use(express.static(new URL("../web", import.meta.url).pathname));

  let server;
  try {
    server = await listenHttp(app, HTTP_PORT);
  } catch (error) {
    if (error?.code !== "EADDRINUSE" && error?.code !== "EPERM") {
      throw error;
    }
    log(
      `could not bind ${HTTP_HOST}:${HTTP_PORT} (${error.code}); falling back to an ephemeral port`,
    );
    server = await listenHttp(app, 0);
  }

  const address = server.address();
  if (address && typeof address === "object" && typeof address.port === "number") {
    runtimeHttpPort = address.port;
  }

  log(`HTTP signaling ready on http://${HTTP_HOST}:${runtimeHttpPort}`);
  return server;
}

function asToolText(payload) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(payload, null, 2),
      },
    ],
  };
}

function activePassPayload() {
  const ensured = ensureActivePassKey({ source: "auto-read", label: "active-pass" });
  return {
    sessionId: ensured.session.sessionId,
    passKey: ensured.passKey,
    issuedAt: nowIso(ensured.session.issuedAt),
    expiresAt: nowIso(ensured.session.expiresAt),
    connectEndpoint: getConnectUrl(),
    reused: ensured.reused,
  };
}

function buildMcpServer() {
  const mcp = new McpServer({
    name: "webrtc-terminal-mcp",
    version: "0.1.0",
  });

  mcp.tool(
    "issue_pass_key",
    "Issue a one-time WebRTC pass key that expires in 10 minutes.",
    {
      label: z.string().trim().max(120).optional(),
    },
    async ({ label }) => {
      const { session, passKey } = issuePassKey({ label, source: "mcp" });
      return asToolText({
        sessionId: session.sessionId,
        passKey,
        issuedAt: nowIso(session.issuedAt),
        expiresAt: nowIso(session.expiresAt),
        connectEndpoint: getConnectUrl(),
      });
    },
  );

  mcp.tool(
    "get_latest_pass_key",
    "Return the active one-time pass key. A key is auto-generated on startup and auto-rotated after use/expiry.",
    {
      rotate: z.boolean().optional(),
    },
    async ({ rotate }) => {
      if (rotate) {
        const issued = rotateActivePassKey({ source: "mcp-rotate", label: "active-pass" });
        return asToolText({
          sessionId: issued.session.sessionId,
          passKey: issued.passKey,
          issuedAt: nowIso(issued.session.issuedAt),
          expiresAt: nowIso(issued.session.expiresAt),
          connectEndpoint: getConnectUrl(),
          rotated: true,
        });
      }
      return asToolText(activePassPayload());
    },
  );

  mcp.tool(
    "list_sessions",
    "List passkey sessions and connection state.",
    {
      includeClosed: z.boolean().optional(),
    },
    async ({ includeClosed }) => {
      let list = [...sessions.values()];
      if (!includeClosed) {
        list = list.filter((session) => session.status !== "closed");
      }
      return asToolText({
        count: list.length,
        sessions: list.map(compactSession),
      });
    },
  );

  mcp.tool(
    "revoke_session",
    "Immediately close and revoke a session.",
    {
      sessionId: z.string().uuid(),
    },
    async ({ sessionId }) => {
      const session = sessions.get(sessionId);
      if (!session) {
        return asToolText({ error: "not-found", sessionId });
      }
      closeSession(session, "revoked-via-mcp");
      return asToolText({ ok: true, session: compactSession(session) });
    },
  );

  mcp.tool(
    "server_status",
    "Return server runtime status and endpoint information.",
    {},
    async () => {
      const active = activePassPayload();
      return asToolText({
        httpHost: HTTP_HOST,
        httpPort: runtimeHttpPort,
        connectUrl: getConnectUrl(),
        passkeyTtlMs: PASSKEY_TTL_MS,
        keepalivePingMs: KEEPALIVE_PING_MS,
        keepaliveTimeoutMs: KEEPALIVE_TIMEOUT_MS,
        dependencies: {
          webrtc: wrtcLoadError ? `error:${formatError(wrtcLoadError)}` : wrtcCtor ? "loaded" : "not-loaded-yet",
          nodePty: nodePtyLoadError
            ? `error:${formatError(nodePtyLoadError)}`
            : nodePtyModule
              ? "loaded"
              : "not-loaded-yet",
        },
        shell: {
          command: SHELL_CMD,
          args: SHELL_ARGS,
          cwd: SHELL_CWD,
        },
        sessions: sessions.size,
        activePass: {
          sessionId: active.sessionId,
          expiresAt: active.expiresAt,
        },
      });
    },
  );

  mcp.tool(
    "manual_connect_guide",
    "Return guided next steps for copy/paste cross-machine connect via Codex/Claude.",
    {},
    async () => {
      const active = activePassPayload();
      return asToolText({
        passKey: active.passKey,
        connectEndpoint: active.connectEndpoint,
        roleA: "Machine A (offerer)",
        roleB: "Machine B (answerer)",
        machineAStep: `npm run connect:a -- --pass-key '${active.passKey}' --connect-url '${active.connectEndpoint}'`,
        machineBStep:
          "After receiving OFFER_BLOB line from machine A, call tool answer_offer_blob with offerBlob and paste returned answerBlobLine back on machine A.",
        machineBFallbackStep: "npm run connect:b -- --blob 'OFFER_BLOB=...'",
        notes: [
          "Use this when both machines are accessible but no public signaling service is hosted.",
          "Data channel traffic is encrypted by DTLS.",
        ],
      });
    },
  );

  mcp.tool(
    "answer_offer_blob",
    "Consume OFFER_BLOB and return ANSWER_BLOB for manual copy/paste signaling.",
    {
      offerBlob: z.string().min(16),
      label: z.string().trim().max(120).optional(),
    },
    async ({ offerBlob, label }) => {
      let parsed;
      try {
        parsed = decodeBlob(offerBlob, "offerBlob");
      } catch (error) {
        return asToolText({ error: "invalid-offer-blob", detail: formatError(error) });
      }

      if (
        !parsed ||
        typeof parsed !== "object" ||
        typeof parsed.passKey !== "string" ||
        typeof parsed.offerSdp !== "string"
      ) {
        return asToolText({
          error: "invalid-offer-payload",
          detail: "Expected offer blob payload with passKey and offerSdp",
        });
      }

      const result = await connectOffer({
        passKey: parsed.passKey,
        offerSdp: parsed.offerSdp,
        label: label || "manual-blob",
      });

      if (result.error) {
        return asToolText({
          error: result.error,
          detail: result.detail,
          status: result.status || 400,
        });
      }

      const answerPayload = {
        version: 1,
        answerSdp: result.answerSdp,
        sessionId: result.session.sessionId,
        expiresAt: nowIso(result.session.expiresAt),
        createdAt: nowIso(),
      };
      const answerBlob = encodeBlob(answerPayload);
      return asToolText({
        ok: true,
        sessionId: result.session.sessionId,
        expiresAt: nowIso(result.session.expiresAt),
        answerBlob,
        answerBlobLine: `ANSWER_BLOB=${answerBlob}`,
      });
    },
  );

  return mcp;
}

function setupProcessGuards(httpServer) {
  const shutdown = () => {
    for (const session of sessions.values()) {
      closeSession(session, "shutdown");
    }
    httpServer.close(() => {
      process.exit(0);
    });
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

async function main() {
  const httpServer = await buildHttpServer();
  setupProcessGuards(httpServer);
  ensureActivePassKey({ source: "startup", label: "active-pass" });

  setInterval(sweepSessions, SESSION_SWEEP_MS).unref?.();

  const mcp = buildMcpServer();
  const transport = new StdioServerTransport();

  await mcp.connect(transport);
  log("MCP stdio transport connected");
}

main().catch((error) => {
  log(`fatal startup error: ${error.stack || error.message}`);
  process.exit(1);
});
