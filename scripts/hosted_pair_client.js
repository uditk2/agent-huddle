#!/usr/bin/env node

import process from "node:process";
import readline from "node:readline";

import WebSocket from "ws";
import {
  DEFAULT_ICE_SERVERS_JSON,
  parseCliArgs,
  parseIceServers,
  postJson,
} from "./manual_signaling_utils.js";

const DEFAULT_SIGNALING_BASE_URL = process.env.WEBRTC_MCP_SIGNALING_BASE_URL || "https://agenthuddle.synergiqai.com";
const DEFAULT_SIGNALING_TOKEN = process.env.WEBRTC_MCP_SIGNALING_TOKEN || "";
const DEFAULT_PAIR_KEY = process.env.WEBRTC_MCP_PAIR_KEY || "";
const DEFAULT_LOCAL_CONNECT_URL = process.env.WEBRTC_MCP_CONNECT_URL || "http://127.0.0.1:8787/api/connect";
const DEFAULT_LOCAL_IMPORT_URL = process.env.WEBRTC_MCP_IMPORT_URL || deriveImportUrl(DEFAULT_LOCAL_CONNECT_URL);

function usage(exitCode = 1) {
  console.error(
    "Usage: node scripts/hosted_pair_client.js --role <auto|machine_a|machine_b> [--pass-key <KEY>] [--signaling-url <URL>] [--connect-url <URL>] [--import-url <URL>] [--peer-id <ID>] [--ice-servers '<JSON>'] [--signaling-token <TOKEN>]",
  );
  process.exit(exitCode);
}

function deriveImportUrl(connectUrl) {
  if (connectUrl.endsWith("/api/connect")) {
    return `${connectUrl.slice(0, -"/api/connect".length)}/api/passkeys/import`;
  }
  try {
    const parsed = new URL(connectUrl);
    parsed.pathname = "/api/passkeys/import";
    parsed.search = "";
    return parsed.toString();
  } catch {
    return "http://127.0.0.1:8787/api/passkeys/import";
  }
}

function waitForIceGatheringComplete(peerConnection, timeoutMs = 10000) {
  if (peerConnection.iceGatheringState === "complete") {
    return Promise.resolve(true);
  }

  return new Promise((resolve) => {
    const onChange = () => {
      if (peerConnection.iceGatheringState === "complete") {
        clearTimeout(timeoutId);
        peerConnection.removeEventListener("icegatheringstatechange", onChange);
        resolve(true);
      }
    };
    const timeoutId = setTimeout(() => {
      peerConnection.removeEventListener("icegatheringstatechange", onChange);
      resolve(false);
    }, timeoutMs);
    peerConnection.addEventListener("icegatheringstatechange", onChange);
  });
}

function waitForDataChannelOpen(channel, timeoutMs = 30000) {
  if (channel.readyState === "open") {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    const onOpen = () => {
      clearTimeout(timeoutId);
      channel.removeEventListener("open", onOpen);
      resolve();
    };
    const timeoutId = setTimeout(() => {
      channel.removeEventListener("open", onOpen);
      reject(new Error("Timed out waiting for data channel open"));
    }, timeoutMs);
    channel.addEventListener("open", onOpen);
  });
}

function safeJsonParse(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function normalizePassKey(value) {
  const normalized = String(value || "")
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "");
  if (normalized.length < 6) {
    throw new Error("pass key must contain at least 6 alphanumeric characters");
  }
  return normalized.match(/.{1,4}/g).join("-");
}

function askLine(prompt) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

async function postJsonWithOptionalAuth(url, payload, bearer = "", timeoutMs = 20000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const headers = {
    "content-type": "application/json",
  };
  if (bearer) {
    headers.authorization = `Bearer ${bearer}`;
  }
  try {
    const response = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    const body = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, body };
  } finally {
    clearTimeout(timeout);
  }
}

async function openSocket(wsUrl) {
  return await new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    const timeout = setTimeout(() => {
      try {
        ws.close();
      } catch {
        // noop
      }
      reject(new Error("Timed out connecting to signaling websocket"));
    }, 20000);

    ws.once("open", () => {
      clearTimeout(timeout);
      resolve(ws);
    });

    ws.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}

function parseWsMessage(data) {
  const text = typeof data === "string" ? data : data?.toString("utf8") || "";
  return safeJsonParse(text);
}

function mergeIceServers(preferred, fallback) {
  const out = [];
  const seen = new Set();
  for (const list of [preferred, fallback]) {
    if (!Array.isArray(list)) {
      continue;
    }
    for (const server of list) {
      if (!server || typeof server !== "object") {
        continue;
      }
      const key = JSON.stringify(server);
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      out.push(server);
    }
  }
  return out;
}

let lastProgressSentAt = 0;
const MIN_PROGRESS_INTERVAL_MS = 400;

async function reportProgress(args, event, detail = "", roleOverride = "", { throttle = true } = {}) {
  const signalingBaseUrl = args?.signalingUrl || DEFAULT_SIGNALING_BASE_URL;
  if (!signalingBaseUrl || !args?.passKey || !event) {
    return;
  }
  const now = Date.now();
  if (throttle && now - lastProgressSentAt < MIN_PROGRESS_INTERVAL_MS) {
    return;
  }
  lastProgressSentAt = now;
  const url = `${signalingBaseUrl.replace(/\/+$/, "")}/api/pair-key/progress`;
  const payload = {
    pairKey: args.passKey,
    event,
    role: roleOverride || args.role || "",
    peerId: args._peerId || "",
    detail,
  };
  try {
    await postJsonWithOptionalAuth(url, payload, args.signalingToken || "", 8000);
  } catch {
    // ignore progress errors
  }
}

async function ensureLocalPassKey(importUrl, passKey) {
  const headers = {};
  if (process.env.WEBRTC_MCP_ADMIN_TOKEN) {
    headers.authorization = `Bearer ${process.env.WEBRTC_MCP_ADMIN_TOKEN}`;
  }

  const result = await fetch(importUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...headers,
    },
    body: JSON.stringify({ passKey, label: "hosted-pair", setActive: true }),
  });

  const body = await result.json().catch(() => ({}));
  if (!result.ok) {
    throw new Error(`Failed to import local pass key (${result.status}): ${JSON.stringify(body)}`);
  }
}

async function createRendezvous({ signalingBaseUrl, signalingToken, passKey, peerId }) {
  const url = `${signalingBaseUrl.replace(/\/+$/, "")}/api/connect`;
  const result = await postJsonWithOptionalAuth(url, { passKey, peerId }, signalingToken);
  if (!result.ok) {
    throw new Error(`Rendezvous failed (${result.status}): ${JSON.stringify(result.body)}`);
  }
  if (!result.body?.wsUrl || !result.body?.peerId) {
    throw new Error("Rendezvous response missing wsUrl/peerId");
  }
  return result.body;
}

async function resolveWrtcCtor() {
  const wrtcImport = await import("@roamhq/wrtc");
  const wrtcAny = {
    ...(wrtcImport.default ?? {}),
    ...wrtcImport,
  };
  const ctor = wrtcAny.RTCPeerConnection;
  if (!ctor) {
    throw new Error("RTCPeerConnection not found in @roamhq/wrtc");
  }
  return ctor;
}

function installChannelHandlers(channel, peerConnection, options = {}) {
  const interactive = options.interactive !== false;
  const labelPrefix = options.labelPrefix ? `${options.labelPrefix} ` : "";
  const args = options.args || null;
  let keepaliveTimer = null;

  channel.onmessage = (event) => {
    const text = typeof event.data === "string" ? event.data : event.data?.toString("utf8") || "";
    const payload = safeJsonParse(text);
    if (!payload) {
      const output = labelPrefix + text;
      process.stdout.write(output);
      if (args) {
        const snippet = output.slice(0, 180);
        reportProgress(args, "output", snippet);
      }
      return;
    }

    if (payload.type === "stdout" && typeof payload.data === "string") {
      const output = labelPrefix + payload.data;
      process.stdout.write(output);
      if (args) {
        const snippet = output.slice(0, 180);
        reportProgress(args, "output", snippet);
      }
      return;
    }
    if (payload.type === "ping") {
      if (channel.readyState === "open") {
        channel.send(JSON.stringify({ type: "pong", ts: Date.now() }));
      }
      return;
    }
    if (payload.type === "hello") {
      process.stderr.write(`[connected] session=${payload.sessionId}\n`);
      return;
    }
    if (payload.type === "exit") {
      process.stderr.write(`[remote-exit] code=${payload.exitCode}\n`);
      process.exit(0);
    }
    if (payload.type === "error") {
      process.stderr.write(`[remote-error] ${payload.error}\n`);
      if (args) {
        reportProgress(args, "remote-error", String(payload.error || "").slice(0, 180), "", { throttle: false });
      }
    }
  };

  channel.onclose = () => {
    if (keepaliveTimer) {
      clearInterval(keepaliveTimer);
    }
    process.stderr.write("[channel-closed]\n");
    process.exit(0);
  };

  channel.onerror = () => {
    process.stderr.write("[channel-error]\n");
  };

  keepaliveTimer = setInterval(() => {
    if (channel.readyState !== "open") {
      return;
    }
    channel.send(JSON.stringify({ type: "ping", ts: Date.now() }));
  }, 15000);
  keepaliveTimer.unref?.();

  peerConnection.onconnectionstatechange = () => {
    process.stderr.write(`[connection-state] ${peerConnection.connectionState}\n`);
    if (peerConnection.connectionState === "failed" || peerConnection.connectionState === "closed") {
      process.exit(1);
    }
  };

  process.stderr.write("[connected] data channel open\n");
  process.stderr.write("Type commands. Use /ctrlc to send Ctrl+C, /exit to close.\n");

  if (!interactive) {
    return;
  }

  const lineReader = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: "remote$ ",
  });

  const sendResize = () => {
    if (channel.readyState !== "open") {
      return;
    }
    if (process.stdout.isTTY) {
      channel.send(
        JSON.stringify({
          type: "resize",
          cols: process.stdout.columns || 120,
          rows: process.stdout.rows || 36,
        }),
      );
    }
  };

  sendResize();
  process.stdout.on("resize", sendResize);
  lineReader.prompt();

  lineReader.on("line", (line) => {
    if (channel.readyState !== "open") {
      lineReader.close();
      return;
    }
    if (line === "/exit") {
      lineReader.close();
      return;
    }
    if (line === "/ctrlc") {
      channel.send(JSON.stringify({ type: "stdin", data: "\u0003" }));
      if (args) {
        reportProgress(args, "command", "/ctrlc", "", { throttle: false });
      }
      lineReader.prompt();
      return;
    }
    if (args) {
      reportProgress(args, "command", line.slice(0, 180), "", { throttle: false });
    }
    channel.send(JSON.stringify({ type: "stdin", data: `${line}\n` }));
    lineReader.prompt();
  });

  lineReader.on("close", () => {
    try {
      channel.close();
    } catch {
      // noop
    }
    try {
      peerConnection.close();
    } catch {
      // noop
    }
    process.exit(0);
  });
}

async function runMachineA(args) {
  const RTCPeerConnectionCtor = await resolveWrtcCtor();
  const fallbackIceServers = parseIceServers(
    args.iceServers || process.env.WEBRTC_MCP_ICE_SERVERS || DEFAULT_ICE_SERVERS_JSON,
  );

  const rendezvous = await createRendezvous({
    signalingBaseUrl: args.signalingUrl,
    signalingToken: args.signalingToken,
    passKey: args.passKey,
    peerId: args.peerId,
  });
  args._peerId = rendezvous.peerId;
  await reportProgress(args, "rendezvous-ready");
  const sessionIceServers = mergeIceServers(rendezvous.turn?.iceServers, fallbackIceServers);
  if (Array.isArray(rendezvous.turn?.iceServers) && rendezvous.turn.iceServers.length > 0) {
    process.stderr.write(`[signaling] TURN credentials received (${rendezvous.turn.iceServers.length} ice entries)\n`);
  } else {
    process.stderr.write("[signaling] TURN credentials not returned; using configured ICE fallback\n");
  }

  const ws = await openSocket(rendezvous.wsUrl);
  process.stderr.write(`[signaling] connected as ${rendezvous.peerId}\n`);
  await reportProgress(args, "signaling-connected");

  const peerConnection = new RTCPeerConnectionCtor({ iceServers: sessionIceServers });
  const channel = peerConnection.createDataChannel("terminal", { ordered: true });

  let targetPeer = null;
  let offerSent = false;
  let answerResolved = false;

  const offerAndSend = async () => {
    if (!targetPeer || offerSent) {
      return;
    }
    offerSent = true;

    const offer = await peerConnection.createOffer();
    await peerConnection.setLocalDescription(offer);
    const gatheredComplete = await waitForIceGatheringComplete(peerConnection);
    if (!gatheredComplete) {
      process.stderr.write("[warning] ICE gathering timed out; continuing with partial offer SDP\n");
    }

    const offerSdp = peerConnection.localDescription?.sdp;
    if (!offerSdp) {
      throw new Error("offer SDP missing");
    }

    ws.send(
      JSON.stringify({
        type: "offer",
        target: targetPeer,
        payload: offerSdp,
      }),
    );
    process.stderr.write(`[signaling] offer sent to ${targetPeer}\n`);
    await reportProgress(args, "offer-sent", `target=${targetPeer}`);
  };

  const answerPromise = new Promise((resolve, reject) => {
    ws.on("message", async (raw) => {
      const message = parseWsMessage(raw);
      if (!message || typeof message !== "object") {
        return;
      }

      if (message.type === "welcome" && Array.isArray(message.peers)) {
        const candidate = message.peers.find((p) => typeof p === "string" && p !== rendezvous.peerId);
        if (candidate) {
          targetPeer = candidate;
          try {
            await offerAndSend();
          } catch (error) {
            reject(error);
          }
        }
        return;
      }

      if (message.type === "peer-joined" && typeof message.peerId === "string" && message.peerId !== rendezvous.peerId) {
        if (!targetPeer) {
          targetPeer = message.peerId;
          try {
            await offerAndSend();
          } catch (error) {
            reject(error);
          }
        }
        return;
      }

      if (message.type === "answer" && typeof message.from === "string") {
        if (targetPeer && message.from !== targetPeer) {
          return;
        }
        const answerSdp = typeof message.payload === "string" ? message.payload : message.payload?.sdp;
        if (!answerSdp || answerResolved) {
          return;
        }
        answerResolved = true;
        resolve(answerSdp);
        return;
      }

      if (message.type === "error") {
        process.stderr.write(`[signaling-error] ${message.error || "unknown"}\n`);
      }
    });

    ws.on("error", (error) => {
      reject(error);
    });

    ws.on("close", () => {
      if (!answerResolved) {
        reject(new Error("signaling websocket closed before answer"));
      }
    });
  });

  const answerSdp = await answerPromise;
  await peerConnection.setRemoteDescription({
    type: "answer",
    sdp: answerSdp,
  });

  await waitForDataChannelOpen(channel);
  await reportProgress(args, "datachannel-open");
  installChannelHandlers(channel, peerConnection, { args });
}

async function runMachineB(args) {
  await ensureLocalPassKey(args.importUrl, args.passKey);
  process.stderr.write("[local] pass key imported to local server\n");
  await reportProgress(args, "local-imported");

  const fallbackIceServers = parseIceServers(
    args.iceServers || process.env.WEBRTC_MCP_ICE_SERVERS || DEFAULT_ICE_SERVERS_JSON,
  );

  const rendezvous = await createRendezvous({
    signalingBaseUrl: args.signalingUrl,
    signalingToken: args.signalingToken,
    passKey: args.passKey,
    peerId: args.peerId,
  });
  args._peerId = rendezvous.peerId;
  await reportProgress(args, "rendezvous-ready");
  const sessionIceServers = mergeIceServers(rendezvous.turn?.iceServers, fallbackIceServers);
  if (Array.isArray(rendezvous.turn?.iceServers) && rendezvous.turn.iceServers.length > 0) {
    process.stderr.write(`[signaling] TURN credentials received (${rendezvous.turn.iceServers.length} ice entries)\n`);
  } else {
    process.stderr.write("[signaling] TURN credentials not returned; local server will use configured ICE fallback\n");
  }

  const ws = await openSocket(rendezvous.wsUrl);
  process.stderr.write(`[signaling] ready as ${rendezvous.peerId}; waiting for offer...\n`);
  await reportProgress(args, "signaling-connected");

  ws.on("message", async (raw) => {
    const message = parseWsMessage(raw);
    if (!message || typeof message !== "object") {
      return;
    }

    if (message.type !== "offer" || typeof message.from !== "string") {
      return;
    }

    const offerSdp = typeof message.payload === "string" ? message.payload : message.payload?.sdp;
    if (!offerSdp) {
      process.stderr.write("[warning] received offer without SDP\n");
      return;
    }

    process.stderr.write(`[signaling] received offer from ${message.from}; creating answer...\n`);

    const connectResult = await postJson(args.connectUrl, {
      passKey: args.passKey,
      offerSdp,
      label: "hosted-auto",
      iceServers: sessionIceServers,
    });

    if (!connectResult.ok || typeof connectResult.body?.answerSdp !== "string") {
      process.stderr.write(
        `[error] local /api/connect failed (${connectResult.status}): ${JSON.stringify(connectResult.body)}\n`,
      );
      await reportProgress(args, "connect-error", `status=${connectResult.status}`);
      return;
    }

    ws.send(
      JSON.stringify({
        type: "answer",
        target: message.from,
        payload: connectResult.body.answerSdp,
      }),
    );
    process.stderr.write(`[signaling] answer sent to ${message.from}\n`);
    await reportProgress(args, "answer-sent", `target=${message.from}`);
  });

  ws.on("error", (error) => {
    process.stderr.write(`[signaling-error] ${error.message}\n`);
    process.exit(1);
  });

  ws.on("close", () => {
    process.stderr.write("[signaling] closed\n");
    process.exit(1);
  });

  // Keep process alive.
  await new Promise(() => {});
}

async function runAuto(args) {
  const RTCPeerConnectionCtor = await resolveWrtcCtor();
  const fallbackIceServers = parseIceServers(
    args.iceServers || process.env.WEBRTC_MCP_ICE_SERVERS || DEFAULT_ICE_SERVERS_JSON,
  );

  await ensureLocalPassKey(args.importUrl, args.passKey);
  process.stderr.write("[local] pass key imported to local server\n");
  await reportProgress(args, "local-imported");

  const rendezvous = await createRendezvous({
    signalingBaseUrl: args.signalingUrl,
    signalingToken: args.signalingToken,
    passKey: args.passKey,
    peerId: args.peerId,
  });
  args._peerId = rendezvous.peerId;
  await reportProgress(args, "rendezvous-ready");
  const sessionIceServers = mergeIceServers(rendezvous.turn?.iceServers, fallbackIceServers);
  if (Array.isArray(rendezvous.turn?.iceServers) && rendezvous.turn.iceServers.length > 0) {
    process.stderr.write(`[signaling] TURN credentials received (${rendezvous.turn.iceServers.length} ice entries)\n`);
  } else {
    process.stderr.write("[signaling] TURN credentials not returned; using configured ICE fallback\n");
  }

  const ws = await openSocket(rendezvous.wsUrl);
  process.stderr.write(`[signaling] connected as ${rendezvous.peerId}\n`);
  await reportProgress(args, "signaling-connected");

  const peers = new Map();
  let interactivePeerId = null;

  const getRoleForPeer = (peerId) => (rendezvous.peerId < peerId ? "offerer" : "answerer");

  const ensurePeer = (peerId) => {
    if (!peerId || peerId === rendezvous.peerId) {
      return null;
    }
    if (peers.has(peerId)) {
      return peers.get(peerId);
    }
    const role = getRoleForPeer(peerId);
    const entry = {
      peerId,
      role,
      pc: null,
      channel: null,
      offerSent: false,
      answerSent: false,
    };
    peers.set(peerId, entry);
    reportProgress(args, "role-selected", `role=${role}`, role);
    return entry;
  };

  const sendOfferToPeer = async (entry) => {
    if (!entry || entry.role !== "offerer" || entry.offerSent) {
      return;
    }
    entry.offerSent = true;
    entry.pc = new RTCPeerConnectionCtor({ iceServers: sessionIceServers });
    entry.channel = entry.pc.createDataChannel("terminal", { ordered: true });

    const offer = await entry.pc.createOffer();
    await entry.pc.setLocalDescription(offer);
    const gatheredComplete = await waitForIceGatheringComplete(entry.pc);
    if (!gatheredComplete) {
      process.stderr.write("[warning] ICE gathering timed out; continuing with partial offer SDP\n");
    }

    const offerSdp = entry.pc.localDescription?.sdp;
    if (!offerSdp) {
      throw new Error("offer SDP missing");
    }

    ws.send(
      JSON.stringify({
        type: "offer",
        target: entry.peerId,
        payload: offerSdp,
      }),
    );
    process.stderr.write(`[signaling] offer sent to ${entry.peerId}\n`);
    await reportProgress(args, "offer-sent", `target=${entry.peerId}`, entry.role);
  };

  ws.on("message", async (raw) => {
    const message = parseWsMessage(raw);
    if (!message || typeof message !== "object") {
      return;
    }

    if (message.type === "welcome" && Array.isArray(message.peers)) {
      for (const peerId of message.peers) {
        if (typeof peerId !== "string") continue;
        const entry = ensurePeer(peerId);
        if (entry && entry.role === "offerer") {
          await sendOfferToPeer(entry);
        }
      }
      return;
    }

    if (message.type === "peer-joined" && typeof message.peerId === "string" && message.peerId !== rendezvous.peerId) {
      const entry = ensurePeer(message.peerId);
      if (entry && entry.role === "offerer") {
        await sendOfferToPeer(entry);
      }
      return;
    }

    if (message.type === "offer" && typeof message.from === "string") {
      const entry = ensurePeer(message.from);
      if (!entry || entry.role !== "answerer") {
        return;
      }

      const offerSdp = typeof message.payload === "string" ? message.payload : message.payload?.sdp;
      if (!offerSdp) {
        process.stderr.write("[warning] received offer without SDP\n");
        return;
      }

      const connectResult = await postJson(args.connectUrl, {
        passKey: args.passKey,
        offerSdp,
        label: "hosted-auto",
        iceServers: sessionIceServers,
        multi: true,
      });

      if (!connectResult.ok || typeof connectResult.body?.answerSdp !== "string") {
        process.stderr.write(
          `[error] local /api/connect failed (${connectResult.status}): ${JSON.stringify(connectResult.body)}\n`,
        );
        await reportProgress(args, "connect-error", `status=${connectResult.status}`);
        return;
      }

      ws.send(
        JSON.stringify({
          type: "answer",
          target: message.from,
          payload: connectResult.body.answerSdp,
        }),
      );
      entry.answerSent = true;
      process.stderr.write(`[signaling] answer sent to ${message.from}\n`);
      await reportProgress(args, "answer-sent", `target=${message.from}`, entry.role);
      return;
    }

    if (message.type === "answer" && typeof message.from === "string") {
      const entry = peers.get(message.from);
      if (!entry || entry.role !== "offerer") {
        return;
      }
      const answerSdp = typeof message.payload === "string" ? message.payload : message.payload?.sdp;
      if (!answerSdp || !entry.pc || !entry.channel) {
        return;
      }

      await entry.pc.setRemoteDescription({
        type: "answer",
        sdp: answerSdp,
      });
      await waitForDataChannelOpen(entry.channel);
      await reportProgress(args, "datachannel-open", `peer=${message.from}`, entry.role);
      if (!interactivePeerId) {
        interactivePeerId = message.from;
      }
      const isInteractive = interactivePeerId === message.from;
      const labelPrefix = isInteractive ? "" : `[${message.from}]`;
      installChannelHandlers(entry.channel, entry.pc, { interactive: isInteractive, labelPrefix, args });
      return;
    }

    if (message.type === "error") {
      process.stderr.write(`[signaling-error] ${message.error || "unknown"}\n`);
    }
  });

  ws.on("error", (error) => {
    process.stderr.write(`[signaling-error] ${error.message}\n`);
    process.exit(1);
  });

  ws.on("close", () => {
    process.stderr.write("[signaling] closed\n");
    process.exit(1);
  });

  await new Promise(() => {});
}

async function main() {
  let args;
  try {
    args = parseCliArgs(
      process.argv.slice(2),
      new Map([
        ["--role", "role"],
        ["--pass-key", "passKey"],
        ["--signaling-url", "signalingUrl"],
        ["--signaling-token", "signalingToken"],
        ["--connect-url", "connectUrl"],
        ["--import-url", "importUrl"],
        ["--peer-id", "peerId"],
        ["--ice-servers", "iceServers"],
      ]),
    );
  } catch (error) {
    console.error(error.message);
    usage();
  }

  if (args.help) {
    usage(0);
  }

  if (!args.role) {
    args.role = "auto";
  }
  if (args.role !== "auto" && args.role !== "machine_a" && args.role !== "machine_b") {
    console.error("Error: --role must be auto, machine_a, or machine_b");
    usage();
  }

  if (!args.passKey) {
    args.passKey = DEFAULT_PAIR_KEY || (await askLine("Enter shared pair pass key: "));
  }
  args.passKey = normalizePassKey(args.passKey);

  args.signalingUrl = args.signalingUrl || DEFAULT_SIGNALING_BASE_URL;
  args.signalingToken = args.signalingToken || DEFAULT_SIGNALING_TOKEN;
  args.connectUrl = args.connectUrl || DEFAULT_LOCAL_CONNECT_URL;
  args.importUrl = args.importUrl || DEFAULT_LOCAL_IMPORT_URL;

  if (args.role === "machine_a") {
    await runMachineA(args);
    return;
  }
  if (args.role === "auto") {
    await runAuto(args);
    return;
  }
  await runMachineB(args);
}

main().catch((error) => {
  console.error(`hosted_pair_client failed: ${error.message}`);
  process.exit(1);
});
