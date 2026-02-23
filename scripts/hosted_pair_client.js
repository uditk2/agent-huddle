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

function installChannelHandlers(channel, peerConnection) {
  let keepaliveTimer = null;

  channel.onmessage = (event) => {
    const text = typeof event.data === "string" ? event.data : event.data?.toString("utf8") || "";
    const payload = safeJsonParse(text);
    if (!payload) {
      process.stdout.write(text);
      return;
    }

    if (payload.type === "stdout" && typeof payload.data === "string") {
      process.stdout.write(payload.data);
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
  process.stderr.write("[connected] data channel open\n");
  process.stderr.write("Type commands. Use /ctrlc to send Ctrl+C, /exit to close.\n");
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
      lineReader.prompt();
      return;
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
  const sessionIceServers = mergeIceServers(rendezvous.turn?.iceServers, fallbackIceServers);
  if (Array.isArray(rendezvous.turn?.iceServers) && rendezvous.turn.iceServers.length > 0) {
    process.stderr.write(`[signaling] TURN credentials received (${rendezvous.turn.iceServers.length} ice entries)\n`);
  } else {
    process.stderr.write("[signaling] TURN credentials not returned; using configured ICE fallback\n");
  }

  const ws = await openSocket(rendezvous.wsUrl);
  process.stderr.write(`[signaling] connected as ${rendezvous.peerId}\n`);

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
  installChannelHandlers(channel, peerConnection);
}

async function runMachineB(args) {
  await ensureLocalPassKey(args.importUrl, args.passKey);
  process.stderr.write("[local] pass key imported to local server\n");

  const fallbackIceServers = parseIceServers(
    args.iceServers || process.env.WEBRTC_MCP_ICE_SERVERS || DEFAULT_ICE_SERVERS_JSON,
  );

  const rendezvous = await createRendezvous({
    signalingBaseUrl: args.signalingUrl,
    signalingToken: args.signalingToken,
    passKey: args.passKey,
    peerId: args.peerId,
  });
  const sessionIceServers = mergeIceServers(rendezvous.turn?.iceServers, fallbackIceServers);
  if (Array.isArray(rendezvous.turn?.iceServers) && rendezvous.turn.iceServers.length > 0) {
    process.stderr.write(`[signaling] TURN credentials received (${rendezvous.turn.iceServers.length} ice entries)\n`);
  } else {
    process.stderr.write("[signaling] TURN credentials not returned; local server will use configured ICE fallback\n");
  }

  const ws = await openSocket(rendezvous.wsUrl);
  process.stderr.write(`[signaling] ready as ${rendezvous.peerId}; waiting for offer...\n`);

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

  const rendezvous = await createRendezvous({
    signalingBaseUrl: args.signalingUrl,
    signalingToken: args.signalingToken,
    passKey: args.passKey,
    peerId: args.peerId,
  });
  const sessionIceServers = mergeIceServers(rendezvous.turn?.iceServers, fallbackIceServers);
  if (Array.isArray(rendezvous.turn?.iceServers) && rendezvous.turn.iceServers.length > 0) {
    process.stderr.write(`[signaling] TURN credentials received (${rendezvous.turn.iceServers.length} ice entries)\n`);
  } else {
    process.stderr.write("[signaling] TURN credentials not returned; using configured ICE fallback\n");
  }

  const ws = await openSocket(rendezvous.wsUrl);
  process.stderr.write(`[signaling] connected as ${rendezvous.peerId}\n`);

  const peerConnection = new RTCPeerConnectionCtor({ iceServers: sessionIceServers });
  let channel = null;
  let targetPeer = null;
  let role = null;
  let offerSent = false;
  let answerSent = false;

  const chooseRole = () => {
    if (role || !targetPeer) {
      return;
    }
    role = rendezvous.peerId < targetPeer ? "offerer" : "answerer";
    process.stderr.write(`[auto-role] ${role} (self=${rendezvous.peerId} peer=${targetPeer})\n`);
  };

  const maybeSendOffer = async () => {
    if (role !== "offerer" || offerSent || !targetPeer) {
      return;
    }
    offerSent = true;
    channel = peerConnection.createDataChannel("terminal", { ordered: true });

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
  };

  ws.on("message", async (raw) => {
    const message = parseWsMessage(raw);
    if (!message || typeof message !== "object") {
      return;
    }

    if (message.type === "welcome" && Array.isArray(message.peers)) {
      const candidate = message.peers.find((p) => typeof p === "string" && p !== rendezvous.peerId);
      if (candidate) {
        targetPeer = candidate;
        chooseRole();
        await maybeSendOffer();
      }
      return;
    }

    if (message.type === "peer-joined" && typeof message.peerId === "string" && message.peerId !== rendezvous.peerId) {
      if (!targetPeer) {
        targetPeer = message.peerId;
        chooseRole();
        await maybeSendOffer();
      }
      return;
    }

    if (message.type === "offer" && typeof message.from === "string") {
      if (!targetPeer) {
        targetPeer = message.from;
      }
      chooseRole();
      if (role !== "answerer") {
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
      });

      if (!connectResult.ok || typeof connectResult.body?.answerSdp !== "string") {
        process.stderr.write(
          `[error] local /api/connect failed (${connectResult.status}): ${JSON.stringify(connectResult.body)}\n`,
        );
        return;
      }

      ws.send(
        JSON.stringify({
          type: "answer",
          target: message.from,
          payload: connectResult.body.answerSdp,
        }),
      );
      answerSent = true;
      process.stderr.write(`[signaling] answer sent to ${message.from}\n`);
      // Host side can exit after answer delivery; terminal session is now local MCP-managed.
      setTimeout(() => process.exit(0), 1000).unref?.();
      return;
    }

    if (message.type === "answer" && typeof message.from === "string") {
      if (role !== "offerer") {
        return;
      }
      if (targetPeer && message.from !== targetPeer) {
        return;
      }
      const answerSdp = typeof message.payload === "string" ? message.payload : message.payload?.sdp;
      if (!answerSdp || !channel) {
        return;
      }

      await peerConnection.setRemoteDescription({
        type: "answer",
        sdp: answerSdp,
      });
      await waitForDataChannelOpen(channel);
      installChannelHandlers(channel, peerConnection);
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
    if (answerSent) {
      process.exit(0);
    }
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
