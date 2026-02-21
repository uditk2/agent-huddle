#!/usr/bin/env node

import process from "node:process";
import readline from "node:readline";
import {
  DEFAULT_ICE_SERVERS_JSON,
  decodeBlob,
  encodeBlob,
  parseCliArgs,
  parseIceServers,
} from "./manual_signaling_utils.js";

function usage(exitCode = 1) {
  console.error(
    "Usage: node scripts/manual_offer_client.js --pass-key <PASSKEY> [--connect-url <URL>] [--ice-servers '<JSON>']",
  );
  process.exit(exitCode);
}

function waitForIceGatheringComplete(peerConnection, timeoutMs = 10000) {
  if (peerConnection.iceGatheringState === "complete") {
    return Promise.resolve();
  }

  return new Promise((resolve, reject) => {
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

function askLine(prompt) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

function safeJsonParse(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function main() {
  let args;
  try {
    args = parseCliArgs(
      process.argv.slice(2),
      new Map([
        ["--pass-key", "passKey"],
        ["--connect-url", "connectUrl"],
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
  if (!args.passKey || !args.passKey.trim()) {
    usage();
  }

  let RTCPeerConnectionCtor;
  try {
    const wrtcImport = await import("@roamhq/wrtc");
    const wrtcAny = {
      ...(wrtcImport.default ?? {}),
      ...wrtcImport,
    };
    RTCPeerConnectionCtor = wrtcAny.RTCPeerConnection;
    if (!RTCPeerConnectionCtor) {
      throw new Error("RTCPeerConnection not found in @roamhq/wrtc");
    }
  } catch (error) {
    console.error(`Failed to load WebRTC runtime: ${error.message}`);
    process.exit(1);
  }

  const iceServers = parseIceServers(
    args.iceServers || process.env.WEBRTC_MCP_ICE_SERVERS || DEFAULT_ICE_SERVERS_JSON,
  );

  const peerConnection = new RTCPeerConnectionCtor({
    iceServers,
  });
  const channel = peerConnection.createDataChannel("terminal", { ordered: true });
  let keepaliveTimer = null;
  let disconnectGraceTimer = null;

  const clearDisconnectGrace = () => {
    if (!disconnectGraceTimer) {
      return;
    }
    clearTimeout(disconnectGraceTimer);
    disconnectGraceTimer = null;
  };

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
      return;
    }
  };

  channel.onclose = () => {
    process.stderr.write("[channel-closed]\n");
    process.exit(0);
  };

  channel.onerror = () => {
    process.stderr.write("[channel-error]\n");
  };

  const offer = await peerConnection.createOffer();
  await peerConnection.setLocalDescription(offer);
  await waitForIceGatheringComplete(peerConnection);

  const offerSdp = peerConnection.localDescription?.sdp;
  if (!offerSdp) {
    throw new Error("offer SDP missing");
  }

  const offerBlob = encodeBlob({
    version: 1,
    passKey: args.passKey.trim(),
    connectEndpoint: args.connectUrl?.trim() || null,
    offerSdp,
    createdAt: new Date().toISOString(),
  });

  process.stdout.write("\nCopy this line to machine B:\n");
  process.stdout.write(`OFFER_BLOB=${offerBlob}\n\n`);

  const answerBlob = await askLine("Paste ANSWER_BLOB line from machine B and press Enter:\n");
  const parsedAnswer = decodeBlob(answerBlob, "answer blob");
  if (!parsedAnswer || typeof parsedAnswer.answerSdp !== "string") {
    throw new Error("Invalid answer blob");
  }

  await peerConnection.setRemoteDescription({
    type: "answer",
    sdp: parsedAnswer.answerSdp,
  });

  await waitForDataChannelOpen(channel);
  keepaliveTimer = setInterval(() => {
    if (channel.readyState !== "open") {
      return;
    }
    channel.send(JSON.stringify({ type: "ping", ts: Date.now() }));
  }, 15000);
  keepaliveTimer.unref?.();

  peerConnection.onconnectionstatechange = () => {
    const state = peerConnection.connectionState;
    process.stderr.write(`[connection-state] ${state}\n`);

    if (state === "connected") {
      clearDisconnectGrace();
      return;
    }

    if (state === "disconnected") {
      clearDisconnectGrace();
      disconnectGraceTimer = setTimeout(() => {
        process.stderr.write("[connection-state] disconnected for >60s, closing\n");
        process.exit(1);
      }, 60000);
      return;
    }

    if (state === "failed" || state === "closed") {
      process.exit(1);
    }
  };

  process.stderr.write("[connected] data channel open\n");
  process.stderr.write("Type commands. Use /ctrlc to send Ctrl+C, /exit to close.\n");

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
      lineReader.prompt();
      return;
    }
    channel.send(JSON.stringify({ type: "stdin", data: `${line}\n` }));
    lineReader.prompt();
  });

  lineReader.on("close", () => {
    clearDisconnectGrace();
    if (keepaliveTimer) {
      clearInterval(keepaliveTimer);
      keepaliveTimer = null;
    }
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

main().catch((error) => {
  console.error(`manual_offer_client failed: ${error.message}`);
  process.exit(1);
});
