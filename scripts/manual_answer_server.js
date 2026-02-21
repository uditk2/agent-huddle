#!/usr/bin/env node

import process from "node:process";
import { decodeBlob, encodeBlob, parseCliArgs, postJson, readAllStdin } from "./manual_signaling_utils.js";

const DEFAULT_CONNECT_URL = process.env.WEBRTC_MCP_CONNECT_URL || "http://127.0.0.1:8787/api/connect";

function usage(exitCode = 1) {
  console.error("Usage: node scripts/manual_answer_server.js [--connect-url <URL>] [--blob <OFFER_BLOB>]");
  process.exit(exitCode);
}

async function main() {
  let args;
  try {
    args = parseCliArgs(
      process.argv.slice(2),
      new Map([
        ["--connect-url", "connectUrl"],
        ["--blob", "blob"],
      ]),
    );
  } catch (error) {
    console.error(error.message);
    usage();
  }
  if (args.help) {
    usage(0);
  }
  const blob = args.blob || (await readAllStdin());
  if (!blob) {
    console.error("Missing offer blob. Pass --blob <OFFER_BLOB> or pipe it via stdin.");
    process.exit(1);
  }

  const decoded = decodeBlob(blob, "offer blob");
  if (!decoded || typeof decoded.passKey !== "string" || typeof decoded.offerSdp !== "string") {
    console.error("Invalid offer blob payload. Expected { passKey, offerSdp }.");
    process.exit(1);
  }

  const connectUrl =
    args.connectUrl ||
    (typeof decoded.connectEndpoint === "string" && decoded.connectEndpoint.trim()) ||
    DEFAULT_CONNECT_URL;

  const result = await postJson(connectUrl, {
    passKey: decoded.passKey,
    offerSdp: decoded.offerSdp,
    label: "manual-copy-paste",
  });

  if (!result.ok) {
    console.error(`Connect failed (${result.status}): ${JSON.stringify(result.body)}`);
    process.exit(1);
  }

  if (typeof result.body.answerSdp !== "string") {
    console.error("Connect response missing answerSdp");
    process.exit(1);
  }

  const answerBlob = encodeBlob({
    version: 1,
    answerSdp: result.body.answerSdp,
    sessionId: result.body.sessionId || null,
    expiresAt: result.body.expiresAt || null,
    createdAt: new Date().toISOString(),
  });

  process.stdout.write("Copy this line back to machine A:\n");
  process.stdout.write(`ANSWER_BLOB=${answerBlob}\n`);
}

main().catch((error) => {
  console.error(`manual_answer_server failed: ${error.message}`);
  process.exit(1);
});
