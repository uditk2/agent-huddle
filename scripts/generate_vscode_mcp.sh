#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREPARE_SCRIPT="$REPO_DIR/scripts/prepare_runtime.sh"
SERVER_NAME="webrtc-terminal"
OUTPUT_PATH="${1:-$REPO_DIR/.vscode/mcp.json}"
RUNTIME_DIR_ARG="${2:-}"

if [[ ! -x "$PREPARE_SCRIPT" ]]; then
  echo "Error: missing executable prepare script: $PREPARE_SCRIPT"
  exit 1
fi

if [[ -n "$RUNTIME_DIR_ARG" ]]; then
  RUNTIME_DIR="$($PREPARE_SCRIPT "$RUNTIME_DIR_ARG")"
else
  RUNTIME_DIR="$($PREPARE_SCRIPT)"
fi

LAUNCHER="$RUNTIME_DIR/scripts/run_mcp.sh"
if [[ ! -x "$LAUNCHER" ]]; then
  echo "Error: launcher not found in runtime dir: $LAUNCHER"
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"

OUTPUT_PATH="$OUTPUT_PATH" LAUNCHER="$LAUNCHER" SERVER_NAME="$SERVER_NAME" node <<'NODE'
const fs = require("node:fs");

const outputPath = process.env.OUTPUT_PATH;
const launcher = process.env.LAUNCHER;
const serverName = process.env.SERVER_NAME;

let doc = {};
if (fs.existsSync(outputPath)) {
  const raw = fs.readFileSync(outputPath, "utf8").trim();
  if (raw) {
    try {
      doc = JSON.parse(raw);
    } catch (error) {
      console.error(`Error: ${outputPath} is not valid JSON: ${error.message}`);
      process.exit(1);
    }
  }
}

if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
  console.error(`Error: ${outputPath} must contain a JSON object.`);
  process.exit(1);
}

if (!doc.servers || typeof doc.servers !== "object" || Array.isArray(doc.servers)) {
  doc.servers = {};
}

const existingServer = doc.servers[serverName];
const existingEnv =
  existingServer &&
  typeof existingServer === "object" &&
  !Array.isArray(existingServer) &&
  existingServer.env &&
  typeof existingServer.env === "object" &&
  !Array.isArray(existingServer.env)
    ? existingServer.env
    : {};

doc.servers[serverName] = {
  type: "stdio",
  command: launcher,
  args: [],
  env: {
    ...existingEnv,
    WEBRTC_MCP_HTTP_HOST: "127.0.0.1",
    WEBRTC_MCP_HTTP_PORT: "8787",
  },
};

fs.writeFileSync(outputPath, `${JSON.stringify(doc, null, 2)}\n`, "utf8");
NODE

ADD_MCP_PAYLOAD="$(LAUNCHER="$LAUNCHER" SERVER_NAME="$SERVER_NAME" node <<'NODE'
const launcher = process.env.LAUNCHER;
const serverName = process.env.SERVER_NAME;

const payload = {
  name: serverName,
  command: launcher,
  args: [],
  env: {
    WEBRTC_MCP_HTTP_HOST: "127.0.0.1",
    WEBRTC_MCP_HTTP_PORT: "8787",
  },
};

process.stdout.write(JSON.stringify(payload));
NODE
)"

echo "Runtime dir: $RUNTIME_DIR"
echo "VS Code workspace MCP config updated: $OUTPUT_PATH"
echo ""
echo "Optional user-profile install via VS Code CLI:"
echo "  code --add-mcp '$ADD_MCP_PAYLOAD'"
