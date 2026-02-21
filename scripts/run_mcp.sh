#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="${WEBRTC_MCP_LOG_FILE:-$REPO_DIR/.webrtc-terminal-mcp.log}"
NODE_BIN="${WEBRTC_MCP_NODE_BIN:-}"

if [[ -z "$NODE_BIN" ]]; then
  if command -v node >/dev/null 2>&1; then
    NODE_BIN="$(command -v node)"
  elif [[ -x "/opt/homebrew/bin/node" ]]; then
    NODE_BIN="/opt/homebrew/bin/node"
  elif [[ -x "/usr/local/bin/node" ]]; then
    NODE_BIN="/usr/local/bin/node"
  fi
fi

if [[ -z "$NODE_BIN" || ! -x "$NODE_BIN" ]]; then
  echo "[webrtc-terminal-mcp] node is not installed or not in PATH (PATH=$PATH)" | tee -a "$LOG_FILE" >&2
  exit 1
fi

if [[ ! -d "$REPO_DIR/node_modules" ]]; then
  echo "[webrtc-terminal-mcp] dependencies missing; run: cd \"$REPO_DIR\" && npm install" | tee -a "$LOG_FILE" >&2
  exit 1
fi

echo "[webrtc-terminal-mcp] launcher starting at $(date -u +%Y-%m-%dT%H:%M:%SZ) (node=$NODE_BIN)" >>"$LOG_FILE"
exec "$NODE_BIN" "$REPO_DIR/src/index.js" 2>>"$LOG_FILE"
