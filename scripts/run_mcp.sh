#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="${WEBRTC_MCP_LOG_FILE:-$REPO_DIR/.webrtc-terminal-mcp.log}"

if ! command -v node >/dev/null 2>&1; then
  echo "[webrtc-terminal-mcp] node is not installed or not in PATH" | tee -a "$LOG_FILE" >&2
  exit 1
fi

if [[ ! -d "$REPO_DIR/node_modules" ]]; then
  echo "[webrtc-terminal-mcp] dependencies missing; run: cd \"$REPO_DIR\" && npm install" | tee -a "$LOG_FILE" >&2
  exit 1
fi

echo "[webrtc-terminal-mcp] launcher starting at $(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$LOG_FILE"
exec node "$REPO_DIR/src/index.js" 2>>"$LOG_FILE"
