#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_RUNTIME_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/agent-huddle/webrtc-terminal-mcp"
RUNTIME_DIR="${1:-${WEBRTC_MCP_RUNTIME_DIR:-$DEFAULT_RUNTIME_DIR}}"

if ! command -v npm >/dev/null 2>&1; then
  echo "Error: 'npm' is not installed or not in PATH." >&2
  exit 1
fi

mkdir -p "$RUNTIME_DIR"

if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete \
    --exclude ".git/" \
    --exclude "node_modules/" \
    --exclude ".mcp.json" \
    --exclude ".webrtc-terminal-mcp.log" \
    "$REPO_DIR/" "$RUNTIME_DIR/"
else
  tar -C "$REPO_DIR" \
    --exclude ".git" \
    --exclude "node_modules" \
    --exclude ".mcp.json" \
    --exclude ".webrtc-terminal-mcp.log" \
    -cf - . | tar -C "$RUNTIME_DIR" -xf -
fi

echo "Installing dependencies in isolated runtime: $RUNTIME_DIR" >&2
(
  cd "$RUNTIME_DIR"
  npm install --no-audit --no-fund 1>&2
)

echo "$RUNTIME_DIR"
