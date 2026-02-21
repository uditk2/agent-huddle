#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAUNCHER="$REPO_DIR/scripts/run_mcp.sh"

if ! command -v npm >/dev/null 2>&1; then
  echo "Error: 'npm' is not installed or not in PATH."
  exit 1
fi

echo "Installing dependencies (npm install)..."
(
  cd "$REPO_DIR"
  npm install --no-audit --no-fund
)

codex mcp add webrtc-terminal -- "$LAUNCHER"

echo "Codex MCP server installed: webrtc-terminal"
