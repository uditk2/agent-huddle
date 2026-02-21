#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAUNCHER="$REPO_DIR/scripts/run_mcp.sh"

codex mcp add webrtc-terminal -- "$LAUNCHER"

echo "Codex MCP server installed: webrtc-terminal"
