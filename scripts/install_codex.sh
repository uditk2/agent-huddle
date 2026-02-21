#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

codex mcp add webrtc-terminal -- node "$REPO_DIR/src/index.js"

echo "Codex MCP server installed: webrtc-terminal"
