#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCOPE="${1:-project}"
SERVER_NAME="webrtc-terminal"
SERVER_CMD="$REPO_DIR/scripts/run_mcp.sh"

if ! command -v claude >/dev/null 2>&1; then
  echo "Error: 'claude' CLI is not installed or not in PATH."
  exit 1
fi

if [[ "$SCOPE" != "project" && "$SCOPE" != "user" && "$SCOPE" != "local" ]]; then
  echo "Usage: $0 [project|user|local]"
  exit 1
fi

# Remove existing entry in the selected scope to keep install idempotent.
claude mcp remove "$SERVER_NAME" -s "$SCOPE" >/dev/null 2>&1 || true

claude mcp add -s "$SCOPE" "$SERVER_NAME" -- "$SERVER_CMD"

echo "Claude Code MCP server installed:"
claude mcp get "$SERVER_NAME"

if [[ "$SCOPE" == "user" && -f "$REPO_DIR/.mcp.json" ]] && rg -q "\"$SERVER_NAME\"" "$REPO_DIR/.mcp.json"; then
  echo "Note: project scope also has '$SERVER_NAME'. User scope may be shadowed in this repo."
  echo "If needed, remove project scope with: claude mcp remove \"$SERVER_NAME\" -s project"
fi
