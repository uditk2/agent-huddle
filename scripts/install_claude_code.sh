#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCOPE="${1:-user}"
RUNTIME_DIR_ARG="${2:-}"
SERVER_NAME="webrtc-terminal"
PREPARE_SCRIPT="$REPO_DIR/scripts/prepare_runtime.sh"

if ! command -v claude >/dev/null 2>&1; then
  echo "Error: 'claude' CLI is not installed or not in PATH."
  exit 1
fi

if [[ "$SCOPE" != "project" && "$SCOPE" != "user" && "$SCOPE" != "local" ]]; then
  echo "Usage: $0 [user|project|local] [runtime_dir]"
  exit 1
fi

if [[ ! -x "$PREPARE_SCRIPT" ]]; then
  echo "Error: missing executable prepare script: $PREPARE_SCRIPT"
  exit 1
fi

if [[ -n "$RUNTIME_DIR_ARG" ]]; then
  RUNTIME_DIR="$("$PREPARE_SCRIPT" "$RUNTIME_DIR_ARG")"
else
  RUNTIME_DIR="$("$PREPARE_SCRIPT")"
fi
SERVER_CMD="$RUNTIME_DIR/scripts/run_mcp.sh"

if [[ ! -x "$SERVER_CMD" ]]; then
  echo "Error: launcher not found in runtime dir: $SERVER_CMD"
  exit 1
fi

# Remove existing entry in the selected scope to keep install idempotent.
claude mcp remove "$SERVER_NAME" -s "$SCOPE" >/dev/null 2>&1 || true

claude mcp add -s "$SCOPE" "$SERVER_NAME" -- "$SERVER_CMD"

echo "Runtime dir: $RUNTIME_DIR"
echo "Claude Code MCP server installed:"
claude mcp get "$SERVER_NAME"

if [[ "$SCOPE" == "user" && -f "$REPO_DIR/.mcp.json" ]] && rg -q "\"$SERVER_NAME\"" "$REPO_DIR/.mcp.json"; then
  echo "Note: project scope also has '$SERVER_NAME'. User scope may be shadowed in this repo."
  echo "If needed, remove project scope with: claude mcp remove \"$SERVER_NAME\" -s project"
fi
