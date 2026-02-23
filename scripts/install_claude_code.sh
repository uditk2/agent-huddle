#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCOPE="${1:-user}"
RUNTIME_DIR_ARG="${2:-}"
SERVER_NAME="webrtc-terminal"
PREPARE_SCRIPT="$REPO_DIR/scripts/prepare_runtime.sh"
BOOTSTRAP_SCRIPT="$REPO_DIR/scripts/bootstrap_hosted_signaling.sh"
ENABLE_BOOTSTRAP="${WEBRTC_MCP_ENABLE_BOOTSTRAP:-0}"
SKIP_BOOTSTRAP="${WEBRTC_MCP_SKIP_BOOTSTRAP:-${WEBRTC_MCP_SKIP_GITHUB_BOOTSTRAP:-0}}"

file_has_server_name() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    return 1
  fi
  if command -v rg >/dev/null 2>&1; then
    rg -q "\"$SERVER_NAME\"" "$file"
    return $?
  fi
  grep -q "\"$SERVER_NAME\"" "$file"
}

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

if [[ "$SKIP_BOOTSTRAP" == "1" ]]; then
  ENABLE_BOOTSTRAP="0"
fi

if [[ "$ENABLE_BOOTSTRAP" == "1" ]]; then
  if [[ ! -x "$BOOTSTRAP_SCRIPT" ]]; then
    echo "Error: missing executable bootstrap script: $BOOTSTRAP_SCRIPT"
    exit 1
  fi
  echo "Bootstrapping hosted signaling login + pair key..."
  "$BOOTSTRAP_SCRIPT" "$RUNTIME_DIR" "${WEBRTC_MCP_PAIR_KEY:-}"
else
  echo "Skipping hosted signaling bootstrap (default behavior)."
  echo "To enable during install, rerun with: WEBRTC_MCP_ENABLE_BOOTSTRAP=1 $0 $SCOPE ${RUNTIME_DIR_ARG:-}"
fi

# Remove existing entry in the selected scope to keep install idempotent.
claude mcp remove "$SERVER_NAME" -s "$SCOPE" >/dev/null 2>&1 || true

claude mcp add -s "$SCOPE" "$SERVER_NAME" -- "$SERVER_CMD"

echo "Runtime dir: $RUNTIME_DIR"
echo "Claude Code MCP server installed:"
claude mcp get "$SERVER_NAME"

if [[ "$SCOPE" == "user" ]] && file_has_server_name "$REPO_DIR/.mcp.json"; then
  echo "Note: project scope also has '$SERVER_NAME'. User scope may be shadowed in this repo."
  echo "If needed, remove project scope with: claude mcp remove \"$SERVER_NAME\" -s project"
fi
