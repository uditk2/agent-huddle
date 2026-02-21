#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR_ARG="${1:-}"
PREPARE_SCRIPT="$REPO_DIR/scripts/prepare_runtime.sh"

if [[ ! -x "$PREPARE_SCRIPT" ]]; then
  echo "Error: missing executable prepare script: $PREPARE_SCRIPT"
  exit 1
fi

if [[ -n "$RUNTIME_DIR_ARG" ]]; then
  RUNTIME_DIR="$("$PREPARE_SCRIPT" "$RUNTIME_DIR_ARG")"
else
  RUNTIME_DIR="$("$PREPARE_SCRIPT")"
fi

LAUNCHER="$RUNTIME_DIR/scripts/run_mcp.sh"
if [[ ! -x "$LAUNCHER" ]]; then
  echo "Error: launcher not found in runtime dir: $LAUNCHER"
  exit 1
fi

codex mcp add webrtc-terminal -- "$LAUNCHER"

echo "Runtime dir: $RUNTIME_DIR"
echo "Codex MCP server installed: webrtc-terminal"
