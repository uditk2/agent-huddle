#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR_ARG="${1:-}"
PREPARE_SCRIPT="$REPO_DIR/scripts/prepare_runtime.sh"
BOOTSTRAP_SCRIPT="$REPO_DIR/scripts/bootstrap_hosted_signaling.sh"
SKIP_BOOTSTRAP="${WEBRTC_MCP_SKIP_BOOTSTRAP:-${WEBRTC_MCP_SKIP_GITHUB_BOOTSTRAP:-0}}"

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

if [[ "$SKIP_BOOTSTRAP" != "1" ]]; then
  if [[ ! -x "$BOOTSTRAP_SCRIPT" ]]; then
    echo "Error: missing executable bootstrap script: $BOOTSTRAP_SCRIPT"
    exit 1
  fi
  echo "Bootstrapping hosted signaling login + pair key..."
  "$BOOTSTRAP_SCRIPT" "$RUNTIME_DIR" "${WEBRTC_MCP_PAIR_KEY:-}"
fi

codex mcp add webrtc-terminal -- "$LAUNCHER"

echo "Runtime dir: $RUNTIME_DIR"
echo "Codex MCP server installed: webrtc-terminal"
