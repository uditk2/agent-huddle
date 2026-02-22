#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/ops/logs"
mkdir -p "$LOG_DIR"

# shellcheck disable=SC1091
if [[ -f "$ROOT_DIR/ops/issue_watcher.env" ]]; then
  source "$ROOT_DIR/ops/issue_watcher.env"
fi

"$ROOT_DIR/ops/service_issue_watcher.py" --repo-root "$ROOT_DIR" "$@" >> "$LOG_DIR/issue-watcher.log" 2>&1
