#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_SCRIPT="$ROOT_DIR/ops/run_issue_watcher.sh"
CRON_LOG="$ROOT_DIR/ops/logs/cron.log"
CRON_ENTRY="*/5 * * * * /usr/bin/env bash -lc '$RUN_SCRIPT >> $CRON_LOG 2>&1'"

current_cron=""
if crontab -l >/dev/null 2>&1; then
  current_cron="$(crontab -l)"
fi

if printf '%s\n' "$current_cron" | grep -F "$RUN_SCRIPT" >/dev/null 2>&1; then
  echo "Cron entry already exists for issue watcher."
  exit 0
fi

{
  printf '%s\n' "$current_cron"
  printf '%s\n' "$CRON_ENTRY"
} | awk 'NF || !seen_blank++' | crontab -

echo "Installed issue watcher cron (every 5 minutes)."
echo "Entry: $CRON_ENTRY"
