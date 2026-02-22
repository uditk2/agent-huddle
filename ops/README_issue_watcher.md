# Service Issue Watcher Agent

This local watcher runs every 5 minutes, scans recent service logs for regex-matched failures, dedupes against existing GitHub issues, and creates a new issue only for new incidents.

## Files

- `ops/service_issue_watcher.py`: single-cycle watcher.
- `ops/run_issue_watcher.sh`: wrapper used by cron.
- `ops/install_issue_watcher_cron.sh`: installs 5-minute cron entry.
- `ops/issue_watcher.env.example`: runtime config template.

## Setup

1. Authenticate GitHub CLI on this machine:

```bash
gh auth login
```

2. Configure env:

```bash
cp ops/issue_watcher.env.example ops/issue_watcher.env
# edit ops/issue_watcher.env
```

3. Test a dry run:

```bash
ops/run_issue_watcher.sh --dry-run
```

4. Install recurring run:

```bash
ops/install_issue_watcher_cron.sh
```

## Dedupe behavior

1. Exact dedupe via `Fingerprint: <hash>` in existing issue bodies.
2. Heuristic title similarity dedupe.
3. Optional LLM semantic dedupe when `DEDUPE_API_URL` + `DEDUPE_API_KEY` are configured (defaults model name to `sqen`).

## Notes

- If no LLM config is provided, watcher still works using deterministic dedupe.
- Run logs are written to `ops/logs/issue-watcher.log` and `ops/logs/cron.log`.
- State is persisted in `ops/.issue_watcher_state.json`.
