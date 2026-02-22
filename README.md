# Agent Huddle (WebRTC Terminal MCP)

Default setup and usage.
For advanced details, see `DETAILREADME.md`.

## Install

Codex:
```bash
./scripts/install_codex.sh
```

Claude Code:
```bash
./scripts/install_claude_code.sh user
```

VS Code (workspace MCP config):
```bash
./scripts/generate_vscode_mcp.sh
```

Notes:
- Install scripts set up isolated runtime and run `npm install` there.
- Install scripts run hosted-signaling bootstrap by default.
- VS Code generator writes/updates `.vscode/mcp.json` with `servers.webrtc-terminal`.
- Use through Codex/Claude as MCP tools. `npm start` is optional for standalone local testing.

## User Steps (Hosted Pair)

1. Install MCP server on both machines (`install_codex.sh` or `install_claude_code.sh user`).
2. Login at `https://agenthuddle.synergiqai.com/login`.
3. Copy the one-time code shown on the site.
4. In Codex/Claude on machine 1, call MCP tool `pair_with_code` with `passKey='<CODE>'`.
5. In Codex/Claude on machine 2, call MCP tool `pair_with_code` with the same `passKey`.
6. Verify with MCP tool `pair_status` on either machine.

CLI fallback:
```bash
npm run pair -- --pass-key '<CODE>'
```

## Default MCP Tool Flow (Fallback)

Use tool `onboarding` first, then `connect`.
This is copy/paste offer/answer flow and does not require hosted signaling.

## MCP Tools (Default)

- `pair_with_code` (recommended hosted flow)
- `pair_status`
- `pair_stop`
- `onboarding` (recommended first call)
- `connect`
- `server_status`

For full/advanced tool list, see `DETAILREADME.md`.

## Cloudflare Signaling Service

For signed-user signaling + TURN credential issuance via Cloudflare Worker:

```bash
cd workers/signaling-service
```

See `workers/signaling-service/README.md` for deploy and API usage.

## Environment Overrides

- `WEBRTC_MCP_AUTH_PROVIDER=google|github|token`
- `WEBRTC_MCP_SIGNALING_BASE_URL=https://agenthuddle.synergiqai.com`
- `WEBRTC_MCP_SIGNALING_TOKEN=<token>` (required for `token` provider)
- `WEBRTC_MCP_PAIR_KEY=<optional-fixed-passkey>`
- `WEBRTC_MCP_SKIP_BOOTSTRAP=1` (skip bootstrap in install scripts)

## Local Service Watcher Agent

For machine-local service monitoring that auto-opens deduped GitHub issues every 5 minutes:

- Docs: `ops/README_issue_watcher.md`
- Install cron watcher: `ops/install_issue_watcher_cron.sh`
