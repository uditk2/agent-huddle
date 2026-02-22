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
- VS Code generator writes/updates `.vscode/mcp.json` with `servers.webrtc-terminal`.
- Use through Codex/Claude as MCP tools. `npm start` is optional for standalone local testing.

## Default Flow (Machine A / Machine B)

1. Pick roles:
- Machine A = offerer
- Machine B = answerer

2. On either machine, call MCP tool:
- `connect`
- It shows two choices: `machine_a` or `machine_b`.

3. On machine B, call:
- `connect` with `role=machine_b`
- Copy returned `machineAStep` and run it on machine A.

4. Machine A prints one line:
- `OFFER_BLOB=...`

5. On machine B, call:
- `connect` with `role=machine_b` and `offerBlob='OFFER_BLOB=...'`

6. Copy `answerBlobLine` from machine B back into machine A prompt:
- `ANSWER_BLOB=...`

7. Session connects and stays active with keepalive.

## A/B CLI Commands

Machine A:
```bash
npm run connect:a -- --pass-key '<PASSKEY>'
```

Machine B (fallback if not using MCP `connect`):
```bash
npm run connect:b -- --blob 'OFFER_BLOB=...'
```

## MCP Tools (Default)

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

## Local Service Watcher Agent

For machine-local service monitoring that auto-opens deduped GitHub issues every 5 minutes:

- Docs: `ops/README_issue_watcher.md`
- Install cron watcher: `ops/install_issue_watcher_cron.sh`
