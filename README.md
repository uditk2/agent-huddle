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

Notes:
- Install scripts set up isolated runtime and run `npm install` there.
- Use through Codex/Claude as MCP tools. `npm start` is optional for standalone local testing.

## Default Flow (Machine A / Machine B)

1. Pick roles:
- Machine A = offerer
- Machine B = answerer

2. On machine B, call MCP tool:
- `manual_connect_guide`

3. Run returned `machineAStep` on machine A. It prints one line:
- `OFFER_BLOB=...`

4. On machine B, call MCP tool:
- `answer_offer_blob` with `offerBlob` = full `OFFER_BLOB=...` line

5. Copy `answerBlobLine` from machine B back into machine A prompt:
- `ANSWER_BLOB=...`

6. Session connects and stays active with keepalive.

## A/B CLI Commands

Machine A:
```bash
npm run connect:a -- --pass-key '<PASSKEY>' --connect-url '<CONNECT_ENDPOINT>'
```

Machine B (fallback if not using MCP `answer_offer_blob`):
```bash
npm run connect:b -- --blob 'OFFER_BLOB=...'
```

## MCP Tools

- `manual_connect_guide`
- `answer_offer_blob`
- `get_latest_pass_key`
- `issue_pass_key`
- `list_sessions`
- `revoke_session`
- `server_status`
