# WebRTC Terminal MCP Server

MCP server that issues one-time pass keys and only accepts WebRTC terminal connections after pass key validation.

## What it does

- Runs as an MCP server over `stdio`.
- Exposes HTTP signaling endpoints for WebRTC connect flow.
- Issues one-time pass keys that expire in exactly 10 minutes.
- Rejects connection attempts without valid, unused, unexpired pass key.
- Starts an interactive terminal (`node-pty`) only after successful pass key connect.
- Keeps active sessions alive with `ping`/`pong` keepalive.

## Security notes

- This server gives **full terminal access** to whoever connects with a valid pass key.
- If the process runs as a user with `sudo` privileges, connected clients can run `sudo` (subject to system sudo policy/password).
- For unrestricted root-level access, run the server process as `root`.
- Set `WEBRTC_MCP_ADMIN_TOKEN` so pass key issuance is authenticated.

## Install

```bash
npm install
```

## Run

```bash
WEBRTC_MCP_ADMIN_TOKEN='change-this' npm start
```

HTTP UI and API will be available at `http://127.0.0.1:8787` by default.

## Environment variables

- `WEBRTC_MCP_HTTP_HOST` (default: `127.0.0.1`)
- `WEBRTC_MCP_HTTP_PORT` (default: `8787`)
- `WEBRTC_MCP_ADMIN_TOKEN` (default: empty; if set, required for issuing/revoking/listing via HTTP)
- `WEBRTC_MCP_SHELL` (default: `$SHELL` or `/bin/bash`)
- `WEBRTC_MCP_SHELL_ARGS` (default: `-li`)
- `WEBRTC_MCP_WORKDIR` (default: current working directory)
- `WEBRTC_MCP_ICE_SERVERS` (JSON array, default: Google STUN)

## HTTP endpoints

- `GET /health`
- `GET /api/config`
- `POST /api/passkeys/issue` (admin token if configured)
- `POST /api/connect`
- `GET /api/sessions` (admin)
- `GET /api/sessions/:sessionId` (admin)
- `POST /api/sessions/revoke` (admin)
- `GET /client.html` (minimal test client)

### Connect flow

1. Issue pass key (`/api/passkeys/issue` or MCP tool `issue_pass_key`).
2. Client creates WebRTC offer and gathers ICE.
3. Client submits `{ passKey, offerSdp }` to `/api/connect`.
4. Server validates key (single-use + 10-minute TTL), returns `answerSdp`.
5. Client applies answer, data channel opens, terminal starts.

## MCP tools

- `issue_pass_key`
- `list_sessions`
- `revoke_session`
- `server_status`

## Codex install

```bash
./scripts/install_codex.sh
```

This runs:

```bash
codex mcp add webrtc-terminal -- node /absolute/path/to/src/index.js
```

## Claude Code install

Use:

```bash
./scripts/install_claude_code.sh project
```

Scopes:

- `project` (default): available only in this repo
- `user`: available across all repos for this user
- `local`: current local workspace scope in Claude

Examples:

```bash
./scripts/install_claude_code.sh project
./scripts/install_claude_code.sh user
```

The installer now uses `claude mcp add` directly, so Claude registers the server in the selected scope.
If both `project` and `user` scopes exist with the same name, project scope takes precedence in this repo.

## Quick test

1. Start server: `WEBRTC_MCP_ADMIN_TOKEN='localtest' npm start`
2. Open `http://127.0.0.1:8787/client.html`
3. Issue key with admin token `localtest`
4. Connect using generated pass key
5. Run terminal commands through the client
