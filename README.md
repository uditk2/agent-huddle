# WebRTC Terminal MCP Server

MCP server that issues one-time pass keys and only accepts WebRTC terminal connections after pass key validation.

## What it does

- Runs as an MCP server over `stdio`.
- Exposes HTTP signaling endpoints for WebRTC connect flow.
- Auto-generates an active one-time pass key on startup.
- Issues one-time pass keys that expire in exactly 10 minutes.
- Keeps one active pass key available and rotates it after use/expiry.
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

HTTP UI and API bind to `127.0.0.1:8787` by default. If that port is unavailable, the server falls back to a random free local port.

## Environment variables

- `WEBRTC_MCP_HTTP_HOST` (default: `127.0.0.1`)
- `WEBRTC_MCP_HTTP_PORT` (default: `8787`)
- `WEBRTC_MCP_PUBLIC_BASE_URL` (default: empty; when set, pass-key responses advertise `<public-base>/api/connect`)
- `WEBRTC_MCP_ADMIN_TOKEN` (default: empty; if set, required for issuing/revoking/listing via HTTP)
- `WEBRTC_MCP_SHELL` (default: `$SHELL` or `/bin/bash`)
- `WEBRTC_MCP_SHELL_ARGS` (default: `-li`)
- `WEBRTC_MCP_WORKDIR` (default: current working directory)
- `WEBRTC_MCP_ICE_SERVERS` (JSON array, default: Google STUN)

## HTTP endpoints

- `GET /health`
- `GET /api/config`
- `POST /api/passkeys/issue` (admin token if configured)
- `GET /api/passkeys/latest` (admin)
- `POST /api/passkeys/rotate` (admin)
- `POST /api/connect`
- `GET /api/sessions` (admin)
- `GET /api/sessions/:sessionId` (admin)
- `POST /api/sessions/revoke` (admin)
- `GET /client.html` (minimal test client)

### Connect flow

1. Get pass key (`/api/passkeys/latest` or MCP tool `get_latest_pass_key`).
2. Client creates WebRTC offer and gathers ICE.
3. Client submits `{ passKey, offerSdp }` to `/api/connect`.
4. Server validates key (single-use + 10-minute TTL), returns `answerSdp`.
5. Client applies answer, data channel opens, terminal starts.

## Manual copy/paste cross-machine flow (recommended minimal path)

This is the default low-friction path when you have shell access to both machines and do not want to host signaling publicly.

1. Start server on machine B:
```bash
npm start
```
2. Get a one-time pass key on machine B:
- MCP tool: `get_latest_pass_key`
- Or HTTP: `GET http://127.0.0.1:8787/api/passkeys/latest`
3. On machine A, generate offer and wait for answer:
```bash
npm run manual:offer -- --pass-key 'PASTE-PASSKEY-HERE'
```
4. Copy printed `OFFER_BLOB` from machine A.
5. On machine B, turn offer into answer:
```bash
npm run manual:answer -- --blob 'PASTE_OFFER_BLOB_HERE'
```
6. Copy printed `ANSWER_BLOB` from machine B back into machine A prompt.
7. Session opens on machine A; run commands interactively.

Notes:
- This path uses no middle data broker.
- The helper client keeps the channel alive with ping/pong and periodic keepalive pings.
- WebRTC data channels are encrypted in transit by DTLS.
- If B is not on `127.0.0.1:8787`, set `WEBRTC_MCP_CONNECT_URL` or pass `--connect-url` on machine B.

Optional: if you later expose signaling on a public URL, set `WEBRTC_MCP_PUBLIC_BASE_URL` so pass-key payloads advertise a remote `connectEndpoint`.

## ICE examples

Google STUN only (minimal test):

```bash
WEBRTC_MCP_ICE_SERVERS='[{"urls":["stun:stun.l.google.com:19302","stun:stun1.l.google.com:19302","stun:stun2.l.google.com:19302"]}]'
```

Add public TURN fallback for quick testing (shared/public, not for production secrets):

```bash
WEBRTC_MCP_ICE_SERVERS='[
  {"urls":["stun:stun.l.google.com:19302","stun:stun1.l.google.com:19302"]},
  {"urls":["turn:openrelay.metered.ca:80"],"username":"openrelayproject","credential":"openrelayproject"},
  {"urls":["turn:openrelay.metered.ca:443"],"username":"openrelayproject","credential":"openrelayproject"},
  {"urls":["turn:openrelay.metered.ca:443?transport=tcp"],"username":"openrelayproject","credential":"openrelayproject"}
]'
```

## MCP tools

- `issue_pass_key`
- `get_latest_pass_key`
- `list_sessions`
- `revoke_session`
- `server_status`

Typical usage from Claude/Codex:

- Ask: `Call webrtc-terminal MCP tool get_latest_pass_key`
- Optional rotate: `Call webrtc-terminal MCP tool get_latest_pass_key with rotate=true`

## Codex install

```bash
./scripts/install_codex.sh
```

This runs:

```bash
codex mcp add webrtc-terminal -- ~/.local/share/agent-huddle/webrtc-terminal-mcp/scripts/run_mcp.sh
```

Optional custom runtime dir:

```bash
./scripts/install_codex.sh /custom/runtime/dir
```

## Claude Code install

Use:

```bash
./scripts/install_claude_code.sh
```

Scopes:

- `user` (default): available across all repos for this user
- `project`: available only in this repo
- `local`: current local workspace scope in Claude

Examples:

```bash
./scripts/install_claude_code.sh user
./scripts/install_claude_code.sh project
```

The installer now uses `claude mcp add` directly, so Claude registers the server in the selected scope.
If both `project` and `user` scopes exist with the same name, project scope takes precedence in this repo.

Optional custom runtime dir:

```bash
./scripts/install_claude_code.sh user /custom/runtime/dir
```

## Dependency Isolation

Installers copy this repo into an isolated runtime directory and install npm dependencies there:

- default runtime dir: `~/.local/share/agent-huddle/webrtc-terminal-mcp`
- source repo stays clean (no `node_modules` required after install)
- both Claude and Codex can point to the same isolated runtime

## If Claude shows `Failed to connect`

1. Reinstall to refresh isolated runtime:
```bash
./scripts/install_claude_code.sh user
```
2. Run launcher directly once:
```bash
~/.local/share/agent-huddle/webrtc-terminal-mcp/scripts/run_mcp.sh
```
3. Check error log:
```bash
tail -n 120 ~/.local/share/agent-huddle/webrtc-terminal-mcp/.webrtc-terminal-mcp.log
```
4. Recheck MCP entry:
```bash
claude mcp get webrtc-terminal
```

## Quick test

1. Start server: `WEBRTC_MCP_ADMIN_TOKEN='localtest' npm start`
2. Call MCP tool `server_status` to read the active `httpPort` (it may differ from `8787` if fallback occurred)
3. Open `http://127.0.0.1:<httpPort>/client.html`
4. Issue key with admin token `localtest`
5. Connect using generated pass key
6. Run terminal commands through the client
