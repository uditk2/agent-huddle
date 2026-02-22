# Agent Huddle Context

Last updated: 2026-02-22 (UTC)

## Objective

Deliver hosted, low-friction cross-machine terminal pairing with:
- Google login on `agenthuddle.synergiqai.com`
- One-time shared code shown by the site after login
- Automatic connection through hosted signaling + TURN fallback

## Current State

- Cloudflare signaling worker supports:
  - `POST /api/auth/google`
  - `POST /api/auth/github`
  - `POST /api/pair-key/issue`
  - `POST /api/rendezvous`
  - `POST /api/turn/credentials`
  - `GET /login` browser helper page (Google sign-in -> one-time code)
- MCP runtime supports one-time pass keys and onboarding tools.
- Hosted pair CLI path is available:
  - `npm run pair -- --pass-key '<KEY>'` on both machines
- Hosted MCP path (preferred) is available:
  - MCP tool `pair_with_code` with `passKey='<KEY>'` on both machines
- TURN credentials from rendezvous are now injected into:
  - Machine A peer connection
  - Machine B local `/api/connect` answer path (per-connection ICE override)

## Installer/Bootstrap Behavior

- `install_codex.sh` / `install_claude_code.sh` run bootstrap unless skipped.
- Bootstrap script now supports:
  - `WEBRTC_MCP_AUTH_PROVIDER=google` (default, via `/login`)
  - `WEBRTC_MCP_AUTH_PROVIDER=github`
  - `WEBRTC_MCP_AUTH_PROVIDER=token`
- Runtime env written to `.webrtc-terminal.env` includes signaling URL/token and pair key.
- Auto role selection (`offerer`/`answerer`) is handled by `pair` command; user does not perform manual blob exchange.
- MCP now exposes `pair_with_code`, `pair_status`, and `pair_stop` so clients can execute pairing without user shell commands.

## Remaining Validation

- End-to-end hosted pair on two machines with real Google login token.
- Confirm TURN secrets are configured in Worker env and relay candidates appear when needed.
- Confirm DNS stability from all target machines for:
  - `agenthuddle.synergiqai.com`
  - `api.telegram.org` (for progress updates)

## Operational Notes

- `server_status` now reports `hostedSignaling` config presence.
- Onboarding/connect tool responses include hosted pair command hints when signaling token is configured.
- Use `WEBRTC_MCP_SKIP_BOOTSTRAP=1` to bypass bootstrap during install for non-interactive runs.
