# Signaling Service (Cloudflare Worker + Durable Object)

This service provides:
- User sign-in (`/api/auth/login`)
- WebRTC signaling rooms over WebSocket (Durable Object)
- Cloudflare TURN credential minting (`/api/turn/credentials`)

It is designed so only this backend holds Cloudflare API secrets. Clients receive short-lived TURN credentials.

## Deploy

1. Install dependencies:

```bash
cd workers/signaling-service
npm install
```

2. Set required secrets:

```bash
npx wrangler secret put SIGNALING_JWT_SECRET
npx wrangler secret put SIGNALING_USERS_JSON
npx wrangler secret put CLOUDFLARE_TURN_API_TOKEN
npx wrangler secret put CLOUDFLARE_TURN_KEY_ID
```

- `SIGNALING_JWT_SECRET`: random long string used to sign JWTs.
- `SIGNALING_USERS_JSON`: JSON user map, e.g. `{"alice":"strong-password","bob":"another"}`.
- `CLOUDFLARE_TURN_API_TOKEN`: Cloudflare API token with TURN credentials generation permission.
- `CLOUDFLARE_TURN_KEY_ID`: TURN key ID from Cloudflare Realtime TURN settings.

3. Deploy:

```bash
npm run deploy
```

## Local dev

```bash
npm run dev
```

## API

### Health

```http
GET /health
```

### Login

```http
POST /api/auth/login
Content-Type: application/json

{ "username": "alice", "password": "strong-password" }
```

Returns bearer token.

### Current user

```http
GET /api/auth/me
Authorization: Bearer <token>
```

### Mint TURN credentials

```http
POST /api/turn/credentials
Authorization: Bearer <token>
Content-Type: application/json

{ "ttlSec": 600, "customIdentifier": "alice-session" }
```

### Create signaling session

```http
POST /api/sessions
Authorization: Bearer <token>
Content-Type: application/json

{ "peerId": "alice-host", "joinTtlSec": 3600, "turnTtlSec": 600 }
```

Returns:
- `sessionId`
- `joinToken`
- `wsUrl` (already contains `token` + `peerId` query params)
- `turn` (short-lived `iceServers`, if configured)

### Join existing signaling session

```http
POST /api/sessions/:sessionId/join
Authorization: Bearer <token>
Content-Type: application/json

{ "peerId": "bob-client", "joinTtlSec": 3600 }
```

Returns `joinToken` and `wsUrl`.

### WebSocket signaling endpoint

```http
GET /api/sessions/:sessionId/ws?token=<joinToken>&peerId=<peerId>
Upgrade: websocket
```

Messages supported (`JSON`):
- `{ "type": "offer", "target": "peer-id", "payload": <sdp-or-object> }`
- `{ "type": "answer", "target": "peer-id", "payload": <sdp-or-object> }`
- `{ "type": "ice", "target": "peer-id", "payload": <candidate-or-object> }`
- `{ "type": "list" }`
- `{ "type": "ping" }`

Server events:
- `welcome`
- `peer-joined`
- `peer-left`
- forwarded `offer`/`answer`/`ice`
- `error`

## Notes

- Keep WebRTC `iceTransportPolicy` as `all` so direct P2P is preferred; TURN is used only when needed.
- `TURN_AUTO_ON_SESSION=true` returns TURN credentials in session creation response by default.
- Restrict `ALLOWED_ORIGINS` in `wrangler.jsonc` for production.
