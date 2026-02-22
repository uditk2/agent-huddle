# Signaling Service (Cloudflare Worker + Durable Object)

This service provides:
- User sign-in (`/api/auth/login`)
- Google sign-in (`/api/auth/google`)
- GitHub token sign-in (`/api/auth/github`)
- WebRTC signaling rooms over WebSocket (Durable Object)
- Cloudflare TURN credential minting (`/api/turn/credentials`)
- Passkey-based rendezvous session creation (`/api/rendezvous`)

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
npx wrangler secret put GOOGLE_OAUTH_CLIENT_ID
npx wrangler secret put GOOGLE_OAUTH_CLIENT_SECRET
```

- `SIGNALING_JWT_SECRET`: random long string used to sign JWTs.
- `SIGNALING_USERS_JSON`: JSON user map, e.g. `{"alice":"strong-password","bob":"another"}`.
- `CLOUDFLARE_TURN_API_TOKEN`: Cloudflare API token with TURN credentials generation permission.
- `CLOUDFLARE_TURN_KEY_ID`: TURN key ID from Cloudflare Realtime TURN settings.
- `GOOGLE_OAUTH_CLIENT_ID`: Google OAuth web client id.
- `GOOGLE_OAUTH_CLIENT_SECRET`: Google OAuth web client secret (used when exchanging auth code).

Optional:
- `GOOGLE_OAUTH_REDIRECT_URI`: default redirect URI used by auth-code exchange when `redirectUri` not sent in request.
- `GOOGLE_OAUTH_ALLOWED_DOMAINS`: comma-separated hosted domains (`hd`) allowed for Google sign-ins.

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

### Browser login helper

```http
GET /login
```

This page performs Google sign-in and displays a one-time pairing code for two-machine setup.

### Login

```http
POST /api/auth/login
Content-Type: application/json

{ "username": "alice", "password": "strong-password" }
```

Returns bearer token.

### Google login (ID token)

```http
POST /api/auth/google
Content-Type: application/json

{ "idToken": "<google-id-token>" }
```

### Google login (Auth code exchange)

```http
POST /api/auth/google
Content-Type: application/json

{
  "code": "<google-auth-code>",
  "redirectUri": "https://your-app.example.com/auth/google/callback"
}
```

Notes:
- If `idToken` is provided, `code` is not required.
- If using `code`, backend exchanges it with Google and validates returned ID token.

### Current user

```http
GET /api/auth/me
Authorization: Bearer <token>
```

### Issue one-time pairing code

```http
POST /api/pair-key/issue
Authorization: Bearer <token>
Content-Type: application/json

{ "ttlSec": 600 }
```

### GitHub login (access token exchange)

```http
POST /api/auth/github
Content-Type: application/json

{ "githubAccessToken": "<gh-oauth-token>" }
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

### Rendezvous by pass key (deterministic session id)

```http
POST /api/rendezvous
Authorization: Bearer <token>
Content-Type: application/json

{ "passKey": "ABCD-EFGH-IJKL", "peerId": "machine-a" }
```

Returns:
- `sessionId` (derived from pass key hash)
- `peerId`
- `joinToken`
- `wsUrl`
- `turn` (if configured)

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
