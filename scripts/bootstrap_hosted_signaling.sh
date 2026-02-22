#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${1:-$REPO_DIR}"
PASSED_PAIR_KEY="${2:-}"
SIGNALING_BASE_URL="${WEBRTC_MCP_SIGNALING_BASE_URL:-https://agenthuddle.synergiqai.com}"
AUTH_PROVIDER="$(printf '%s' "${WEBRTC_MCP_AUTH_PROVIDER:-google}" | tr '[:upper:]' '[:lower:]')"
PRESET_SIGNALING_TOKEN="${WEBRTC_MCP_SIGNALING_TOKEN:-}"
ENV_FILE="$RUNTIME_DIR/.webrtc-terminal.env"

usage() {
  cat <<EOF
Usage: $0 [runtime_dir] [pair_key]

Authenticates against Agent Huddle signaling and writes runtime config to:
  $ENV_FILE

Auth providers (set WEBRTC_MCP_AUTH_PROVIDER):
  google (default)  - paste token from Agent Huddle Google login page
  github            - exchange local gh auth token for signaling JWT
  token             - use WEBRTC_MCP_SIGNALING_TOKEN directly
EOF
}

normalize_pass_key() {
  local raw="$1"
  local normalized
  normalized="$(printf '%s' "$raw" | tr '[:lower:]' '[:upper:]' | tr -cd 'A-Z0-9')"
  if [[ ${#normalized} -lt 6 ]]; then
    echo "Error: pass key must contain at least 6 alphanumeric characters." >&2
    return 1
  fi
  printf '%s' "$normalized" | sed -E 's/(.{4})/\1-/g; s/-$//'
}

generate_pass_key() {
  local raw
  raw="$(openssl rand -base64 18 | tr '[:lower:]' '[:upper:]' | tr -cd 'A-Z0-9' | head -c 12)"
  printf '%s-%s-%s\n' "${raw:0:4}" "${raw:4:4}" "${raw:8:4}"
}

upsert_env() {
  local key="$1"
  local value="$2"

  if [[ ! -f "$ENV_FILE" ]]; then
    touch "$ENV_FILE"
    chmod 600 "$ENV_FILE"
  fi

  if grep -q "^${key}=" "$ENV_FILE"; then
    local escaped
    escaped="$(printf '%s' "$value" | sed -e 's/[\\/&]/\\&/g')"
    if sed --version >/dev/null 2>&1; then
      sed -i "s|^${key}=.*|${key}=${escaped}|" "$ENV_FILE"
    else
      sed -i '' "s|^${key}=.*|${key}=${escaped}|" "$ENV_FILE"
    fi
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

extract_json_field() {
  local json_text="$1"
  local field="$2"
  python3 -c 'import json,sys
field=sys.argv[1]
raw=sys.argv[2]
try:
  payload=json.loads(raw)
except Exception:
  print("")
  raise SystemExit(0)
value=payload.get(field,"")
print("" if value is None else str(value))
' "$field" "$json_text"
}

validate_signaling_token() {
  local token="$1"
  local response
  response="$(curl -fsS -H "authorization: Bearer $token" "$SIGNALING_BASE_URL/api/auth/me" 2>/dev/null || true)"
  [[ -n "$response" ]]
}

request_signaling_token_google() {
  local login_url="$SIGNALING_BASE_URL/login?mode=token"
  local token="${PRESET_SIGNALING_TOKEN:-}"
  if [[ -n "$token" ]]; then
    printf '%s\n' "$token"
    return 0
  fi

  echo "Google login required on Agent Huddle."
  echo "1) Open: $login_url"
  echo "2) Sign in with Google and copy the generated access token."
  echo "3) Paste it below."
  read -r -p "Paste Agent Huddle access token: " token
  if [[ -z "$token" ]]; then
    echo "Error: empty token." >&2
    return 1
  fi

  if ! validate_signaling_token "$token"; then
    echo "Error: token validation failed via $SIGNALING_BASE_URL/api/auth/me" >&2
    return 1
  fi

  printf '%s\n' "$token"
}

request_signaling_token_github() {
  if ! command -v gh >/dev/null 2>&1; then
    echo "Error: GitHub CLI (gh) is required for WEBRTC_MCP_AUTH_PROVIDER=github." >&2
    return 1
  fi

  if ! gh auth status >/dev/null 2>&1; then
    echo "GitHub login required. Starting 'gh auth login -w'..."
    gh auth login -w
  fi

  local gh_token
  gh_token="$(gh auth token)"
  if [[ -z "$gh_token" ]]; then
    echo "Error: failed to read GitHub token from gh auth." >&2
    return 1
  fi

  local auth_json
  auth_json="$(curl -fsS -X POST "$SIGNALING_BASE_URL/api/auth/github" \
    -H 'content-type: application/json' \
    -d "{\"githubAccessToken\":\"$gh_token\"}")"

  local signaling_token
  signaling_token="$(extract_json_field "$auth_json" accessToken)"
  if [[ -z "$signaling_token" ]]; then
    echo "Error: signaling auth failed. Response:" >&2
    printf '%s\n' "$auth_json" >&2
    return 1
  fi
  printf '%s\n' "$signaling_token"
}

request_signaling_token_direct() {
  local token="${PRESET_SIGNALING_TOKEN:-}"
  if [[ -z "$token" ]]; then
    echo "Error: WEBRTC_MCP_SIGNALING_TOKEN is required for WEBRTC_MCP_AUTH_PROVIDER=token." >&2
    return 1
  fi
  printf '%s\n' "$token"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "Error: curl is required." >&2
  exit 1
fi

SIGNALING_TOKEN=""
case "$AUTH_PROVIDER" in
  google)
    SIGNALING_TOKEN="$(request_signaling_token_google)"
    ;;
  github)
    SIGNALING_TOKEN="$(request_signaling_token_github)"
    ;;
  token)
    SIGNALING_TOKEN="$(request_signaling_token_direct)"
    ;;
  *)
    echo "Error: unsupported WEBRTC_MCP_AUTH_PROVIDER='$AUTH_PROVIDER' (expected google|github|token)." >&2
    exit 1
    ;;
esac

if [[ -z "$SIGNALING_TOKEN" ]]; then
  echo "Error: empty signaling token after auth flow." >&2
  exit 1
fi

PAIR_KEY=""
if [[ -n "$PASSED_PAIR_KEY" ]]; then
  PAIR_KEY="$(normalize_pass_key "$PASSED_PAIR_KEY")"
else
  PAIR_KEY="$(generate_pass_key)"
fi

upsert_env WEBRTC_MCP_SIGNALING_BASE_URL "$SIGNALING_BASE_URL"
upsert_env WEBRTC_MCP_AUTH_PROVIDER "$AUTH_PROVIDER"
upsert_env WEBRTC_MCP_SIGNALING_TOKEN "$SIGNALING_TOKEN"
upsert_env WEBRTC_MCP_PAIR_KEY "$PAIR_KEY"

echo "Hosted signaling bootstrap complete."
echo "Runtime env file: $ENV_FILE"
echo "Pair key: $PAIR_KEY"
echo "Auth provider: $AUTH_PROVIDER"
echo ""
echo "Next steps on this machine:"
echo "  npm run pair -- --pass-key '$PAIR_KEY'"
echo ""
echo "On remote machine, use the same pair key:"
echo "  ./scripts/bootstrap_hosted_signaling.sh <runtime_dir> '$PAIR_KEY'"
echo "  npm run pair -- --pass-key '$PAIR_KEY'"
