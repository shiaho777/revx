#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BIND="${REVX_MCP_BIND:-127.0.0.1:9310}"
URL="http://${BIND}/mcp"
WORKSPACE="${REVX_WORKSPACE:-$HOME/.local/share/revx/workspace}"
ENGINE="${REVX_ENGINE:-}"

find_engine() {
  if [[ -n "$ENGINE" && -x "$ENGINE" ]]; then echo "$ENGINE"; return; fi
  if [[ -x "$ROOT/revx-engine" ]]; then echo "$ROOT/revx-engine"; return; fi
  if [[ -x "$ROOT/../revx-engine" ]]; then echo "$ROOT/../revx-engine"; return; fi
  if [[ -x "$HOME/.local/bin/revx-engine" ]]; then echo "$HOME/.local/bin/revx-engine"; return; fi
  if command -v revx-engine >/dev/null 2>&1; then command -v revx-engine; return; fi
  local repo
  repo="$(cd "$ROOT/../.." 2>/dev/null && pwd || true)"
  if [[ -n "$repo" && -f "$repo/Cargo.toml" ]]; then
    echo "[revx] building revx-engine (release)..." >&2
    (cd "$repo" && cargo build -p revx-engine --release) >&2
    if [[ -x "$repo/target/release/revx-engine" ]]; then
      echo "$repo/target/release/revx-engine"
      return
    fi
  fi
  return 1
}

if ! ENGINE_BIN="$(find_engine)"; then
  echo "[revx] revx-engine not found. Put it next to this script or set REVX_ENGINE." >&2
  exit 1
fi

mkdir -p "$WORKSPACE"
if [[ ! -d "$WORKSPACE/.revx" ]]; then
  "$ENGINE_BIN" init "$WORKSPACE" >/dev/null
fi

TOKEN_FILE="$WORKSPACE/.revx/mcp-token"
TOKEN="${REVX_MCP_TOKEN:-}"
if [[ -z "$TOKEN" && -f "$TOKEN_FILE" ]]; then
  TOKEN="$(tr -d '[:space:]' <"$TOKEN_FILE")"
fi
AUTH_ARGS=()
if [[ -n "$TOKEN" ]]; then
  AUTH_ARGS=(-H "Authorization: Bearer $TOKEN")
fi

health_ok() {
  curl -fsS --max-time 1 "${AUTH_ARGS[@]}" "http://${BIND}/mcp/health" >/dev/null 2>&1
}

print_client_config() {
  echo "[revx] codex config:"
  cat <<CFG
[mcp_servers.revx]
url = "$URL"
bearer_token_env_var = "REVX_MCP_TOKEN"
CFG
  if [[ -n "$TOKEN" ]]; then
    echo "[revx] token: $TOKEN"
    echo "[revx] token file: $TOKEN_FILE"
    echo "[revx] export REVX_MCP_TOKEN=\"$TOKEN\""
  else
    echo "[revx] token will be generated at $TOKEN_FILE on first start"
  fi
}

if health_ok; then
  echo "[revx] already running: $URL"
  echo "[revx] engine: $ENGINE_BIN"
  echo "[revx] workspace: $WORKSPACE"
  print_client_config
  exit 0
fi

echo "[revx] starting MCP HTTP"
echo "[revx] engine: $ENGINE_BIN"
echo "[revx] workspace: $WORKSPACE"
echo "[revx] url: $URL"

if [[ "${REVX_MCP_FOREGROUND:-0}" == "1" ]]; then
  exec "$ENGINE_BIN" mcp http --bind "$BIND" --workspace "$WORKSPACE"
fi

nohup "$ENGINE_BIN" mcp http --bind "$BIND" --workspace "$WORKSPACE" \
  >"$WORKSPACE/../mcp-http.log" 2>"$WORKSPACE/../mcp-http.err.log" &
echo $! >"$WORKSPACE/../mcp-http.pid"

for _ in 1 2 3 4 5 6 7 8 9 10; do
  if [[ -z "$TOKEN" && -f "$TOKEN_FILE" ]]; then
    TOKEN="$(tr -d '[:space:]' <"$TOKEN_FILE")"
    AUTH_ARGS=(-H "Authorization: Bearer $TOKEN")
  fi
  if health_ok; then
    echo "[revx] ready: $URL"
    print_client_config
    exit 0
  fi
  sleep 0.3
done

echo "[revx] started but health check failed; see $WORKSPACE/../mcp-http.err.log" >&2
exit 1
