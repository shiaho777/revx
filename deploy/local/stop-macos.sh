#!/usr/bin/env bash
set -euo pipefail
BIND="${REVX_MCP_BIND:-127.0.0.1:9310}"
PID_FILE="${REVX_WORKSPACE:-$HOME/.local/share/revx/workspace}/../mcp-http.pid"
if [[ -f "$PID_FILE" ]]; then
  kill "$(cat "$PID_FILE")" 2>/dev/null || true
  rm -f "$PID_FILE"
fi
if command -v lsof >/dev/null 2>&1; then
  PIDS="$(lsof -tiTCP:${BIND##*:} -sTCP:LISTEN 2>/dev/null || true)"
  if [[ -n "${PIDS:-}" ]]; then kill $PIDS 2>/dev/null || true; fi
fi
echo "[revx] stopped ${BIND}"
