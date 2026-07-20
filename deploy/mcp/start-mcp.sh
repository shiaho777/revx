#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

WORKSPACE="$(revx_default_workspace)"
INIT_WS="${REVX_INIT_WORKSPACE:-0}"

if ! ENGINE="$(revx_resolve_engine)"; then
  echo "[revx-mcp] engine not found; building release..." >&2
  revx_build_release
  ENGINE="$(revx_repo_root)/target/release/revx-engine"
fi

ARGS=(mcp serve --workspace "$WORKSPACE")
if [[ "$INIT_WS" == "1" ]]; then
  ARGS+=(--init)
fi

exec "$ENGINE" "${ARGS[@]}"
