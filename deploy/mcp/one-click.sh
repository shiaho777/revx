#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

PREFIX="$(revx_default_prefix)"
WORKSPACE="$(revx_default_workspace)"
INIT_WS="${REVX_INIT_WORKSPACE:-1}"

echo "[revx-mcp] repo=$(revx_repo_root)"
echo "[revx-mcp] prefix=$PREFIX"
echo "[revx-mcp] workspace=$WORKSPACE"

revx_build_release
ENGINE="$(revx_repo_root)/target/release/revx-engine"
if [[ ! -x "$ENGINE" ]]; then
  echo "error: missing $ENGINE" >&2
  exit 1
fi

INSTALL_ARGS=(mcp install --prefix "$PREFIX" --workspace "$WORKSPACE" --write-config)
if [[ "$INIT_WS" == "1" ]]; then
  INSTALL_ARGS+=(--init-workspace)
fi

"$ENGINE" "${INSTALL_ARGS[@]}"
INSTALLED="$PREFIX/bin/revx-engine"
"$INSTALLED" mcp doctor --workspace "$WORKSPACE"

echo
echo "[revx-mcp] ready"
echo "[revx-mcp] host config samples under: $PREFIX/share/revx/mcp/"
echo "[revx-mcp] point MCP Host command to:"
echo "  $INSTALLED mcp serve --workspace $WORKSPACE"
echo
echo "[revx-mcp] generic config:"
"$INSTALLED" mcp config --host generic --workspace "$WORKSPACE" --bin "$INSTALLED"
