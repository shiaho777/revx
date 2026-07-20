#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

WORKSPACE="$(revx_default_workspace)"
if ! ENGINE="$(revx_resolve_engine)"; then
  echo "error: revx-engine not found. Run deploy/mcp/one-click.sh first." >&2
  exit 1
fi

"$ENGINE" mcp doctor --workspace "$WORKSPACE"
echo
echo "config (generic):"
"$ENGINE" mcp config --host generic --workspace "$WORKSPACE" --bin "$ENGINE"
