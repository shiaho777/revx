#!/usr/bin/env bash
# check-deps.sh — verify revx CLI availability and workspace state.
#
# Machine-readable output (one per line):
#   REVX_OK:<path>            revx binary found
#   REVX_MISSING              revx binary not found / not built
#   WORKSPACE_OK:<path>       a revx workspace exists at or above cwd
#   WORKSPACE_MISSING         no workspace found (run `revx init`)
#   CORPUS_HINT:<dir>         sibling arm64-v8a/ directory with .so files

set -uo pipefail

fail() { echo "$1"; exit "${2:-1}"; }

find_revx() {
  if command -v revx >/dev/null 2>&1; then
    command -v revx
    return 0
  fi
  for candidate in \
    "$(pwd)/target/release/revx" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../.." 2>/dev/null && pwd)/target/release/revx"; do
    if [[ -x "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

REVX_BIN="$(find_revx)"
if [[ -n "$REVX_BIN" ]]; then
  echo "REVX_OK:$REVX_BIN"
else
  echo "REVX_MISSING"
  echo "hint: cargo build --release -p revx   (Rust workspace at the repo root)"
  exit 1
fi

# workspace discovery: cwd or any parent containing project.toml / state.sqlite
dir="$(pwd)"
while true; do
  if [[ -f "$dir/project.toml" || -f "$dir/.revx/state.sqlite" || -f "$dir/state.sqlite" ]]; then
    echo "WORKSPACE_OK:$dir"
    break
  fi
  [[ "$dir" == "/" ]] && { echo "WORKSPACE_MISSING"; break; }
  dir="$(dirname "$dir")"
done

exit 0
