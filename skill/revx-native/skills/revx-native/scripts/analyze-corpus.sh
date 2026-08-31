#!/usr/bin/env bash
# analyze-corpus.sh — batch-analyze every .so in a directory.
#
# Usage: analyze-corpus.sh <dir-with-so> [workspace-dir]
#
# Prints one line per lib (name, seconds, functions, pseudocode) and a final
# summary line. Designed so an agent can eyeball failures without parsing
# raw JSON.

set -uo pipefail

DIR="${1:?usage: analyze-corpus.sh <dir-with-so> [ws-dir]}"
WS="${2:-.}"
TIMEOUT="${REVX_CORPUS_TIMEOUT:-120}"

find_revx() {
  if command -v revx >/dev/null 2>&1; then
    command -v revx
    return 0
  fi
  # repo checkout: scripts live at skill/revx-native/skills/<name>/scripts
  local root
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../.." && pwd)"
  if [[ -x "$root/target/release/revx" ]]; then
    echo "$root/target/release/revx"
    return 0
  fi
  return 1
}

REVX_BIN="${REVX_BIN:-$(find_revx)}"
[[ -n "$REVX_BIN" && -x "$REVX_BIN" ]] || { echo "revx not found; build it (cargo build --release -p revx) or set REVX_BIN" >&2; exit 1; }

mkdir -p "$WS"
cd "$WS" || exit 1
[[ -f project.toml ]] || "$REVX_BIN" init . >/dev/null 2>&1

# portable timeout: prefer GNU/BSD timeout, else run unbounded
run_timeout() {
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$secs" "$@"
  else
    "$@"
  fi
}

count=0; total_s=0; total_fn=0
for so in "$DIR"/*.so; do
  [[ -e "$so" ]] || continue
  count=$((count + 1))
  name=$(basename "$so")
  start=$(date +%s)
  # analyze prints multi-line pretty JSON; capture all of it for extraction
  out=$(run_timeout "$TIMEOUT" "$REVX_BIN" analyze "$so" --profile fast 2>/dev/null)
  rc=$?
  end=$(date +%s)
  dt=$((end - start))
  total_s=$((total_s + dt))
  if [[ $rc -ne 0 || -z "$out" ]]; then
    echo "FAIL  $name  ${dt}s (rc=$rc)"
    continue
  fi
  # pretty JSON: values are on their own line after the key
  fns=$(printf '%s' "$out" | sed -n 's/.*"function_count": \([0-9]*\).*/\1/p' | head -1)
  pseudo=$(printf '%s' "$out" | sed -n 's/.*"structured_pseudocode_count": \([0-9]*\).*/\1/p' | head -1)
  fns=${fns:-0}; pseudo=${pseudo:-0}
  total_fn=$((total_fn + fns))
  printf 'OK    %-40s %4ds  funcs=%-6s pseudo=%s\n' "$name" "$dt" "$fns" "$pseudo"
done

echo "== $count libs, ${total_s}s total, $total_fn functions =="
