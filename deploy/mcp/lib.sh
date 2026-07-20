#!/usr/bin/env bash
set -euo pipefail

revx_deploy_root() {
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "$here/../.." && pwd
}

revx_repo_root() {
  revx_deploy_root
}

revx_default_prefix() {
  echo "${REVX_PREFIX:-$HOME/.local}"
}

revx_default_workspace() {
  if [[ -n "${REVX_WORKSPACE:-}" ]]; then
    echo "$REVX_WORKSPACE"
    return
  fi
  if [[ -d "$PWD/.revx" ]]; then
    pwd
    return
  fi
  echo "$(revx_repo_root)"
}

revx_resolve_engine() {
  if [[ -n "${REVX_ENGINE:-}" && -x "${REVX_ENGINE}" ]]; then
    echo "$REVX_ENGINE"
    return
  fi
  local prefix bin repo
  prefix="$(revx_default_prefix)"
  bin="$prefix/bin/revx-engine"
  if [[ -x "$bin" ]]; then
    echo "$bin"
    return
  fi
  repo="$(revx_repo_root)"
  if [[ -x "$repo/target/release/revx-engine" ]]; then
    echo "$repo/target/release/revx-engine"
    return
  fi
  if [[ -x "$repo/target/debug/revx-engine" ]]; then
    echo "$repo/target/debug/revx-engine"
    return
  fi
  if command -v revx-engine >/dev/null 2>&1; then
    command -v revx-engine
    return
  fi
  return 1
}

revx_build_release() {
  local repo
  repo="$(revx_repo_root)"
  (cd "$repo" && cargo build -p revx -p revx-engine --release)
}
