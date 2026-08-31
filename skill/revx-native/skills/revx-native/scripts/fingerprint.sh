#!/usr/bin/env bash
# fingerprint.sh — Phase 0 triage for a directory of native libs (or one .so).
#
# Answers, in one screen: is this corpus il2cpp-driven, how big, which libs
# matter, is there a global-metadata.dat, and what should you run next.
# This is the native-side analogue of an APK fingerprint: it exists so you
# don't burn hours on the wrong tool for the job.

set -uo pipefail

usage() {
  cat <<EOF
Usage: fingerprint.sh <dir-with-so | file.so>

Prints a one-screen summary:
  * corpus size + lib count, top binaries by size
  * il2cpp markers (il2cpp_* exports, libil2cpp.so presence)
  * global-metadata.dat availability (this decides how far you can get)
  * protection hints (obfuscator strings, packer markers)
  * recommended revx commands
EOF
  exit 0
}

[[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]] && usage

TARGET="$1"

if [[ -f "$TARGET" ]]; then
  LIBS=("$TARGET")
  BASE="$(dirname "$TARGET")"
else
  [[ -d "$TARGET" ]] || { echo "not a file or directory: $TARGET" >&2; exit 1; }
  BASE="$TARGET"
  LIBS=()
  while IFS= read -r lib; do LIBS+=("$lib"); done < <(find "$BASE" -maxdepth 1 -name '*.so' -type f | sort)
  [[ ${#LIBS[@]} -eq 0 ]] && { echo "no .so files in $TARGET" >&2; exit 1; }
fi

total_bytes=0
for lib in "${LIBS[@]}"; do
  size=$(stat -f%z "$lib" 2>/dev/null || stat -c%s "$lib" 2>/dev/null || echo 0)
  total_bytes=$((total_bytes + size))
done
echo "== corpus =="
echo "libs: ${#LIBS[@]}  total: $((total_bytes / 1024 / 1024)) MB"

echo
echo "== top 5 by size =="
for lib in "${LIBS[@]}"; do
  echo "$(( $(stat -f%z "$lib" 2>/dev/null || stat -c%s "$lib" 2>/dev/null || echo 0) / 1024 / 1024 )) MB  $(basename "$lib")"
done | sort -rn | head -5

echo
echo "== il2cpp markers =="
IL2CPP_PRESENT=no
for lib in "${LIBS[@]}"; do
  name="$(basename "$lib")"
  if [[ "$name" == libil2cpp.so ]]; then IL2CPP_PRESENT=yes; fi
done
echo "libil2cpp.so present: $IL2CPP_PRESENT"

if command -v nm >/dev/null 2>&1; then
  sample="${LIBS[${#LIBS[@]}-1]}"
  api_count=$(nm -gU "$sample" 2>/dev/null | grep -c ' il2cpp_' || true)
  if [[ "$api_count" -gt 0 ]]; then
    echo "il2cpp_* exports in $(basename "$sample"): $api_count (il2cpp runtime confirmed)"
  fi
fi

echo
echo "== global-metadata.dat =="
METADATA=""
for candidate in \
  "$BASE/global-metadata.dat" \
  "$BASE/il2cpp_data/Metadata/global-metadata.dat" \
  "$(dirname "$BASE")/global-metadata.dat" \
  "$(dirname "$BASE")/il2cpp_data/Metadata/global-metadata.dat"; do
  if [[ -f "$candidate" ]]; then METADATA="$candidate"; break; fi
done
if [[ -n "$METADATA" ]]; then
  echo "FOUND: $METADATA"
  echo "-> full class/field/method recovery is possible"
  echo "-> next: revx analyze <lib> --profile full  (with REVX_IL2CPP_METADATA set)"
else
  echo "NOT FOUND (checked lib dir, parent dir, il2cpp_data/Metadata/)"
  echo "-> class names and field offsets will be UNAVAILABLE; only structural"
  echo "   analysis + export tables + method-pointer scans work"
  echo "-> get the file from the APK: unzip the APK, it lives at"
  echo "   assets/bin/Data/Managed/Metadata/global-metadata.dat"
fi

echo
echo "== protection hints =="
strings_sample() {
  local lib="$1" limit="${2:-2000000}"
  if command -v strings >/dev/null 2>&1; then
    strings -n 6 "$lib" 2>/dev/null | head -c "$limit"
  fi
}
for lib in "${LIBS[@]}"; do
  name="$(basename "$lib")"
  hits=""
  if strings_sample "$lib" | grep -q "Tencent.*protect\|tersafe\|libTP" ; then
    hits="tersafe/TP (Tencent protect)"
  fi
  if strings_sample "$lib" | grep -qi "frida-agent\|xposedBridge\|libxposed"; then
    hits="$hits anti-instrumentation markers"
  fi
  [[ -n "$hits" ]] && echo "$name: $hits"
done
echo "(empty = no obvious protection markers in the first strings pass)"

echo
echo "== recommended next steps =="
if [[ -n "$METADATA" ]]; then
  echo "1. revx analyze <libil2cpp.so> --profile full"
  echo "2. revx export-offsets --binary libil2cpp.so --out offsets.json"
  echo "3. revx func <TypeName.MethodName>   /  revx decompile <query>"
else
  echo "1. revx il2cpp-scan <libil2cpp.so>          # method tables, relocs"
  echo "2. revx analyze <lib.so> --profile fast     # batch survey all libs"
  echo "3. revx export-offsets --binary <name> --out offsets.json"
fi
