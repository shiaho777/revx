#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="target/bench-results/$STAMP"
mkdir -p "$OUT"

run_pass() {
  local name=$1
  shift
  echo "== pass: $name =="
  env "$@" cargo bench -p revx-analysis --bench analyze -- --save-baseline "$name" 2>&1 | tee "$OUT/$name.log"
}

run_pass lean
run_pass fullmem REVX_FULL_MEM=1 REVX_RSS_MB=512

python3 - "$OUT/summary.csv" <<'PY'
import json, pathlib, sys

out = sys.argv[1]
root = pathlib.Path("target/criterion")
rows = ["pass,bench,mean_ns,std_dev_ns"]
for estimates in sorted(root.glob("*/*/*/estimates.json")):
    group, bid, baseline = estimates.relative_to(root).parts[:3]
    if baseline == "new":
        continue
    data = json.loads(estimates.read_text())
    rows.append(
        f"{baseline},{group}/{bid},"
        f"{data['mean']['point_estimate']:.0f},"
        f"{data['std_dev']['point_estimate']:.0f}"
    )
pathlib.Path(out).write_text("\n".join(rows) + "\n")
print("\n".join(rows))
print(f"saved: {out}")
PY
