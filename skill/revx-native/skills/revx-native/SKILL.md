---
description: Analyze native Android libraries (libil2cpp.so, libGameCore.so, ARM64 .so) with revx — a memory-frugal native reverse-engineering CLI. Find il2cpp method-pointer tables, recover class/field metadata, export offset tables for game tooling, and decompile ARM64 functions. Use when the user wants to analyze native .so libraries, extract il2cpp offsets, reverse engineer a Unity game's native code, or decompile ARM64. 中文触发词：逆向so、il2cpp分析、导出偏移、原生库分析、反编译ARM64、游戏逆向
trigger: analyze so|native library|libil2cpp|il2cpp|global-metadata|method pointer table|offset table|export-offsets|arm64 reverse|decompile arm64|逆向so|il2cpp偏移|原生库逆向|so分析
---

# Native Library Reverse Engineering with revx

Analyze ARM64/ARM32 native libraries from Android apps — especially Unity
il2cpp games — using revx, a CLI that keeps a hard memory envelope (default
8 MB RSS) so full-corpus analysis fits in CI or a laptop. revx's differentiator
vs jadx-class tools is the **native layer**: jadx stops at DEX, revx reads the
ELF below it — il2cpp metadata, method-pointer tables, relocations — and turns
them into a validated offset table.

## Prerequisites

revx must be built from the repo root (Rust workspace). Verify:

```bash
bash ${SKILL_DIR}/scripts/check-deps.sh
```

Output is machine-readable: `REVX_OK:<path>` / `REVX_MISSING`,
`WORKSPACE_OK:<dir>` / `WORKSPACE_MISSING`. If missing, build with
`cargo build --release -p revx` at the repo root (needs Rust 1.85+).

## Workflow

### Phase 0: Fingerprint the corpus (always first)

Before any analysis, run triage. It tells you whether the target is an il2cpp
game, whether `global-metadata.dat` exists (this single file decides how far
you can get), and which protection markers are present.

```bash
bash ${SKILL_DIR}/scripts/fingerprint.sh <dir-with-so | file.so>
```

Read the verdict:
- **global-metadata.dat FOUND** → full path: classes, fields, methods, offsets.
  Phases 1–3 below apply directly.
- **global-metadata.dat NOT FOUND** → tell the user this is the bottleneck and
  where to find it (unzip the APK: `assets/bin/Data/Managed/Metadata/`).
  Structural analysis (Phase 2) still works; Phase 3 will carry empty classes.
- **tersafe/TP markers** → Tencent protection present; expect encrypted .text
  tails and stripped module names. Note it in your report — do not promise
  symbol recovery the binary cannot give.

### Phase 1: Establish a workspace (once per project)

```bash
mkdir -p ws && cd ws
revx init .
```

### Phase 2: Analyze

Single library, default profile (fast, ~8 MB RSS):

```bash
revx analyze /path/to/lib.so --profile fast
```

Full profile with il2cpp metadata enrichment (needs the metadata file next to
the binary, or `REVX_IL2CPP_METADATA` pointing at it):

```bash
REVX_IL2CPP_METADATA=/path/to/global-metadata.dat \
REVX_RSS_MB=512 \
  revx analyze /path/to/libil2cpp.so --profile full
```

Batch a whole corpus (skip per-binary noise, see `references/batch.md`):

```bash
bash ${SKILL_DIR}/scripts/analyze-corpus.sh <dir-with-so> [ws-dir]
```

What the summary JSON tells you: `function_count`, `typed_function_count`
(functions with recovered argument types), `structured_pseudocode_count`,
`coverage` (fraction of executable bytes accounted for). Coverage far below
~0.5 on a big game lib usually means protection-encrypted sections, not a
revx bug — say so instead of retrying.

### Phase 3: il2cpp surface scan + offset export

Method-pointer tables and relocation scan (no metadata needed):

```bash
revx il2cpp-scan /path/to/libil2cpp.so
```

`method_pointer_tables` + `method_entries` counts confirm CodeRegistration
layout; `metadata_candidates` shows where revx looked for global-metadata.dat.

Export the offset table consumed by esp-overlay / game tooling:

```bash
revx export-offsets --binary libil2cpp.so --out offsets.json
```

The output validates against the `esp-offsets` v1 contract: `format`,
`version`, `binary`, `hash_blake3`, `classes{fields{offset,type}}`,
`globals{}`, `methods{address}`. If `classes` is empty and a warning is
present, metadata enrichment never ran — revisit Phase 0's verdict.

### Phase 4: Interrogate results

All queries run against the workspace (cwd or a parent with a workspace):

```bash
revx funcs --limit 50 <name-pattern>     # search functions
revx func <name-or-address>              # one function's details
revx decompile <name-or-address>         # structured pseudocode
revx disasm <name-or-address>            # basic blocks
revx xrefs <name-or-address>             # cross-references
revx strings --limit 100 <pattern>       # string literals
revx survey [--binary-id ID]             # corpus overview
```

Decompile quality is best on full-profile runs with metadata; fast-profile
runs return compact summaries suited to triage.

## Deliverables

End a session with: (1) the fingerprint verdict, (2) per-lib analysis summary
table, (3) `offsets.json` when il2cpp is involved, (4) named findings with
addresses — not internal workspace IDs.

## References

- `${SKILL_DIR}/references/il2cpp-internals.md` — metadata layout,
  method-pointer tables, why index alignment needs real metadata
- `${SKILL_DIR}/references/batch.md` — corpus-wide runs, budget env vars,
  interpreting warnings and coverage
- `${SKILL_DIR}/references/esp-offsets-format.md` — the exported table
  contract and its consumer
