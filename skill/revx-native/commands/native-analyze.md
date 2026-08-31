---
allowed-tools: Bash, Read, Glob, Grep, Write, Edit
description: Fingerprint and analyze a native Android library (or a whole arm64-v8a directory) with revx
user-invocable: true
argument-hint: <path to .so file or directory of .so files>
argument: path to a native .so or a directory containing them (optional)
---

# /native-analyze

Fingerprint, analyze, and (for il2cpp targets) export offsets from native
Android libraries.

## Step 1: Get the target

Use the argument path if given. Otherwise ask for either a single `.so` file
or a directory of extracted native libraries (typically `arm64-v8a/` from an
APK).

## Step 2: Dependency check

```bash
bash ${SKILL_DIR}/scripts/check-deps.sh
```

If `REVX_MISSING`, build at the repo root: `cargo build --release -p revx`.
If `WORKSPACE_MISSING`, remember to create one in Step 4.

## Step 3: Fingerprint (Phase 0 verdict)

```bash
bash ${SKILL_DIR}/scripts/fingerprint.sh <target>
```

Report to the user: il2cpp presence, **global-metadata.dat availability**
(this decides everything), protection markers. If metadata is missing, tell
the user where to get it and what stays possible without it.

## Step 4: Workspace + analysis

```bash
mkdir -p ws && cd ws && revx init .
revx analyze <target.so> --profile fast          # triage
REVX_IL2CPP_METADATA=<path> REVX_RSS_MB=512 \
  revx analyze <libil2cpp.so> --profile full     # when metadata exists
```

For a whole directory:

```bash
bash ${SKILL_DIR}/scripts/analyze-corpus.sh <dir> ws
```

## Step 5: il2cpp surface + offsets

```bash
revx il2cpp-scan <libil2cpp.so>
revx export-offsets --binary libil2cpp.so --out offsets.json
```

## Step 6: Deliver

Summarize per-lib: functions, typed functions, pseudocode, coverage. Hand
over `offsets.json` when produced, and name findings with addresses. Do not
show internal workspace IDs.
