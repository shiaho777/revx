# ReVX

`revx` is a new standalone Rust reverse-engineering workspace built around three invariants:

- one cross-platform binary for Windows, macOS, and Linux hosts,
- one workspace authority in `.revx/`,
- one daemon capability surface shared by CLI, TUI, and MCP.

This repository is aligned to the ReVX v1 correction plan. It does not treat ad hoc HTTP routes or direct CLI-to-analysis calls as the product contract.

## Current shape

The Rust workspace is split into:

- `revx-core`: canonical model, artifact handles, capability DTOs
- `revx-loader`: PE/ELF/Mach-O normalization, strings, relocations, debug hooks
- `revx-arch-x64`: x86_64 decode and reference extraction
- `revx-arch-arm64`: arm64 decode and reference extraction
- `revx-analysis`: cross-arch recovery pipeline prototype using the canonical model
- `revx-workspace`: SQLite authority plus content-addressed artifact store
- `revx-daemon`: transport-agnostic capability service, local IPC, stdio MCP
- `revx` binary: ultra-thin CLI (`revx-query` + system SQLite; light query/status/func/xrefs/decompile/disasm)
- `revx-engine` binary: full capability stack (analyze, object, daemon, mcp; system SQLite; default arm64 analysis)
- `revx-micro` binary: pure-std ultra-low-memory ELF analyzer (`revx analyze --micro`)
- `revx-query`: read-only SQLite query crate for thin CLI

Build the full toolset with:

```bash
cargo build -p revx -p revx-engine -p revx-micro --release
```

Optional full object/debug stack (zip/tar/xz containers + DWARF/PDB):

```bash
cargo build -p revx-engine --release --features full-loader
```

x86_64 decode is optional via `revx-analysis` feature `arch-x64`.

Place `revx`, `revx-engine`, and `revx-micro` side by side on `PATH` (or set `REVX_ENGINE`). Light commands stay in-process; heavy commands spawn `revx-engine`. System `sqlite3` (pkg-config) is required for non-bundled builds.

Default analysis targets single-digit MB process growth (`REVX_RSS_MB=8`, 1 job, lean Fast snapshots). Raise only when needed via `REVX_FULL_MEM=1` / `REVX_RSS_MB=512`. Ultra-low: `REVX_MICRO=1`.

## Commands

The public command surface is constrained to the v1 plan:

- `revx daemon start|stop|status`
- `revx init <path>`
- `revx add <path>`
- `revx analyze <path> [--profile fast|full]`
- `revx status`
- `revx survey`
- `revx funcs`
- `revx func <name|addr>`
- `revx xrefs <target>`
- `revx strings`
- `revx search text <pattern>`
- `revx search bytes <pattern>`
- `revx evidence <subject>`
- `revx brief <query>`
- `revx report generate <topic>`
- `revx trace import <file>`
- `revx mcp serve`
- `revx tui`

## Workspace authority

The workspace layout is:

```text
.revx/
  project.toml
  state.sqlite
  artifacts/
  cache/
  reports/
  log/
```

Large payloads are written into `.revx/artifacts/` as content-addressed blobs. SQLite stores summaries, query fields, and artifact handles rather than raw survey/function/report payloads.

`project.toml` is schema-gated. Pre-v1 unstable layouts are not migrated forward; reinitialize and reanalyze instead.

## IPC and MCP

- daemon transport default:
  - macOS/Linux: Unix domain socket at `.revx/daemon.sock`
  - Windows: named pipe (`\\.\pipe\revx-<hash>`), path marker at `.revx/daemon.pipe`
- MCP transport default:
  - stdio JSON-RPC surface exposing only high-level tools

The high-level MCP tools are:

- `project_open`
- `project_status`
- `binary_list`
- `analysis_run`
- `analysis_status`
- `binary_survey`
- `function_search`
- `function_profile`
- `decompile_function`
- `disassemble_function`
- `xrefs_query`
- `callgraph_slice`
- `string_search`
- `evidence_pack`
- `hypothesis_create`
- `hypothesis_update`
- `report_generate`
- `analysis_brief`
- `trace_import`
- `trace_query`

## Build and smoke

```bash
cargo check
cargo test

cargo run -p revx -- init .
cargo run -p revx -- add /path/to/binary
cargo run -p revx -- analyze /path/to/binary --profile fast
cargo run -p revx -- survey
cargo run -p revx -- func main
cargo run -p revx -- brief ActiveDesk
```

## Current v1 boundary

Implemented now:

- canonical workspace state with artifact indirection
- PE/ELF/Mach-O normalization
- x86_64 and arm64 decode/reference extraction moved into dedicated arch crates (both enabled by default)
- function recovery, CFG block splitting, xrefs, callgraph slice, strings, evidence, pseudocode
- stronger stack/arg/local recovery (SysV vs Win64, def-before-use arg masks, stack args/locals)
- richer type import/inference from debug hints, known libc signatures, and usage patterns
- deterministic region structuring (if/loop/switch/return) for fast + SSA paths
- parity suite across PE/ELF/Mach-O × x86_64/arm64 synthetic targets
- daemon capability service with Unix sockets and Windows named-pipe transport
- stdio MCP high-level tool surface
- read-oriented TUI (`revx tui` / `revx-engine tui`): status/funcs/strings/xrefs + dual-pane detail (CFG|pseudo), notes
- decompile strategies (`auto|cached|fast|full|hotblock`) on CLI/MCP/TUI with cache write-back

Still improving beyond v1:

- even higher-fidelity structuring on multi-thousand-instruction monsters
- broader public corpus CI (currently: synthetic matrix + optional real SO smoke)

Recent optimizations:

- adaptive SSA/linear/heavy limits (`REVX_FULL_MEM` boosts 4×; Full default 2× when not lean)
- hot-block multi-window SSA for oversized functions (score entry/calls/loops/xrefs)
- sampled stack/arg/local recovery for large functions (prologue/call-site/epilogue)
- parallel analysis pool when `REVX_JOBS>1` (up to 4 with `REVX_FULL_MEM`)
- decompile strategy selection + recomposed/strategy-keyed pseudocode write-back (`revx-engine decompile --strategy hotblock --force-refresh`)
- denser address tags in fast/SSA/hotblock text + TUI carry-forward linking (`j`/`k`, exact highlight)
- TUI triple pane detail (cfg/disasm/pseudo) with linked addresses (`h`/`l`, `i` disasm, `c` cache status)
- `decompile_cache_status` MCP/CLI (`revx-engine decompile-cache <query>`) for strategy cache inspection

- TUI dual-pane detail with address-linked highlight (`j`/`k` link, `h`/`l` pane, `s` cycle strategy)
- CI workflow + parity/corpus/golden tests (`REVX_CORPUS_DIR` optional)

## Contributing

Issue → PR into `main` → CI (**ci / test**) green → merge (Issue closes via `Fixes #N`). See [CONTRIBUTING.md](CONTRIBUTING.md); coding agents: [AGENTS.md](AGENTS.md).
