# Corpus-wide runs and budget knobs

## Environment variables

| variable | default | meaning |
|---|---|---|
| `REVX_RSS_MB` | 8 | memory envelope; scales function budget (`by_rss = rss_kb / 8`) |
| `REVX_MAX_FUNCTION_BUDGET` | derived | hard override of the function cap |
| `REVX_DEPTH_QUOTA` | budget/4 | how many functions get deep (typed) analysis |
| `REVX_LEAN` / `REVX_MICRO` / `REVX_FULL_MEM` | unset | mode selection; lean skips debug import + il2cpp enrichment |
| `REVX_WALL_SEC` / `REVX_CPU_SEC` | unset | wall/CPU time ceilings per analysis |
| `REVX_JOBS` | 1 | parallel analysis workers (non-deterministic above 1) |
| `REVX_IL2CPP_METADATA` | unset | explicit path to global-metadata.dat |

Rule of thumb: default 8 MB gives triage-grade results for ~100 libs in
seconds. For a single important lib (libil2cpp, libGameCore) raise
`REVX_RSS_MB=512` and use `--profile full`; typed-function and pseudocode
counts rise roughly linearly with the budget.

## Reading the summary

- `function_count` — recovered functions (budget-capped; check `warnings`)
- `typed_function_count` / `structured_pseudocode_count` — deep-analysis yield
- `deep_function_count` — functions that went through full CFG/SSA
- `lean_stub_pseudocode_count` — lean-mode placeholder bodies (not real pseudocode)
- `coverage` — `(claimed + probed) / total` executable bytes. ~0.69 on
  libGameCore is typical for a packed Tencent title; the uncovered tail is
  encrypted sections, not a revx defect.

## Warning semantics

- tiny-budget warnings → raise `REVX_RSS_MB` or `REVX_MAX_FUNCTION_BUDGET`
- `truncated` counts → budget hit; increase and re-run the single lib
- repeated coverage ≈ 0 with nonzero function_count → packed/encrypted .text;
  document and move on

## Failure playbook

| symptom | cause | action |
|---|---|---|
| analyze exits 0 but empty summary | cwd has no workspace | `revx init .` first |
| functions ≈ budget exactly | cap reached | raise budget for that lib |
| il2cpp-scan shows 0 tables on a known il2cpp lib | packer stripped/encrypted | report as protection finding |
| export-offsets classes empty | metadata missing or lean run | re-run full profile with metadata path |
