# DEX agent surface — region vs legacy (2026-10)

Agent-facing evidence for the R5 synthetic matrix. JADX is not a CI dependency. Legacy render is the goto-shaped path that wrapped JADX-class tools emit for these shapes.

## How an agent should read a method

1. `dex_decompile` with default `detail=summary`.
2. Cite `evidence_id`. Read `coverage.status`.
3. If `partial`, `list_unknowns` / `unknowns[]` for the fallback reason. Page text with `inspect_analysis_view`.
4. Do not treat an empty call list or leftover goto as “no structure” when coverage is `unknown`.

## Matrix

| shape | region path | coverage | unknown.reason | agent-visible text |
| --- | --- | --- | --- | --- |
| nested natural loops | yes | complete | none | `while` nest, no split |
| two-entry loop | yes, `nodes_split >= 2` | complete | none | two single-entry `while (true)` copies |
| SCC larger than split budget 32 | no | partial | `budget_exceeded` | same as legacy |
| multi-entry SCC with protected block | no | partial | `loop_exception_intersection` | same as legacy |
| try crosses loop back-edge | yes, after R7 | complete | none | `try` inside `while (true)` |
| multi-entry loop with phi | yes, after R6 lowering | complete | none | region `while` copies |
| loop with two return tails | yes, after R8 | complete | none | `while (true)` with both tails |
| switch arms rejoin | yes, after R8 | complete | none | join emitted once |
| switch inside loop | yes, after R8 | complete | none | `switch` in `while (true)` |

Tests: `crates/revx-dex/tests/evidence.rs`, `crates/revx-dex/tests/r5_acceptance.rs`.

## What this does not claim

Private APK SHA-256 `656331a8…` was not re-run. JADX was not invoked. v1 does not claim zero goto on arbitrary DEX.
