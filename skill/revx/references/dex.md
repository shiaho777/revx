# DEX evidence

## Coverage

| status | meaning |
| --- | --- |
| complete | Region tree rendered the method. `used_region_path` is true. |
| partial | Legacy render after a recorded fallback. Text matches `--mode legacy`. |
| unknown | No code, parse failure, or no fallback recorded. |

Missing coverage is unknown, not absence.

## Fallback reasons (unknown.reason)

- `shared_handler`
- `ordinary_reachable_handler`
- `invalid_exception_metadata`
- `cross_region_edge`
- `loop_exception_intersection`
- `unsupported_control_flow`
- `budget_exceeded`
- `validation_failed`

## Tools

- MCP `dex_decompile` `{ "path": "/abs/classes.dex", "method": "onCreate" }`
- MCP `inspect_analysis_view` `{ "evidence_id": "ev_…", "offset": 0, "limit": 80 }`
- MCP `list_unknowns` `{}`
- CLI `revx dex decompile <path> --json --detail summary`
- CLI `revx dex goto-census <path> --json`

Census schema v7 classifies leftover final `goto L<n>;` as `irreducible_loop`, `handler`, `switch`, `unstructured`, or `unknown`. R11 keeps one method's pseudocode byte-identical across processes: join phis follow ascending Dalvik registers, and semantic renames apply once to the original tokens. Raw revisit / forward-revisit stay emission-path diagnostics. R7 puts shared handlers, ordinary-reachable handlers, and try-in-loop on the region path. R8 puts loop-only multi-exit and switch-in-loop on the region path. Overlapping tries still use `cross_region_edge`. Two loop exits that both merge with outer code still use `unsupported_control_flow`.
