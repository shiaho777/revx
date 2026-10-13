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

Census schema v6 adds `phi_lower_methods` on top of evidence/unknown ids. R7 puts shared handlers, ordinary-reachable handlers, and try-in-loop on the region path; overlapping tries still use `cross_region_edge`.
