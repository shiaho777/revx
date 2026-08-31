# esp-offsets v1 — the exported offset table contract

## Example

```json
{
  "format": "esp-offsets",
  "version": 1,
  "binary": "libGameCore.so",
  "hash_blake3": "…64 hex chars…",
  "generated": "2026-08-30T14:10:00.168996+00:00",
  "generator": "revx 0.1.0",
  "binary_format": "Elf",
  "binary_architecture": "Arm64",
  "warnings": [],
  "classes": {
    "UnityEngine.Camera": {
      "fields": { "current": {"offset": 0, "type": null} }
    }
  },
  "globals": {},
  "methods": {
    "methodPointerTable[0]": {"address": 69206004}
  }
}
```

## Validation rules (enforced by the consumer)

- `format` must be exactly `"esp-offsets"`, `version` must be `1` — otherwise
  the table is rejected outright
- `classes`/`globals`/`methods` are optional objects; unknown extra keys are
  ignored
- field entries: `{"offset": <u32>, "type": <string|null>}`; a field whose
  `offset` is 0 is treated as **miss** by esp-overlay's camera path and the
  engine falls back to runtime heuristics — so zero offsets are safe to emit
- `methods` values: `{"address": <u64>}`; file offsets (image-relative), not
  runtime VAs

## Consumer

esp-overlay (Android ESP overlay) loads the table from
`/data/data/com.esp.overlay/files/offsets.json` at init. If the file is
missing or invalid, the app logs and continues in heuristic mode — table
presence is an accelerator, never a hard dependency.

## Field semantics

- `hash_blake3` — blake3 of the analyzed .so; consumers can verify the table
  belongs to the binary loaded in the target process (hash check is planned;
  today the consumer validates structure only)
- `generated` — timestamp of the source analysis run (null if unknown)
- `warnings` — non-empty means the export is structurally valid but
  incomplete (typically: no il2cpp metadata was available at analysis time)
