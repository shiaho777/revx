# ghidra-decompiler (vendored)

Ghidra's native decompiler core (C++), vendored under Apache-2.0.
See `cpp/VENDORED.md` for the exact modification list (GPL-BFD excision,
macOS libc++ crash fixes, unbuffered console output).

## What the revx build produces

- `decomp_opt` — console decompiler driven by an XML `<binaryimage>` script
  (the bridge path used by `revx decompile --engine ghidra`)
- `sleigh_opt` — Sleigh compiler used to build processor `.sla` files

## Sleigh specification (AARCH64)

The ARM64 `.slaspec`/`.pspec`/`.cspec` come from upstream
`Ghidra/Processors/AARCH64/data/languages/` and are compiled once via:

```bash
sleigh_opt AARCH64.slaspec AARCH64.sla
```

The resulting `AARCH64.sla` + spec XMLs are cached under `~/.revx/ghidra/`
(the bridge compiles them on first use if absent).

## Bridge protocol (revx ↔ decomp_opt)

1. revx recovers function boundaries and (optionally) il2cpp types
2. revx writes a `<binaryimage>` XML: one `<bytechunk>` per mapped segment
   (hex-encoded), plus `<define>` for known symbols/types
3. script: `load file X` → `load addr <fn> <name>` → `decompile` → `print C`
4. revx parses the C text back; errors arrive on unbuffered stderr

This keeps the GPL-free boundary: no BFD, no Ghidra Java, no GPL code.
