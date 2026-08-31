# il2cpp internals (as revx sees them)

## global-metadata.dat

Unity il2cpp ships type information in `global-metadata.dat`, separate from
`libil2cpp.so`. Header starts with sanity `0xFAB11BAF` (little-endian u32),
then a version u32 (revx supports 20–31). Field pairs at fixed header
offsets give (offset, size) of each table:

| header offset | table |
|---|---|
| 0x50 | string (names) |
| 0x58 | typeDefinitions |
| 0x60 | fields |
| 0x70 | methods |

TypeDefinition stride is 0x4C on v24.2: name index at +0x00, namespace at
+0x04, fieldStart at +0x30, fieldCount at +0x38, methodStart at +0x40,
methodCount at +0x44. All indices are into the string table (null-terminated
C strings at `string_offset + index`).

**Where to find it**: inside the APK at
`assets/bin/Data/Managed/Metadata/global-metadata.dat`. If the game uses a
packer (Tencent TP/tersafe), the file may be encrypted at rest or assembled
in memory only — revx has no loader for that; the honest answer to the user
is that class/field recovery is blocked, and structural analysis is the
ceiling.

## Method-pointer tables (CodeRegistration / CppCodegenModule)

Without metadata, method addresses are still recoverable from the binary
itself. `revx il2cpp-scan` runs two detectors:

1. **File-state (count, ptr) scan** — sweeps data/readonly sections for
   u64 pairs that look like (methodCount, methodPointers). A pair is
   accepted only when ≥4 of the following 8 slots after `ptr` land in
   executable sections (density rule). Packer-encrypted tails generate
   huge random u64s; the density rule rejects them (zero false positives
   on the 133-lib corpus).
2. **Relocation-aware scan** — collects R_AARCH64_RELATIVE addends (the
   object crate reports kind `Unknown`; revx keys on addend != 0), sorts,
   and finds maximal runs where consecutive addends step by 8 and run
   length ≥ 100. Such runs are methodPointer arrays materialized by the
   dynamic linker.

**Why methods in export-offsets are indexed, not named**: metadata gives
each module a methodPointer *array*; aligning method index → table slot
needs the real global-metadata.dat (module name pointers are stripped by
packers). With metadata absent, revx exports `methodPointerTable[N]`
addresses instead of inventing names. Do not present them as symbols.

## Field offsets: why export-offsets writes 0

v24.2 FieldDef entries carry name + type index, not the compile-time field
offset. Offsets live in the compiled class objects at runtime. esp-overlay's
consumer treats offset 0 as "miss" and falls back to runtime heuristics, so
a zero there is contract-valid, not an error. Recovering real offsets needs
either v27+ metadata (fieldOffsets table) or runtime klass traversal.
