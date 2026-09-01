# Vendored: Ghidra native decompiler

Source: https://github.com/NationalSecurityAgency/ghidra
Path upstream: Ghidra/Features/Decompiler/src/decompile/cpp
License: Apache-2.0 (see LICENSE.upstream-ghidra at this directory's parent)

Modifications made by the revx project (all marked with `// revx:` comments):
1. Removed GPL-BFD integration: `bfd_arch.*`, `loadimage_bfd.*`, `analyzesigs.*`,
   `sleighexample.cc` are NOT vendored (upstream keeps them optional); the
   `-lbfd` link flag and `IfcCodeDataTarget` BFD command were excised.
2. `RawLoadImage::~RawLoadImage` guards `thefile->close()` with `is_open()`
   (crash on half-open streams with macOS libc++).
3. `filemanage.cc` `findFile` drops redundant explicit `close()` calls
   (same libc++ crash class).
4. `consolemain.cc` routes console output through `std::cerr` (unbuffered,
   so scripts driving the binary never lose error text on abort).

The AARCH64 Sleigh specification is NOT vendored here; the bridge compiles
it from upstream at build time (see third_party/ghidra-decompiler/README.md)
or consumes a prebuilt `.sla`.
