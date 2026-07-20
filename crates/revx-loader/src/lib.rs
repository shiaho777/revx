use anyhow::{Context, Result};
#[cfg(feature = "containers")]
use bzip2::read::BzDecoder;
#[cfg(feature = "containers")]
use flate2::read::GzDecoder;
#[cfg(feature = "debug-info")]
use gimli::{EndianSlice, RunTimeEndian, SectionId};
use object::read::macho::MachHeader;
use object::{
    Architecture as ObjArch, Object, ObjectSection, ObjectSegment,
    ObjectSymbol, ObjectSymbolTable, SegmentFlags, endian::Endianness, macho,
};
#[cfg(feature = "debug-info")]
use pdb::{FallibleIterator, PDB};
use revx_core::{
    Architecture, BinaryFormat, BinaryImage, CompoundFile, DebugArtifact, DebugFunctionHint,
    DebugImportStatus, DebugImportSummary, Export, Import, Module, ObjectAnalysisStatus,
    ObjectAnalysisSummary, ObjectEdge, ObjectEdgeKind, ObjectGraph, ObjectKind, Relocation,
    Section, Segment, StringLiteral, Symbol, UniversalObject, is_compound_file,
};
#[cfg(feature = "debug-info")]
use revx_core::{
    DebugVariableHint, SourceAnchor, TypeDef, TypeSource, Variable, VariableRole, VariableStorage,
};
#[cfg(feature = "containers")]
use ruzstd::decoding::StreamingDecoder as ZstdDecoder;
#[cfg(feature = "debug-info")]
use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use memmap2::Mmap;
use std::fs;
#[cfg(feature = "containers")]
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
#[cfg(feature = "containers")]
use xz2::read::XzDecoder;


fn advise_mmap_sequential(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    #[cfg(unix)]
    unsafe {
        unsafe extern "C" {
            fn madvise(addr: *mut u8, len: usize, advice: i32) -> i32;
        }
        const MADV_SEQUENTIAL: i32 = 2;
        let _ = madvise(bytes.as_ptr() as *mut u8, bytes.len(), MADV_SEQUENTIAL);
    }
    let _ = bytes;
}

fn advise_mmap_dontneed(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    #[cfg(unix)]
    unsafe {
        unsafe extern "C" {
            fn madvise(addr: *mut u8, len: usize, advice: i32) -> i32;
        }
        #[cfg(target_os = "macos")]
        const MADV_FREE: i32 = 5;
        #[cfg(target_os = "macos")]
        const MADV_DONTNEED: i32 = 4;
        #[cfg(not(target_os = "macos"))]
        const MADV_DONTNEED: i32 = 4;
        #[cfg(target_os = "macos")]
        {
            let _ = madvise(bytes.as_ptr() as *mut u8, bytes.len(), MADV_FREE);
            let _ = madvise(bytes.as_ptr() as *mut u8, bytes.len(), MADV_DONTNEED);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = madvise(bytes.as_ptr() as *mut u8, bytes.len(), MADV_DONTNEED);
        }
    }
    let _ = bytes;
}

pub fn load_binary(path: &Path) -> Result<BinaryImage> {
    let file_handle = fs::File::open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    let bytes = unsafe { Mmap::map(&file_handle) }
        .with_context(|| format!("failed to mmap {}", path.display()))?;
    if let Some(thin) = extract_preferred_macho_thin_slice(&bytes) {
        let cache = std::env::temp_dir().join(format!(
            "revx-macho-thin-{}.bin",
            blake3::hash(&thin).to_hex()
        ));
        if !cache.exists() {
            fs::write(&cache, &thin).with_context(|| {
                format!(
                    "failed to materialize preferred Mach-O thin slice for {}",
                    path.display()
                )
            })?;
        }
        let mut image = load_binary_from_bytes(&cache, &thin)?;
        image.path = cache.display().to_string();
        if let Some(module) = image.modules.first_mut() {
            module.path = Some(path.display().to_string());
            module.name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string());
        }
        return Ok(image);
    }
    advise_mmap_sequential(&bytes);
    let image = load_binary_from_bytes(path, &bytes)?;
    advise_mmap_dontneed(&bytes);
    Ok(image)
}

fn load_binary_from_bytes(path: &Path, bytes: &[u8]) -> Result<BinaryImage> {
    let file = object::File::parse(bytes).context("failed to parse object file")?;

    let format = match file.format() {
        object::BinaryFormat::Coff | object::BinaryFormat::Pe => BinaryFormat::Pe,
        object::BinaryFormat::Elf => BinaryFormat::Elf,
        object::BinaryFormat::MachO => BinaryFormat::MachO,
        _ => BinaryFormat::Unknown,
    };
    let architecture = match file.architecture() {
        ObjArch::X86_64 => Architecture::X86_64,
        ObjArch::Aarch64 => Architecture::Arm64,
        _ => Architecture::Unknown,
    };

    let modules = vec![Module {
        name: path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string()),
        path: Some(path.display().to_string()),
    }];

    let segments = file
        .segments()
        .map(|segment| Segment {
            name: segment
                .name()
                .ok()
                .flatten()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| format!("segment_{:x}", segment.address())),
            address: segment.address(),
            size: segment.size(),
            permissions: segment_permissions(&segment),
        })
        .collect();

    let sections = file
        .sections()
        .map(|section| Section {
            name: section.name().unwrap_or("<unknown>").to_string(),
            address: section.address(),
            size: section.size(),
            kind: format!("{:?}", section.kind()),
            file_offset: section.file_range().map(|(offset, _)| offset),
        })
        .collect();

    let micro = revx_core::micro_mode();
    let lean = revx_core::lean_mode();
    let symbol_cap = revx_core::lean_symbol_cap();
    let ie_cap = revx_core::lean_import_export_cap();

    let symbols = if symbol_cap == 0 {
        Vec::new()
    } else {
        let mut symbols = Vec::with_capacity(if lean { symbol_cap.min(256) } else { 8192 });
        let sources: &[&str] = if lean { &["dynamic", "static"] } else { &["static"] };
        for source in sources {
            if *source == "dynamic" {
                for sym in file.dynamic_symbols() {
                    if symbols.len() >= symbol_cap {
                        break;
                    }
                    symbols.push(Symbol {
                        name: sym.name().unwrap_or("<anon>").to_string(),
                        address: if sym.address() == 0 {
                            None
                        } else {
                            Some(sym.address())
                        },
                        kind: format!("{:?}", sym.kind()),
                        size: if sym.size() == 0 {
                            None
                        } else {
                            Some(sym.size())
                        },
                        global: sym.is_global(),
                    });
                }
            } else {
                if lean && !symbols.is_empty() {
                    break;
                }
                for sym in file.symbols() {
                    if symbols.len() >= symbol_cap {
                        break;
                    }
                    symbols.push(Symbol {
                        name: sym.name().unwrap_or("<anon>").to_string(),
                        address: if sym.address() == 0 {
                            None
                        } else {
                            Some(sym.address())
                        },
                        kind: format!("{:?}", sym.kind()),
                        size: if sym.size() == 0 {
                            None
                        } else {
                            Some(sym.size())
                        },
                        global: sym.is_global(),
                    });
                }
            }
            if symbols.len() >= symbol_cap {
                break;
            }
        }
        symbols
    };

    let mut imports = file_imports(&file, format, architecture, bytes, ie_cap, lean);
    if imports.len() > ie_cap {
        imports.truncate(ie_cap);
    }
    let mut exports = file_exports(&file, ie_cap);
    if exports.len() > ie_cap {
        exports.truncate(ie_cap);
    }
    let relocations = if micro || lean {
        Vec::new()
    } else {
        file_relocations(&file)
    };
    let mut debug_import = if micro || lean {
        DebugImportSummary::default()
    } else {
        import_debug_info(path, &bytes, &file, format, architecture)
    };
    if !micro && !lean {
        enrich_debug_function_hints_from_macho(&bytes, &file, format, &mut debug_import);
    }
    let debug_artifacts = if micro || lean {
        Vec::new()
    } else {
        file_debug_artifacts(path, &file, &debug_import)
    };

    let strings = if lean {
        let (max_count, max_bytes, max_scan) = revx_core::lean_string_limits();
        if max_count == 0 {
            Vec::new()
        } else {
            extract_strings_capped(&file, max_count, max_bytes, max_scan)
        }
    } else {
        extract_strings(&file)
    };
    let hash_blake3 = if micro || lean {
        hash_bytes_sample(bytes)
    } else {
        hash_bytes_streaming(bytes)
    };

    Ok(BinaryImage {
        id: hash_blake3.clone(),
        path: path.display().to_string(),
        format,
        architecture,
        entry: resolved_entry_point(&file, format),
        image_base: Some(file.relative_address_base()),
        size: bytes.len() as u64,
        hash_blake3,
        modules,
        segments,
        sections,
        imports,
        exports,
        relocations,
        debug_artifacts,
        debug_import,
        symbols,
        strings,
    })
}


fn segment_permissions(segment: &object::Segment<'_, '_>) -> String {
    match segment.flags() {
        SegmentFlags::Elf { p_flags } => {
            let mut parts = Vec::with_capacity(3);
            if p_flags & 0x4 != 0 {
                parts.push("r");
            }
            if p_flags & 0x2 != 0 {
                parts.push("w");
            }
            if p_flags & 0x1 != 0 {
                parts.push("x");
            }
            if parts.is_empty() {
                "none".to_string()
            } else {
                parts.join("")
            }
        }
        SegmentFlags::MachO { initprot, .. } => {
            let mut parts = Vec::with_capacity(3);
            if initprot & 0x1 != 0 {
                parts.push("r");
            }
            if initprot & 0x2 != 0 {
                parts.push("w");
            }
            if initprot & 0x4 != 0 {
                parts.push("x");
            }
            if parts.is_empty() {
                "none".to_string()
            } else {
                parts.join("")
            }
        }
        SegmentFlags::Coff { characteristics } => {
            let mut parts = Vec::with_capacity(3);
            if characteristics & 0x4000_0000 != 0 {
                parts.push("r");
            }
            if characteristics & 0x8000_0000 != 0 {
                parts.push("w");
            }
            if characteristics & 0x2000_0000 != 0 {
                parts.push("x");
            }
            if parts.is_empty() {
                format!("coff:{characteristics:x}")
            } else {
                parts.join("")
            }
        }
        SegmentFlags::None => "none".to_string(),
        other => format!("{other:?}"),
    }
}

fn resolved_entry_point(file: &object::File<'_>, format: BinaryFormat) -> Option<u64> {
    let entry = file.entry();
    if entry == 0 {
        return None;
    }
    if format == BinaryFormat::MachO {
        let text_base = file
            .segments()
            .find(|segment| {
                segment
                    .name()
                    .ok()
                    .flatten()
                    .is_some_and(|name| name == "__TEXT")
            })
            .map(|segment| segment.address())
            .or_else(|| {
                file.sections()
                    .find(|section| {
                        section
                            .name()
                            .ok()
                            .is_some_and(|name| name == "__text" || name.ends_with("__text"))
                    })
                    .map(|section| section.address())
            })
            .unwrap_or(0);
        let va = text_base.saturating_add(entry);
        if va != 0 {
            return Some(va);
        }
    }
    Some(entry)
}

fn enrich_debug_function_hints_from_macho(
    bytes: &[u8],
    file: &object::File<'_>,
    format: BinaryFormat,
    debug_import: &mut DebugImportSummary,
) {
    if format != BinaryFormat::MachO {
        return;
    }
    let starts = match macho_function_starts(bytes, file) {
        Some(starts) if !starts.is_empty() => starts,
        _ => return,
    };
    let mut known = debug_import
        .function_hints
        .iter()
        .filter_map(|hint| hint.address)
        .collect::<std::collections::BTreeSet<_>>();
    let mut added = 0usize;
    for address in starts {
        if address == 0 || !known.insert(address) {
            continue;
        }
        debug_import.function_hints.push(DebugFunctionHint {
            address: Some(address),
            name: format!("sub_{address:x}"),
            return_type: None,
            calling_convention: None,
            arguments: Vec::new(),
            locals: Vec::new(),
            source_anchor: None,
            evidence_ids: vec![format!("macho:function_starts:{address:x}")],
        });
        added += 1;
    }
    if added == 0 {
        return;
    }
    debug_import.imported_function_hint_count = debug_import
        .imported_function_hint_count
        .saturating_add(added);
    if debug_import.status == DebugImportStatus::NotFound {
        debug_import.status = DebugImportStatus::Parsed;
        debug_import.source_kind = Some("macho_function_starts".to_string());
    }
    debug_import
        .notes
        .push(format!("macho LC_FUNCTION_STARTS seeds={added}"));
}

fn macho_function_starts(bytes: &[u8], file: &object::File<'_>) -> Option<Vec<u64>> {
    let text_base = file
        .segments()
        .find(|segment| {
            segment
                .name()
                .ok()
                .flatten()
                .is_some_and(|name| name == "__TEXT")
        })
        .map(|segment| segment.address())?;
    parse_macho_function_starts::<macho::MachHeader64<Endianness>>(bytes, text_base).or_else(|| {
        parse_macho_function_starts::<macho::MachHeader32<Endianness>>(bytes, text_base)
    })
}

fn parse_macho_function_starts<Mach: MachHeader>(
    bytes: &[u8],
    text_base: u64,
) -> Option<Vec<u64>> {
    let header = Mach::parse(bytes, 0).ok()?;
    let endian = header.endian().ok()?;
    let mut commands = header.load_commands(endian, bytes, 0).ok()?;
    while let Some(command) = commands.next().ok()? {
        if command.cmd() != macho::LC_FUNCTION_STARTS {
            continue;
        }
        let data_cmd: &macho::LinkeditDataCommand<Mach::Endian> = command.data().ok()?;
        let mut iter = data_cmd.function_starts(endian, bytes, text_base).ok()?;
        let mut starts = Vec::new();
        while let Some(address) = iter.next().ok()? {
            starts.push(address);
        }
        if !starts.is_empty() {
            return Some(starts);
        }
    }
    None
}


fn extract_preferred_macho_thin_slice(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 8 {
        return None;
    }
    let magic = u32::from_be_bytes(bytes[0..4].try_into().ok()?);
    if magic != 0xcafebabe && magic != 0xcafebabf {
        return None;
    }
    let nfat = u32::from_be_bytes(bytes[4..8].try_into().ok()?) as usize;
    if nfat == 0 || nfat > 16 {
        return None;
    }
    let mut candidates = Vec::with_capacity(nfat);
    for index in 0..nfat {
        let base = 8 + index * 20;
        if base + 20 > bytes.len() {
            break;
        }
        let cputype = u32::from_be_bytes(bytes[base..base + 4].try_into().ok()?);
        let cpusubtype = u32::from_be_bytes(bytes[base + 4..base + 8].try_into().ok()?);
        let offset = u32::from_be_bytes(bytes[base + 8..base + 12].try_into().ok()?) as usize;
        let size = u32::from_be_bytes(bytes[base + 12..base + 16].try_into().ok()?) as usize;
        if offset == 0 || size == 0 || offset.saturating_add(size) > bytes.len() {
            continue;
        }
        candidates.push((cputype, cpusubtype, offset, size));
    }
    if candidates.is_empty() {
        return None;
    }
    let preferred = preferred_macho_cpu();
    let selected = candidates
        .iter()
        .find(|(cputype, _, _, _)| *cputype == preferred)
        .or_else(|| {
            candidates
                .iter()
                .find(|(cputype, _, _, _)| *cputype == 0x0100_000c || *cputype == 0x0c)
        })
        .or_else(|| candidates.first())?;
    let (_, _, offset, size) = *selected;
    Some(bytes[offset..offset + size].to_vec())
}

fn preferred_macho_cpu() -> u32 {
    if cfg!(target_arch = "aarch64") {
        0x0100_000c
    } else if cfg!(target_arch = "x86_64") {
        0x0100_0007
    } else {
        0x0100_000c
    }
}

pub fn identify_object_graph(
    path: &Path,
    max_depth: usize,
    max_children: usize,
) -> Result<ObjectGraph> {
    let mut objects = Vec::new();
    let mut edges = Vec::new();
    let root = identify_path(path, 0, max_depth, max_children, &mut objects, &mut edges)?;
    Ok(ObjectGraph {
        root_id: root,
        objects,
        edges,
    })
}

fn identify_path(
    path: &Path,
    depth: usize,
    max_depth: usize,
    max_children: usize,
    objects: &mut Vec<UniversalObject>,
    edges: &mut Vec<ObjectEdge>,
) -> Result<String> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.is_dir() {
        let id = directory_object_id(path);
        objects.push(UniversalObject {
            id: id.clone(),
            path: Some(path.display().to_string()),
            display_name: display_name(path),
            kind: ObjectKind::Directory,
            format: Some("directory".to_string()),
            size: 0,
            hash_blake3: None,
            media_type: None,
            entropy: None,
            depth,
            flags: Vec::new(),
            metadata: serde_json::json!({
                "readonly": metadata.permissions().readonly(),
            }),
            analyses: analyze_object(&id, ObjectKind::Directory, Some("directory"), &[]),
            evidence_ids: vec![format!("object:{id}:identity")],
        });
        if depth < max_depth {
            let mut child_count = 0usize;
            for entry in fs::read_dir(path)
                .with_context(|| format!("failed to read directory {}", path.display()))?
            {
                if child_count >= max_children {
                    break;
                }
                let entry = entry?;
                let child_id = identify_path(
                    &entry.path(),
                    depth + 1,
                    max_depth,
                    max_children,
                    objects,
                    edges,
                )?;
                edges.push(ObjectEdge {
                    from: id.clone(),
                    to: child_id,
                    kind: ObjectEdgeKind::Contains,
                    metadata: serde_json::json!({ "index": child_count }),
                });
                child_count += 1;
            }
            if child_count >= max_children {
                if let Some(object) = objects.iter_mut().find(|object| object.id == id) {
                    object.flags.push("children_truncated".to_string());
                    object.metadata["max_children"] = serde_json::json!(max_children);
                }
            }
        }
        return Ok(id);
    }

    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let id = format!("obj:{hash}");
    let signature = detect_signature(path, &bytes);
    let format = signature.format.clone();
    let media_type = signature.media_type.clone();
    let entropy = if bytes.is_empty() {
        None
    } else {
        Some(shannon_entropy(&bytes))
    };
    let mut flags = Vec::new();
    if metadata.file_type().is_symlink() {
        flags.push("symlink".to_string());
    }
    if is_probably_text(&bytes) {
        flags.push("text_like".to_string());
    }
    if is_container_candidate(signature.kind, &format) {
        flags.push("container_candidate".to_string());
    }

    let object_display_name = display_name(path);
    let analyses = analyze_object(&id, signature.kind, Some(&format), &bytes);
    objects.push(UniversalObject {
        id: id.clone(),
        path: Some(path.display().to_string()),
        display_name: object_display_name.clone(),
        kind: signature.kind,
        format: Some(format.clone()),
        size: bytes.len() as u64,
        hash_blake3: Some(hash),
        media_type,
        entropy,
        depth,
        flags,
        metadata: serde_json::json!({
            "extension": path.extension().and_then(|value| value.to_str()),
            "readonly": metadata.permissions().readonly(),
            "magic": bytes.iter().take(16).map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(""),
        }),
        analyses,
        evidence_ids: vec![format!("object:{id}:identity")],
    });
    if depth < max_depth {
        analyze_container_by_format(
            &id,
            &object_display_name,
            &format,
            &bytes,
            depth,
            max_depth,
            max_children,
            objects,
            edges,
        );
    }

    Ok(id)
}

#[cfg(feature = "containers")]
fn analyze_zip_container(
    parent_id: &str,
    bytes: &[u8],
    depth: usize,
    max_depth: usize,
    max_children: usize,
    objects: &mut Vec<UniversalObject>,
    edges: &mut Vec<ObjectEdge>,
) {
    let result = expand_zip_container(
        parent_id,
        bytes,
        depth,
        max_depth,
        max_children,
        objects,
        edges,
    );
    let analysis = match result {
        Ok(summary) => summary,
        Err(err) => ObjectAnalysisSummary {
            analyzer: "zip_container".to_string(),
            status: ObjectAnalysisStatus::Failed,
            summary: format!("ZIP expansion failed: {err}"),
            details: serde_json::json!({ "error": err.to_string() }),
            evidence_ids: vec![format!("analysis:{parent_id}:zip_container")],
        },
    };
    if let Some(parent) = objects.iter_mut().find(|object| object.id == parent_id) {
        if analysis.status == ObjectAnalysisStatus::Partial {
            parent.flags.push("children_truncated".to_string());
        }
        parent.analyses.push(analysis);
    }
}

#[cfg(feature = "containers")]
fn expand_zip_container(
    parent_id: &str,
    bytes: &[u8],
    depth: usize,
    max_depth: usize,
    max_children: usize,
    objects: &mut Vec<UniversalObject>,
    edges: &mut Vec<ObjectEdge>,
) -> Result<ObjectAnalysisSummary> {
    let cursor = Cursor::new(bytes);
    let mut archive =
        zip::ZipArchive::new(cursor).context("failed to parse ZIP central directory")?;
    let entry_total = archive.len();
    let mut expanded = 0usize;
    for index in 0..entry_total.min(max_children) {
        let mut file = archive.by_index(index)?;
        let entry_name = file.name().to_string();
        if file.is_dir() {
            let child_id = virtual_directory_object_id(parent_id, &entry_name);
            objects.push(UniversalObject {
                id: child_id.clone(),
                path: Some(format!("{parent_id}!/{entry_name}")),
                display_name: entry_name.clone(),
                kind: ObjectKind::Directory,
                format: Some("zip_directory".to_string()),
                size: 0,
                hash_blake3: None,
                media_type: None,
                entropy: None,
                depth: depth + 1,
                flags: vec!["virtual".to_string()],
                metadata: serde_json::json!({
                    "container": parent_id,
                    "container_format": "zip",
                    "zip_entry": entry_name,
                    "index": index,
                }),
                analyses: analyze_object(
                    &child_id,
                    ObjectKind::Directory,
                    Some("zip_directory"),
                    &[],
                ),
                evidence_ids: vec![format!("object:{child_id}:identity")],
            });
            edges.push(ObjectEdge {
                from: parent_id.to_string(),
                to: child_id,
                kind: ObjectEdgeKind::Contains,
                metadata: serde_json::json!({
                    "container_format": "zip",
                    "entry_name": entry_name,
                    "index": index,
                }),
            });
            expanded += 1;
            continue;
        }

        let mut entry_bytes = Vec::new();
        file.read_to_end(&mut entry_bytes)
            .with_context(|| format!("failed to read ZIP entry {entry_name}"))?;
        let child_id = identify_virtual_file(
            parent_id,
            "zip",
            &entry_name,
            &entry_bytes,
            depth + 1,
            max_depth,
            max_children,
            objects,
            edges,
        );
        edges.push(ObjectEdge {
            from: parent_id.to_string(),
            to: child_id,
            kind: ObjectEdgeKind::Contains,
            metadata: serde_json::json!({
                "container_format": "zip",
                "entry_name": entry_name,
                "index": index,
            }),
        });
        expanded += 1;
    }
    let truncated = entry_total > expanded;
    Ok(ObjectAnalysisSummary {
        analyzer: "zip_container".to_string(),
        status: if truncated {
            ObjectAnalysisStatus::Partial
        } else {
            ObjectAnalysisStatus::Completed
        },
        summary: format!("Expanded {expanded} of {entry_total} ZIP entries into the object graph"),
        details: serde_json::json!({
            "entry_count": entry_total,
            "expanded_count": expanded,
            "max_children": max_children,
            "truncated": truncated,
        }),
        evidence_ids: vec![format!("analysis:{parent_id}:zip_container")],
    })
}

#[cfg(feature = "containers")]
fn analyze_tar_container(
    parent_id: &str,
    container_format: &str,
    bytes: &[u8],
    depth: usize,
    max_depth: usize,
    max_children: usize,
    objects: &mut Vec<UniversalObject>,
    edges: &mut Vec<ObjectEdge>,
) {
    let result = expand_tar_container(
        parent_id,
        container_format,
        bytes,
        depth,
        max_depth,
        max_children,
        objects,
        edges,
    );
    let analysis = match result {
        Ok(summary) => summary,
        Err(err) => ObjectAnalysisSummary {
            analyzer: "tar_container".to_string(),
            status: ObjectAnalysisStatus::Failed,
            summary: format!("TAR expansion failed: {err}"),
            details: serde_json::json!({ "error": err.to_string() }),
            evidence_ids: vec![format!("analysis:{parent_id}:tar_container")],
        },
    };
    if let Some(parent) = objects.iter_mut().find(|object| object.id == parent_id) {
        if analysis.status == ObjectAnalysisStatus::Partial {
            parent.flags.push("children_truncated".to_string());
        }
        parent.analyses.push(analysis);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompressedFormat {
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

impl CompressedFormat {
    fn format(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
        }
    }

    fn analyzer(self) -> &'static str {
        match self {
            Self::Gzip => "gzip_container",
            Self::Bzip2 => "bzip2_container",
            Self::Xz => "xz_container",
            Self::Zstd => "zstd_container",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Gzip => "GZIP",
            Self::Bzip2 => "BZIP2",
            Self::Xz => "XZ",
            Self::Zstd => "ZSTD",
        }
    }
}

#[cfg(feature = "containers")]
fn analyze_compressed_container(
    parent_id: &str,
    parent_display_name: &str,
    compressed_format: CompressedFormat,
    bytes: &[u8],
    depth: usize,
    max_depth: usize,
    max_children: usize,
    objects: &mut Vec<UniversalObject>,
    edges: &mut Vec<ObjectEdge>,
) {
    let result = expand_compressed_container(
        parent_id,
        parent_display_name,
        compressed_format,
        bytes,
        depth,
        max_depth,
        max_children,
        objects,
        edges,
    );
    let analysis = match result {
        Ok(summary) => summary,
        Err(err) => ObjectAnalysisSummary {
            analyzer: compressed_format.analyzer().to_string(),
            status: ObjectAnalysisStatus::Failed,
            summary: format!(
                "{} expansion failed: {err}",
                compressed_format.display_name()
            ),
            details: serde_json::json!({ "error": err.to_string() }),
            evidence_ids: vec![format!(
                "analysis:{parent_id}:{}",
                compressed_format.analyzer()
            )],
        },
    };
    if let Some(parent) = objects.iter_mut().find(|object| object.id == parent_id) {
        parent.analyses.push(analysis);
    }
}

fn analyze_ico_container(
    parent_id: &str,
    bytes: &[u8],
    depth: usize,
    max_depth: usize,
    max_children: usize,
    objects: &mut Vec<UniversalObject>,
    edges: &mut Vec<ObjectEdge>,
) {
    let result = expand_ico_container(
        parent_id,
        bytes,
        depth,
        max_depth,
        max_children,
        objects,
        edges,
    );
    let analysis = match result {
        Ok(summary) => summary,
        Err(err) => ObjectAnalysisSummary {
            analyzer: "ico_container".to_string(),
            status: ObjectAnalysisStatus::Failed,
            summary: format!("ICO expansion failed: {err}"),
            details: serde_json::json!({ "error": err.to_string() }),
            evidence_ids: vec![format!("analysis:{parent_id}:ico_container")],
        },
    };
    if let Some(parent) = objects.iter_mut().find(|object| object.id == parent_id) {
        if analysis.status == ObjectAnalysisStatus::Partial {
            parent.flags.push("children_truncated".to_string());
        }
        parent.analyses.push(analysis);
    }
}

fn expand_ico_container(
    parent_id: &str,
    bytes: &[u8],
    depth: usize,
    max_depth: usize,
    max_children: usize,
    objects: &mut Vec<UniversalObject>,
    edges: &mut Vec<ObjectEdge>,
) -> Result<ObjectAnalysisSummary> {
    let entries = parse_ico_directory(bytes)?;
    let mut expanded = 0usize;
    let mut skipped = 0usize;
    let mut entry_summaries = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let image_end = entry.image_offset.saturating_add(entry.image_size);
        let entry_summary = serde_json::json!({
            "index": index,
            "width": entry.width,
            "height": entry.height,
            "color_count": entry.color_count,
            "planes": entry.planes,
            "bit_count": entry.bit_count,
            "image_size": entry.image_size,
            "image_offset": entry.image_offset,
            "image_format": ico_entry_image_format(bytes, entry),
        });
        entry_summaries.push(entry_summary);
        if expanded >= max_children {
            continue;
        }
        if image_end > bytes.len() || entry.image_size == 0 {
            skipped += 1;
            continue;
        }
        let entry_bytes = &bytes[entry.image_offset..image_end];
        let entry_name = ico_entry_name(index, entry, entry_bytes);
        let child_id = identify_virtual_file(
            parent_id,
            "ico",
            &entry_name,
            entry_bytes,
            depth + 1,
            max_depth,
            max_children,
            objects,
            edges,
        );
        if let Some(child) = objects.iter_mut().find(|object| object.id == child_id) {
            child.metadata["ico_entry"] = serde_json::json!(index);
            child.metadata["ico_image_offset"] = serde_json::json!(entry.image_offset);
            child.metadata["ico_image_size"] = serde_json::json!(entry.image_size);
            child.metadata["ico_width"] = serde_json::json!(entry.width);
            child.metadata["ico_height"] = serde_json::json!(entry.height);
            child.metadata["ico_bit_count"] = serde_json::json!(entry.bit_count);
        }
        edges.push(ObjectEdge {
            from: parent_id.to_string(),
            to: child_id,
            kind: ObjectEdgeKind::Contains,
            metadata: serde_json::json!({
                "container_format": "ico",
                "entry_name": entry_name,
                "index": index,
                "image_offset": entry.image_offset,
                "image_size": entry.image_size,
            }),
        });
        expanded += 1;
    }
    let truncated = entries.len() > expanded + skipped;
    Ok(ObjectAnalysisSummary {
        analyzer: "ico_container".to_string(),
        status: if truncated || skipped > 0 {
            ObjectAnalysisStatus::Partial
        } else {
            ObjectAnalysisStatus::Completed
        },
        summary: format!(
            "Expanded {expanded} of {} ICO image entries into the object graph",
            entries.len()
        ),
        details: serde_json::json!({
            "entry_count": entries.len(),
            "expanded_count": expanded,
            "skipped_count": skipped,
            "max_children": max_children,
            "truncated": truncated,
            "entries": entry_summaries,
        }),
        evidence_ids: vec![format!("analysis:{parent_id}:ico_container")],
    })
}

fn analyze_riff_container(
    parent_id: &str,
    container_format: &str,
    bytes: &[u8],
    depth: usize,
    max_depth: usize,
    max_children: usize,
    objects: &mut Vec<UniversalObject>,
    edges: &mut Vec<ObjectEdge>,
) {
    let result = expand_riff_container(
        parent_id,
        container_format,
        bytes,
        depth,
        max_depth,
        max_children,
        objects,
        edges,
    );
    let analysis = match result {
        Ok(summary) => summary,
        Err(err) => ObjectAnalysisSummary {
            analyzer: "riff_container".to_string(),
            status: ObjectAnalysisStatus::Failed,
            summary: format!("RIFF expansion failed: {err}"),
            details: serde_json::json!({ "error": err.to_string() }),
            evidence_ids: vec![format!("analysis:{parent_id}:riff_container")],
        },
    };
    if let Some(parent) = objects.iter_mut().find(|object| object.id == parent_id) {
        if analysis.status == ObjectAnalysisStatus::Partial {
            parent.flags.push("children_truncated".to_string());
        }
        parent.analyses.push(analysis);
    }
}

fn expand_riff_container(
    parent_id: &str,
    container_format: &str,
    bytes: &[u8],
    depth: usize,
    max_depth: usize,
    max_children: usize,
    objects: &mut Vec<UniversalObject>,
    edges: &mut Vec<ObjectEdge>,
) -> Result<ObjectAnalysisSummary> {
    let riff = parse_riff_container(bytes)?;
    let mut expanded = 0usize;
    let mut skipped = 0usize;
    let mut chunk_summaries = Vec::new();
    for (index, chunk) in riff.chunks.iter().enumerate() {
        let chunk_summary = serde_json::json!({
            "index": index,
            "id": chunk.id,
            "offset": chunk.offset,
            "data_offset": chunk.data_offset,
            "declared_size": chunk.declared_size,
            "available_size": chunk.available_size,
            "padded_size": chunk.padded_size,
            "truncated": chunk.truncated,
            "list_type": chunk.list_type,
            "format_hint": riff_chunk_format_hint(&riff.form_type, chunk),
        });
        chunk_summaries.push(chunk_summary);
        if expanded >= max_children {
            continue;
        }
        if chunk.available_size == 0 || chunk.truncated {
            skipped += 1;
            continue;
        }
        let entry_name = riff_chunk_entry_name(index, &riff.form_type, chunk);
        let entry_bytes = &bytes[chunk.data_offset..chunk.data_offset + chunk.available_size];
        let child_id = identify_virtual_file(
            parent_id,
            "riff",
            &entry_name,
            entry_bytes,
            depth + 1,
            max_depth,
            max_children,
            objects,
            edges,
        );
        if let Some(child) = objects.iter_mut().find(|object| object.id == child_id) {
            child.metadata["riff_container_format"] = serde_json::json!(container_format);
            child.metadata["riff_form_type"] = serde_json::json!(riff.form_type);
            child.metadata["riff_chunk_index"] = serde_json::json!(index);
            child.metadata["riff_chunk_id"] = serde_json::json!(chunk.id);
            child.metadata["riff_chunk_offset"] = serde_json::json!(chunk.offset);
            child.metadata["riff_chunk_data_offset"] = serde_json::json!(chunk.data_offset);
            child.metadata["riff_chunk_size"] = serde_json::json!(chunk.available_size);
            child.metadata["riff_chunk_declared_size"] = serde_json::json!(chunk.declared_size);
            child.metadata["riff_chunk_padded_size"] = serde_json::json!(chunk.padded_size);
            if let Some(list_type) = &chunk.list_type {
                child.metadata["riff_list_type"] = serde_json::json!(list_type);
            }
        }
        edges.push(ObjectEdge {
            from: parent_id.to_string(),
            to: child_id,
            kind: ObjectEdgeKind::Contains,
            metadata: serde_json::json!({
                "container_format": "riff",
                "riff_container_format": container_format,
                "form_type": riff.form_type,
                "chunk_id": chunk.id,
                "entry_name": entry_name,
                "index": index,
                "offset": chunk.offset,
                "data_offset": chunk.data_offset,
                "declared_size": chunk.declared_size,
                "available_size": chunk.available_size,
            }),
        });
        expanded += 1;
    }
    let truncated = riff.truncated || riff.chunks.len() > expanded + skipped;
    Ok(ObjectAnalysisSummary {
        analyzer: "riff_container".to_string(),
        status: if truncated || skipped > 0 {
            ObjectAnalysisStatus::Partial
        } else {
            ObjectAnalysisStatus::Completed
        },
        summary: format!(
            "Expanded {expanded} of {} RIFF chunks from {} form into the object graph",
            riff.chunks.len(),
            riff.form_type
        ),
        details: serde_json::json!({
            "form_type": riff.form_type,
            "declared_size": riff.declared_size,
            "declared_end": riff.declared_end,
            "actual_size": bytes.len(),
            "chunk_count": riff.chunks.len(),
            "expanded_count": expanded,
            "skipped_count": skipped,
            "max_children": max_children,
            "truncated": truncated,
            "chunks": chunk_summaries,
            "warnings": riff.warnings,
        }),
        evidence_ids: vec![format!("analysis:{parent_id}:riff_container")],
    })
}

fn analyze_ole_container(
    parent_id: &str,
    bytes: &[u8],
    depth: usize,
    max_depth: usize,
    max_children: usize,
    objects: &mut Vec<UniversalObject>,
    edges: &mut Vec<ObjectEdge>,
) {
    let result = expand_ole_container(
        parent_id,
        bytes,
        depth,
        max_depth,
        max_children,
        objects,
        edges,
    );
    let analysis = match result {
        Ok(summary) => summary,
        Err(err) => ObjectAnalysisSummary {
            analyzer: "ole_container".to_string(),
            status: ObjectAnalysisStatus::Failed,
            summary: format!("OLE/CFB expansion failed: {err}"),
            details: serde_json::json!({ "error": err.to_string() }),
            evidence_ids: vec![format!("analysis:{parent_id}:ole_container")],
        },
    };
    if let Some(parent) = objects.iter_mut().find(|object| object.id == parent_id) {
        if analysis.status == ObjectAnalysisStatus::Partial {
            parent.flags.push("children_truncated".to_string());
        }
        parent.analyses.push(analysis);
    }
}

fn expand_ole_container(
    parent_id: &str,
    bytes: &[u8],
    depth: usize,
    max_depth: usize,
    max_children: usize,
    objects: &mut Vec<UniversalObject>,
    edges: &mut Vec<ObjectEdge>,
) -> Result<ObjectAnalysisSummary> {
    let compound = CompoundFile::parse(bytes).map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let streams = compound.streams();
    let storages = compound.storages();
    let mut expanded = 0usize;
    let mut skipped = 0usize;

    for storage in storages.iter().take(max_children.saturating_sub(expanded)) {
        let child_id = virtual_directory_object_id(parent_id, &storage.path);
        objects.push(UniversalObject {
            id: child_id.clone(),
            path: Some(format!("{parent_id}!/{}", storage.path)),
            display_name: storage.path.clone(),
            kind: ObjectKind::Directory,
            format: Some("ole_storage".to_string()),
            size: 0,
            hash_blake3: None,
            media_type: None,
            entropy: None,
            depth: depth + 1,
            flags: vec!["virtual".to_string()],
            metadata: serde_json::json!({
                "container": parent_id,
                "container_format": "ole",
                "ole_entry_type": "storage",
                "ole_storage": storage.path,
                "ole_entry_index": storage.index,
                "child_count": storage.child_count,
            }),
            analyses: analyze_object(&child_id, ObjectKind::Directory, Some("ole_storage"), &[]),
            evidence_ids: vec![format!("object:{child_id}:identity")],
        });
        edges.push(ObjectEdge {
            from: parent_id.to_string(),
            to: child_id,
            kind: ObjectEdgeKind::Contains,
            metadata: serde_json::json!({
                "container_format": "ole",
                "entry_type": "storage",
                "entry_name": storage.path,
                "index": storage.index,
            }),
        });
        expanded += 1;
    }

    for stream in streams.iter() {
        if expanded >= max_children {
            continue;
        }
        let stream_bytes = match compound.read_stream_by_index(stream.index) {
            Ok(bytes) => bytes,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let child_id = identify_virtual_file(
            parent_id,
            "ole",
            &stream.path,
            &stream_bytes,
            depth + 1,
            max_depth,
            max_children,
            objects,
            edges,
        );
        if let Some(child) = objects.iter_mut().find(|object| object.id == child_id) {
            child.metadata["ole_entry_type"] = serde_json::json!("stream");
            child.metadata["ole_entry_index"] = serde_json::json!(stream.index);
            child.metadata["ole_stream_path"] = serde_json::json!(stream.path);
            child.metadata["ole_stream_name"] = serde_json::json!(stream.name);
            child.metadata["ole_storage_path"] = serde_json::json!(stream.storage_path);
            child.metadata["ole_start_sector"] = serde_json::json!(stream.start_sector);
            child.metadata["ole_stream_size"] = serde_json::json!(stream.size);
        }
        edges.push(ObjectEdge {
            from: parent_id.to_string(),
            to: child_id,
            kind: ObjectEdgeKind::Contains,
            metadata: serde_json::json!({
                "container_format": "ole",
                "entry_type": "stream",
                "entry_name": stream.path,
                "index": stream.index,
                "size": stream.size,
            }),
        });
        expanded += 1;
    }

    let total_entries = streams.len() + storages.len();
    let truncated = total_entries > expanded + skipped;
    Ok(ObjectAnalysisSummary {
        analyzer: "ole_container".to_string(),
        status: if truncated || skipped > 0 || !compound.warnings().is_empty() {
            ObjectAnalysisStatus::Partial
        } else {
            ObjectAnalysisStatus::Completed
        },
        summary: format!(
            "Expanded {expanded} of {total_entries} OLE/CFB entries into the object graph"
        ),
        details: serde_json::json!({
            "format": "ole",
            "entry_count": compound.directory().len(),
            "storage_count": storages.len(),
            "stream_count": streams.len(),
            "expanded_count": expanded,
            "skipped_count": skipped,
            "max_children": max_children,
            "truncated": truncated,
            "header": compound.header(),
            "warnings": compound.warnings(),
        }),
        evidence_ids: vec![format!("analysis:{parent_id}:ole_container")],
    })
}

#[cfg(feature = "containers")]
fn expand_compressed_container(
    parent_id: &str,
    parent_display_name: &str,
    compressed_format: CompressedFormat,
    bytes: &[u8],
    depth: usize,
    max_depth: usize,
    max_children: usize,
    objects: &mut Vec<UniversalObject>,
    edges: &mut Vec<ObjectEdge>,
) -> Result<ObjectAnalysisSummary> {
    if max_children == 0 {
        return Ok(ObjectAnalysisSummary {
            analyzer: compressed_format.analyzer().to_string(),
            status: ObjectAnalysisStatus::Partial,
            summary: format!(
                "Skipped {} payload expansion because max_children is 0",
                compressed_format.display_name()
            ),
            details: serde_json::json!({
                "expanded_count": 0,
                "max_children": max_children,
                "truncated": true,
            }),
            evidence_ids: vec![format!(
                "analysis:{parent_id}:{}",
                compressed_format.analyzer()
            )],
        });
    }
    let entry_bytes = decompress_by_format(bytes, compressed_format)?;
    let entry_name = compressed_payload_name(parent_display_name, compressed_format);
    let child_id = identify_virtual_file(
        parent_id,
        compressed_format.format(),
        &entry_name,
        &entry_bytes,
        depth + 1,
        max_depth,
        max_children,
        objects,
        edges,
    );
    edges.push(ObjectEdge {
        from: parent_id.to_string(),
        to: child_id,
        kind: ObjectEdgeKind::Contains,
        metadata: serde_json::json!({
            "container_format": compressed_format.format(),
            "entry_name": entry_name,
            "index": 0,
        }),
    });
    Ok(ObjectAnalysisSummary {
        analyzer: compressed_format.analyzer().to_string(),
        status: ObjectAnalysisStatus::Completed,
        summary: format!(
            "Expanded {} payload into the object graph",
            compressed_format.display_name()
        ),
        details: serde_json::json!({
            "expanded_count": 1,
            "max_children": max_children,
            "truncated": false,
        }),
        evidence_ids: vec![format!(
            "analysis:{parent_id}:{}",
            compressed_format.analyzer()
        )],
    })
}

#[cfg(feature = "containers")]
fn expand_tar_container(
    parent_id: &str,
    container_format: &str,
    bytes: &[u8],
    depth: usize,
    max_depth: usize,
    max_children: usize,
    objects: &mut Vec<UniversalObject>,
    edges: &mut Vec<ObjectEdge>,
) -> Result<ObjectAnalysisSummary> {
    let archive_bytes;
    let tar_bytes = if let Some(compressed_format) = compressed_tar_format(container_format) {
        archive_bytes = decompress_by_format(bytes, compressed_format)?;
        archive_bytes.as_slice()
    } else {
        bytes
    };
    let cursor = Cursor::new(tar_bytes);
    let mut archive = tar::Archive::new(cursor);
    let mut expanded = 0usize;
    let mut skipped = 0usize;
    let mut truncated = false;
    for (index, entry) in archive.entries()?.enumerate() {
        if expanded >= max_children {
            truncated = true;
            break;
        }
        let mut entry = entry?;
        let entry_path = entry.path()?.to_string_lossy().into_owned();
        if entry_path.is_empty() {
            skipped += 1;
            continue;
        }
        if entry.header().entry_type().is_dir() {
            let child_id = virtual_directory_object_id(parent_id, &entry_path);
            objects.push(UniversalObject {
                id: child_id.clone(),
                path: Some(format!("{parent_id}!/{entry_path}")),
                display_name: entry_path.clone(),
                kind: ObjectKind::Directory,
                format: Some("tar_directory".to_string()),
                size: 0,
                hash_blake3: None,
                media_type: None,
                entropy: None,
                depth: depth + 1,
                flags: vec!["virtual".to_string()],
                metadata: serde_json::json!({
                    "container": parent_id,
                    "container_format": container_format,
                    "tar_entry": entry_path,
                    "index": index,
                }),
                analyses: analyze_object(
                    &child_id,
                    ObjectKind::Directory,
                    Some("tar_directory"),
                    &[],
                ),
                evidence_ids: vec![format!("object:{child_id}:identity")],
            });
            edges.push(ObjectEdge {
                from: parent_id.to_string(),
                to: child_id,
                kind: ObjectEdgeKind::Contains,
                metadata: serde_json::json!({
                    "container_format": container_format,
                    "entry_name": entry_path,
                    "index": index,
                }),
            });
            expanded += 1;
            continue;
        }
        if !entry.header().entry_type().is_file() {
            skipped += 1;
            continue;
        }
        let mut entry_bytes = Vec::new();
        entry
            .read_to_end(&mut entry_bytes)
            .with_context(|| format!("failed to read TAR entry {entry_path}"))?;
        let child_id = identify_virtual_file(
            parent_id,
            container_format,
            &entry_path,
            &entry_bytes,
            depth + 1,
            max_depth,
            max_children,
            objects,
            edges,
        );
        edges.push(ObjectEdge {
            from: parent_id.to_string(),
            to: child_id,
            kind: ObjectEdgeKind::Contains,
            metadata: serde_json::json!({
                "container_format": container_format,
                "entry_name": entry_path,
                "index": index,
            }),
        });
        expanded += 1;
    }
    Ok(ObjectAnalysisSummary {
        analyzer: "tar_container".to_string(),
        status: if truncated {
            ObjectAnalysisStatus::Partial
        } else {
            ObjectAnalysisStatus::Completed
        },
        summary: format!("Expanded {expanded} TAR entries into the object graph"),
        details: serde_json::json!({
            "expanded_count": expanded,
            "skipped_count": skipped,
            "max_children": max_children,
            "truncated": truncated,
        }),
        evidence_ids: vec![format!("analysis:{parent_id}:tar_container")],
    })
}

fn identify_virtual_file(
    container_id: &str,
    container_format: &str,
    entry_name: &str,
    bytes: &[u8],
    depth: usize,
    max_depth: usize,
    max_children: usize,
    objects: &mut Vec<UniversalObject>,
    edges: &mut Vec<ObjectEdge>,
) -> String {
    let hash = blake3::hash(bytes).to_hex().to_string();
    let id = format!("obj:{hash}");
    let signature = detect_signature(Path::new(entry_name), bytes);
    let format = signature.format.clone();
    let media_type = signature.media_type.clone();
    let mut flags = vec!["virtual".to_string()];
    if is_probably_text(bytes) {
        flags.push("text_like".to_string());
    }
    if is_container_candidate(signature.kind, &format) {
        flags.push("container_candidate".to_string());
    }
    let analyses = analyze_object(&id, signature.kind, Some(&format), bytes);
    objects.push(UniversalObject {
        id: id.clone(),
        path: Some(format!("{container_id}!/{entry_name}")),
        display_name: entry_name.to_string(),
        kind: signature.kind,
        format: Some(format.clone()),
        size: bytes.len() as u64,
        hash_blake3: Some(hash),
        media_type,
        entropy: (!bytes.is_empty()).then(|| shannon_entropy(bytes)),
        depth,
        flags,
        metadata: serde_json::json!({
            "container": container_id,
            "container_format": container_format,
            "zip_entry": if container_format == "zip" { Some(entry_name) } else { None },
            "tar_entry": if is_tar_like_format(container_format) { Some(entry_name) } else { None },
            "gzip_entry": if container_format == "gzip" { Some(entry_name) } else { None },
            "bzip2_entry": if container_format == "bzip2" { Some(entry_name) } else { None },
            "xz_entry": if container_format == "xz" { Some(entry_name) } else { None },
            "zstd_entry": if container_format == "zstd" { Some(entry_name) } else { None },
            "riff_chunk": if container_format == "riff" { Some(entry_name) } else { None },
            "ole_stream": if container_format == "ole" { Some(entry_name) } else { None },
            "magic": bytes.iter().take(16).map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(""),
        }),
        analyses,
        evidence_ids: vec![format!("object:{id}:identity")],
    });
    if depth < max_depth {
        analyze_container_by_format(
            &id,
            entry_name,
            &format,
            bytes,
            depth,
            max_depth,
            max_children,
            objects,
            edges,
        );
    }
    id
}

fn analyze_container_by_format(
    object_id: &str,
    object_display_name: &str,
    format: &str,
    bytes: &[u8],
    depth: usize,
    max_depth: usize,
    max_children: usize,
    objects: &mut Vec<UniversalObject>,
    edges: &mut Vec<ObjectEdge>,
) {
    let _ = object_display_name;
    #[cfg(feature = "containers")]
    if is_zip_like_format(format) {
        analyze_zip_container(
            object_id,
            bytes,
            depth,
            max_depth,
            max_children,
            objects,
            edges,
        );
        return;
    } else if is_tar_like_format(format) {
        analyze_tar_container(
            object_id,
            format,
            bytes,
            depth,
            max_depth,
            max_children,
            objects,
            edges,
        );
        return;
    } else if let Some(compressed_format) = compressed_format(format) {
        analyze_compressed_container(
            object_id,
            object_display_name,
            compressed_format,
            bytes,
            depth,
            max_depth,
            max_children,
            objects,
            edges,
        );
        return;
    }
    if format == "ico" {
        analyze_ico_container(
            object_id,
            bytes,
            depth,
            max_depth,
            max_children,
            objects,
            edges,
        );
    } else if is_riff_like_format(format) {
        analyze_riff_container(
            object_id,
            format,
            bytes,
            depth,
            max_depth,
            max_children,
            objects,
            edges,
        );
    } else if is_ole_like_format(format) {
        analyze_ole_container(
            object_id,
            bytes,
            depth,
            max_depth,
            max_children,
            objects,
            edges,
        );
    }
}

fn is_container_candidate(kind: ObjectKind, format: &str) -> bool {
    kind == ObjectKind::Archive
        || kind == ObjectKind::Package
        || format == "ico"
        || is_riff_like_format(format)
        || is_ole_like_format(format)
}

fn is_zip_like_format(format: &str) -> bool {
    matches!(
        format,
        "zip" | "apk" | "ipa" | "jar" | "docx" | "docm" | "xlsx" | "xlsm" | "pptx" | "pptm"
    )
}

fn is_tar_like_format(format: &str) -> bool {
    format == "tar" || compressed_tar_format(format).is_some()
}

fn is_riff_like_format(format: &str) -> bool {
    matches!(format, "riff" | "webp" | "wav" | "avi")
}

fn is_ole_like_format(format: &str) -> bool {
    matches!(format, "ole" | "doc" | "xls" | "ppt" | "msi" | "msg")
}

fn compressed_format(format: &str) -> Option<CompressedFormat> {
    match format {
        "gzip" => Some(CompressedFormat::Gzip),
        "bzip2" => Some(CompressedFormat::Bzip2),
        "xz" => Some(CompressedFormat::Xz),
        "zstd" => Some(CompressedFormat::Zstd),
        _ => None,
    }
}

fn compressed_tar_format(format: &str) -> Option<CompressedFormat> {
    match format {
        "tar.gz" => Some(CompressedFormat::Gzip),
        "tar.bz2" => Some(CompressedFormat::Bzip2),
        "tar.xz" => Some(CompressedFormat::Xz),
        "tar.zst" => Some(CompressedFormat::Zstd),
        _ => None,
    }
}

#[cfg(feature = "containers")]
fn decompress_by_format(bytes: &[u8], compressed_format: CompressedFormat) -> Result<Vec<u8>> {
    let mut decompressed = Vec::new();
    match compressed_format {
        CompressedFormat::Gzip => {
            let mut decoder = GzDecoder::new(bytes);
            decoder
                .read_to_end(&mut decompressed)
                .context("failed to decompress gzip stream")?;
        }
        CompressedFormat::Bzip2 => {
            let mut decoder = BzDecoder::new(bytes);
            decoder
                .read_to_end(&mut decompressed)
                .context("failed to decompress bzip2 stream")?;
        }
        CompressedFormat::Xz => {
            let mut decoder = XzDecoder::new(bytes);
            decoder
                .read_to_end(&mut decompressed)
                .context("failed to decompress xz stream")?;
        }
        CompressedFormat::Zstd => {
            let mut decoder =
                ZstdDecoder::new(bytes).context("failed to initialize zstd decoder")?;
            decoder
                .read_to_end(&mut decompressed)
                .context("failed to decompress zstd stream")?;
        }
    }
    Ok(decompressed)
}

fn compressed_payload_name(container_name: &str, compressed_format: CompressedFormat) -> String {
    let suffixes = match compressed_format {
        CompressedFormat::Gzip => &[".gz"][..],
        CompressedFormat::Bzip2 => &[".bz2", ".bz"][..],
        CompressedFormat::Xz => &[".xz"][..],
        CompressedFormat::Zstd => &[".zst", ".zstd"][..],
    };
    strip_compression_suffix(container_name, suffixes).unwrap_or_else(|| "payload".to_string())
}

fn strip_compression_suffix(container_name: &str, suffixes: &[&str]) -> Option<String> {
    let name = container_name
        .rsplit_once("!/")
        .map(|(_, name)| name)
        .or_else(|| container_name.rsplit_once('/').map(|(_, name)| name))
        .unwrap_or(container_name);
    for suffix in suffixes {
        if name.len() > suffix.len()
            && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        {
            let payload_name = &name[..name.len() - suffix.len()];
            if !payload_name.is_empty() {
                return Some(payload_name.to_string());
            }
        }
    }
    None
}

fn analyze_object(
    object_id: &str,
    kind: ObjectKind,
    format: Option<&str>,
    bytes: &[u8],
) -> Vec<ObjectAnalysisSummary> {
    let mut analyses = Vec::new();
    if matches!(kind, ObjectKind::Text) {
        analyses.push(analyze_text_object(object_id, format, bytes));
    }
    if matches!(format, Some("json" | "safetensors_index")) {
        analyses.push(analyze_json_object(object_id, bytes));
    }
    if format == Some("dex") {
        analyses.push(analyze_dex_header(object_id, bytes));
    }
    if format == Some("jvm_class") {
        analyses.push(analyze_jvm_class_header(object_id, bytes));
    }
    if format == Some("lnk") {
        analyses.push(analyze_lnk_header(object_id, bytes));
    }
    if format == Some("safetensors") {
        analyses.push(analyze_safetensors_header(object_id, bytes));
    }
    if format == Some("gguf") {
        analyses.push(analyze_gguf_header(object_id, bytes));
    }
    if format == Some("pytorch") {
        analyses.push(analyze_pytorch_header(object_id, bytes));
    }
    if format == Some("sqlite") {
        analyses.push(analyze_sqlite_header(object_id, bytes));
    }
    if format == Some("wasm") {
        analyses.push(analyze_wasm_header(object_id, bytes));
    }
    if format == Some("pdf") {
        analyses.push(analyze_pdf_header(object_id, bytes));
    }
    if format.is_some_and(is_ole_like_format) {
        analyses.push(analyze_ole_header(object_id, bytes));
    }
    if format == Some("png") {
        analyses.push(analyze_png_header(object_id, bytes));
    }
    if format == Some("jpeg") {
        analyses.push(analyze_jpeg_header(object_id, bytes));
    }
    if format == Some("gif") {
        analyses.push(analyze_gif_header(object_id, bytes));
    }
    if format == Some("ico") {
        analyses.push(analyze_ico_header(object_id, bytes));
    }
    if format == Some("bmp") || format == Some("dib") {
        analyses.push(analyze_bmp_header(object_id, format, bytes));
    }
    if format.is_some_and(is_riff_like_format) {
        analyses.push(analyze_riff_header(object_id, format, bytes));
    }
    if format == Some("pcap") || format == Some("pcapng") {
        analyses.push(analyze_pcap_header(object_id, format, bytes));
    }
    if matches!(
        format,
        Some(
            "cab" | "flac" | "ogg" | "mp3" | "mp4" | "m4a" | "m4v" | "mov" | "heif" | "avif"
                | "tiff" | "woff" | "woff2" | "ttf" | "otf" | "ar" | "qcow2" | "iso" | "dmg" | "pem"
        )
    ) {
        analyses.push(analyze_generic_format_header(object_id, format, bytes));
    }
    if matches!(kind, ObjectKind::Binary) {
        analyses.push(analyze_binary_header(object_id, format, bytes));
    }
    if matches!(kind, ObjectKind::File | ObjectKind::Unknown) && format == Some("unknown") {
        analyses.push(analyze_unknown_blob_profile(object_id, bytes));
    }
    analyses
}


fn analyze_generic_format_header(
    object_id: &str,
    format: Option<&str>,
    bytes: &[u8],
) -> ObjectAnalysisSummary {
    let format = format.unwrap_or("unknown");
    let magic = bytes
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("");
    let mut details = serde_json::json!({
        "format": format,
        "size": bytes.len(),
        "magic": magic,
    });
    match format {
        "cab" => {
            details["magic_ok"] = serde_json::json!(bytes.starts_with(b"MSCF"));
            if let Some(size) = read_le_u32(bytes, 8) {
                details["cabinet_size"] = serde_json::json!(size);
            }
            if let Some(files) = read_le_u16(bytes, 28) {
                details["file_count"] = serde_json::json!(files);
            }
            if let Some(folders) = read_le_u16(bytes, 26) {
                details["folder_count"] = serde_json::json!(folders);
            }
        }
        "flac" => {
            details["magic_ok"] = serde_json::json!(bytes.starts_with(b"fLaC"));
        }
        "ogg" => {
            details["magic_ok"] = serde_json::json!(bytes.starts_with(b"OggS"));
            if bytes.len() > 5 {
                details["version"] = serde_json::json!(bytes[4]);
            }
        }
        "mp3" => {
            details["id3"] = serde_json::json!(bytes.starts_with(b"ID3"));
            details["frame_sync"] = serde_json::json!(is_mp3_like(bytes));
        }
        "mp4" | "m4a" | "m4v" | "mov" | "heif" | "avif" => {
            details["ftyp"] = serde_json::json!(is_mp4_family_like(bytes));
            details["major_brand"] = serde_json::json!(mp4_major_brand(bytes));
            if bytes.len() >= 4 {
                if let Ok(size) = <[u8; 4]>::try_from(&bytes[0..4]) {
                    details["box_size"] = serde_json::json!(u32::from_be_bytes(size));
                }
            }
        }
        "tiff" => {
            details["magic_ok"] = serde_json::json!(is_tiff_like(bytes));
            details["endian"] = serde_json::json!(if bytes.starts_with(b"II") {
                "le"
            } else if bytes.starts_with(b"MM") {
                "be"
            } else {
                "unknown"
            });
        }
        "woff" | "woff2" | "ttf" | "otf" => {
            details["font_family"] = serde_json::json!(format);
            details["magic_ok"] = serde_json::json!(match format {
                "woff" => bytes.starts_with(b"wOFF"),
                "woff2" => bytes.starts_with(b"wOF2"),
                "otf" => bytes.starts_with(b"OTTO"),
                "ttf" => is_truetype_like(bytes),
                _ => false,
            });
        }
        "ar" => {
            details["magic_ok"] = serde_json::json!(bytes.starts_with(b"!<arch>\n"));
        }
        "qcow2" => {
            details["magic_ok"] = serde_json::json!(is_qcow2_like(bytes));
            if let Some(version) = read_be_u32(bytes, 4) {
                details["version"] = serde_json::json!(version);
            }
        }
        "iso" => {
            details["magic_ok"] = serde_json::json!(is_iso9660_like(bytes));
        }
        "dmg" => {
            details["magic_ok"] = serde_json::json!(is_dmg_like(bytes));
        }
        "pem" => {
            details["pem_like"] = serde_json::json!(looks_like_pem(bytes));
            let text = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]);
            let labels = text
                .lines()
                .filter_map(|line| {
                    line.strip_prefix("-----BEGIN ")
                        .and_then(|rest| rest.strip_suffix("-----"))
                        .map(str::trim)
                        .map(str::to_string)
                })
                .take(8)
                .collect::<Vec<_>>();
            details["begin_labels"] = serde_json::json!(labels);
        }
        "html" | "xml" | "json" => {
            let preview = String::from_utf8_lossy(&bytes[..bytes.len().min(240)]).to_string();
            details["preview"] = serde_json::json!(preview);
            details["line_count"] = serde_json::json!(String::from_utf8_lossy(bytes).lines().count());
        }
        _ => {}
    }
    ObjectAnalysisSummary {
        analyzer: format!("{format}_header"),
        status: ObjectAnalysisStatus::Completed,
        summary: format!("Generic format header analysis for {format}"),
        details,
        evidence_ids: vec![format!("analysis:{object_id}:{format}_header")],
    }
}

fn analyze_unknown_blob_profile(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    let mut histogram = [0usize; 256];
    for byte in bytes {
        histogram[*byte as usize] += 1;
    }
    let entropy = shannon_entropy(bytes);
    let ascii_printable = bytes
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .count();
    let unique = histogram.iter().filter(|c| **c > 0).count();
    let strings = extract_ascii_strings(0, &bytes[..bytes.len().min(64 * 1024)])
        .into_iter()
        .take(24)
        .map(|s| s.value)
        .collect::<Vec<_>>();
    let content_class = if bytes.is_empty() {
        "empty"
    } else if ascii_printable * 100 / bytes.len().max(1) >= 90 {
        "text_like"
    } else if entropy >= 7.5 {
        "compressed_or_encrypted_like"
    } else if unique <= 24 {
        "low_alphabet"
    } else {
        "opaque_binary"
    };
    ObjectAnalysisSummary {
        analyzer: "unknown_blob_profile".to_string(),
        status: ObjectAnalysisStatus::Completed,
        summary: format!(
            "Unknown blob profile: class {content_class}, entropy {entropy:.3}, {} printable strings sampled",
            strings.len()
        ),
        details: serde_json::json!({
            "size": bytes.len(),
            "entropy": entropy,
            "unique_bytes": unique,
            "ascii_printable_count": ascii_printable,
            "ascii_printable_ratio": if bytes.is_empty() { 0.0 } else { ascii_printable as f64 / bytes.len() as f64 },
            "content_class": content_class,
            "magic": bytes.iter().take(16).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(""),
            "sample_strings": strings,
        }),
        evidence_ids: vec![format!("analysis:{object_id}:unknown_blob_profile")],
    }
}

fn analyze_text_object(
    object_id: &str,
    format: Option<&str>,
    bytes: &[u8],
) -> ObjectAnalysisSummary {
    let text = String::from_utf8_lossy(bytes);
    let line_count = text.lines().count();
    let non_empty_line_count = text.lines().filter(|line| !line.trim().is_empty()).count();
    let preview = text.chars().take(160).collect::<String>();
    ObjectAnalysisSummary {
        analyzer: "text_summary".to_string(),
        status: ObjectAnalysisStatus::Completed,
        summary: format!(
            "Text object contains {line_count} lines ({non_empty_line_count} non-empty)"
        ),
        details: serde_json::json!({
            "format": format,
            "line_count": line_count,
            "non_empty_line_count": non_empty_line_count,
            "char_count": text.chars().count(),
            "preview": preview,
        }),
        evidence_ids: vec![format!("analysis:{object_id}:text_summary")],
    }
}

fn analyze_json_object(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(value) => {
            let (shape, entry_count) = match &value {
                serde_json::Value::Object(map) => ("object", map.len()),
                serde_json::Value::Array(items) => ("array", items.len()),
                serde_json::Value::String(_) => ("string", 1),
                serde_json::Value::Number(_) => ("number", 1),
                serde_json::Value::Bool(_) => ("bool", 1),
                serde_json::Value::Null => ("null", 0),
            };
            let keys = value
                .as_object()
                .map(|map| map.keys().take(32).cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            ObjectAnalysisSummary {
                analyzer: "json_structure".to_string(),
                status: ObjectAnalysisStatus::Completed,
                summary: format!("JSON {shape} with {entry_count} top-level entries"),
                details: serde_json::json!({
                    "shape": shape,
                    "entry_count": entry_count,
                    "keys": keys,
                }),
                evidence_ids: vec![format!("analysis:{object_id}:json_structure")],
            }
        }
        Err(err) => ObjectAnalysisSummary {
            analyzer: "json_structure".to_string(),
            status: ObjectAnalysisStatus::Failed,
            summary: format!("JSON parse failed: {err}"),
            details: serde_json::json!({ "error": err.to_string() }),
            evidence_ids: vec![format!("analysis:{object_id}:json_structure")],
        },
    }
}

fn analyze_dex_header(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    let version = bytes
        .get(4..7)
        .and_then(|slice| std::str::from_utf8(slice).ok())
        .unwrap_or("unknown");
    ObjectAnalysisSummary {
        analyzer: "dex_header".to_string(),
        status: if bytes.starts_with(b"dex\n") {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Failed
        },
        summary: format!("DEX header version {version}"),
        details: serde_json::json!({
            "version": version,
            "declared_magic": bytes.iter().take(8).map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(""),
        }),
        evidence_ids: vec![format!("analysis:{object_id}:dex_header")],
    }
}

fn analyze_jvm_class_header(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    let minor = read_be_u16(bytes, 4);
    let major = read_be_u16(bytes, 6);
    ObjectAnalysisSummary {
        analyzer: "jvm_class_header".to_string(),
        status: if bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) && major.is_some() {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Failed
        },
        summary: match (major, minor) {
            (Some(major), Some(minor)) => {
                format!("JVM class file version {major}.{minor}")
            }
            _ => "JVM class header is truncated".to_string(),
        },
        details: serde_json::json!({
            "major_version": major,
            "minor_version": minor,
        }),
        evidence_ids: vec![format!("analysis:{object_id}:jvm_class_header")],
    }
}

fn analyze_lnk_header(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    let header_size = read_le_u32(bytes, 0);
    let link_flags = read_le_u32(bytes, 20);
    let file_attributes = read_le_u32(bytes, 24);
    let class_id = bytes.get(4..20).map(|slice| {
        slice
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    });
    let valid = is_lnk_like(bytes);
    ObjectAnalysisSummary {
        analyzer: "lnk_header".to_string(),
        status: if valid {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Failed
        },
        summary: if valid {
            format!(
                "Windows Shell Link header flags {:#x}",
                link_flags.unwrap_or_default()
            )
        } else {
            "Windows Shell Link header is malformed or truncated".to_string()
        },
        details: serde_json::json!({
            "magic": valid,
            "header_size": header_size,
            "class_id": class_id,
            "link_flags": link_flags,
            "file_attributes": file_attributes,
        }),
        evidence_ids: vec![format!("analysis:{object_id}:lnk_header")],
    }
}

fn analyze_safetensors_header(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    let summary = parse_safetensors_header(bytes);
    ObjectAnalysisSummary {
        analyzer: "safetensors_header".to_string(),
        status: if summary.is_some() {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Failed
        },
        summary: match summary.as_ref() {
            Some((header_len, tensor_count, metadata_present)) => format!(
                "SafeTensors model with {tensor_count} tensor(s), header {header_len} bytes, metadata: {metadata_present}"
            ),
            None => "SafeTensors header is malformed or truncated".to_string(),
        },
        details: serde_json::json!({
            "magic": summary.is_some(),
            "header_length": summary.map(|(header_len, _, _)| header_len),
            "tensor_count": summary.map(|(_, tensor_count, _)| tensor_count),
            "metadata_present": summary.map(|(_, _, metadata_present)| metadata_present),
        }),
        evidence_ids: vec![format!("analysis:{object_id}:safetensors_header")],
    }
}

fn analyze_gguf_header(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    let summary = parse_gguf_header(bytes);
    ObjectAnalysisSummary {
        analyzer: "gguf_header".to_string(),
        status: if summary.is_some() {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Failed
        },
        summary: match summary.as_ref() {
            Some((version, tensor_count, metadata_kv_count)) => format!(
                "GGUF v{version} model with {tensor_count} tensor(s), {metadata_kv_count} metadata item(s)"
            ),
            None => "GGUF header is malformed or truncated".to_string(),
        },
        details: serde_json::json!({
            "magic": summary.is_some(),
            "version": summary.map(|(version, _, _)| version),
            "tensor_count": summary.map(|(_, tensor_count, _)| tensor_count),
            "metadata_kv_count": summary.map(|(_, _, metadata_kv_count)| metadata_kv_count),
        }),
        evidence_ids: vec![format!("analysis:{object_id}:gguf_header")],
    }
}

fn analyze_pytorch_header(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    let summary = parse_pytorch_header(bytes);
    ObjectAnalysisSummary {
        analyzer: "pytorch_header".to_string(),
        status: if summary.is_some() {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Failed
        },
        summary: match summary.as_ref() {
            Some((container, entry_count, pickle_present)) => format!(
                "PyTorch {container} model with {entry_count} container entrie(s), pickle: {pickle_present}"
            ),
            None => "PyTorch serialization header is malformed or unrecognized".to_string(),
        },
        details: serde_json::json!({
            "magic": summary.is_some(),
            "container": summary.map(|(container, _, _)| container),
            "entry_count": summary.map(|(_, entry_count, _)| entry_count),
            "pickle_present": summary.map(|(_, _, pickle_present)| pickle_present),
        }),
        evidence_ids: vec![format!("analysis:{object_id}:pytorch_header")],
    }
}

fn analyze_sqlite_header(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    let page_size_raw = read_be_u16(bytes, 16);
    let page_size = match page_size_raw {
        Some(1) => Some(65_536u32),
        Some(value) => Some(value as u32),
        None => None,
    };
    let sqlite_version = read_be_u32(bytes, 96);
    ObjectAnalysisSummary {
        analyzer: "sqlite_header".to_string(),
        status: if bytes.starts_with(b"SQLite format 3\0") {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Failed
        },
        summary: match (page_size, sqlite_version) {
            (Some(page_size), Some(sqlite_version)) => {
                format!(
                    "SQLite database header with {page_size}-byte pages, SQLite version number {sqlite_version}"
                )
            }
            (Some(page_size), None) => {
                format!("SQLite database header with {page_size}-byte pages")
            }
            _ => "SQLite database header is truncated".to_string(),
        },
        details: serde_json::json!({
            "page_size": page_size,
            "write_version": bytes.get(18).copied(),
            "read_version": bytes.get(19).copied(),
            "reserved_space": bytes.get(20).copied(),
            "file_change_counter": read_be_u32(bytes, 24),
            "database_size_pages": read_be_u32(bytes, 28),
            "freelist_pages": read_be_u32(bytes, 36),
            "schema_cookie": read_be_u32(bytes, 40),
            "schema_format": read_be_u32(bytes, 44),
            "text_encoding": read_be_u32(bytes, 56),
            "user_version": read_be_u32(bytes, 60),
            "application_id": read_be_u32(bytes, 68),
            "sqlite_version_number": sqlite_version,
        }),
        evidence_ids: vec![format!("analysis:{object_id}:sqlite_header")],
    }
}

fn analyze_wasm_header(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    let version = read_le_u32(bytes, 4);
    ObjectAnalysisSummary {
        analyzer: "wasm_header".to_string(),
        status: if bytes.starts_with(b"\0asm") && version.is_some() {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Failed
        },
        summary: match version {
            Some(version) => format!("WebAssembly module header version {version}"),
            None => "WebAssembly module header is truncated".to_string(),
        },
        details: serde_json::json!({
            "magic": bytes.starts_with(b"\0asm"),
            "version": version,
        }),
        evidence_ids: vec![format!("analysis:{object_id}:wasm_header")],
    }
}

fn analyze_pdf_header(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    let first_line_end = bytes
        .iter()
        .position(|byte| *byte == b'\n' || *byte == b'\r')
        .unwrap_or(bytes.len().min(32));
    let header = String::from_utf8_lossy(&bytes[..first_line_end.min(bytes.len())]).to_string();
    let version = header.strip_prefix("%PDF-").map(str::to_string);
    ObjectAnalysisSummary {
        analyzer: "pdf_header".to_string(),
        status: if bytes.starts_with(b"%PDF-") {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Failed
        },
        summary: match version.as_deref() {
            Some(version) => format!("PDF document header version {version}"),
            None => "PDF document header is malformed or truncated".to_string(),
        },
        details: serde_json::json!({
            "header": header,
            "version": version,
            "has_eof_marker": find_subsequence(bytes, b"%%EOF").is_some(),
            "startxref_count": count_subsequence(bytes, b"startxref"),
            "eof_count": count_subsequence(bytes, b"%%EOF"),
        }),
        evidence_ids: vec![format!("analysis:{object_id}:pdf_header")],
    }
}

fn analyze_ole_header(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    match CompoundFile::parse(bytes) {
        Ok(compound) => ObjectAnalysisSummary {
            analyzer: "ole_header".to_string(),
            status: if compound.warnings().is_empty() {
                ObjectAnalysisStatus::Completed
            } else {
                ObjectAnalysisStatus::Partial
            },
            summary: format!(
                "OLE/CFB compound file with {} directory entries, {} streams",
                compound.directory().len(),
                compound.streams().len()
            ),
            details: serde_json::json!({
                "magic": is_compound_file(bytes),
                "header": compound.header(),
                "directory_entry_count": compound.directory().len(),
                "stream_count": compound.streams().len(),
                "storage_count": compound.storages().len(),
                "physical_size": compound.physical_size(),
                "warnings": compound.warnings(),
            }),
            evidence_ids: vec![format!("analysis:{object_id}:ole_header")],
        },
        Err(err) => ObjectAnalysisSummary {
            analyzer: "ole_header".to_string(),
            status: ObjectAnalysisStatus::Failed,
            summary: format!("OLE/CFB header analysis failed: {err}"),
            details: serde_json::json!({
                "magic": is_compound_file(bytes),
                "error": err.to_string(),
            }),
            evidence_ids: vec![format!("analysis:{object_id}:ole_header")],
        },
    }
}

fn analyze_png_header(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    let ihdr = parse_png_ihdr(bytes);
    ObjectAnalysisSummary {
        analyzer: "png_header".to_string(),
        status: if bytes.starts_with(b"\x89PNG\r\n\x1a\n") && ihdr.is_some() {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Failed
        },
        summary: match ihdr {
            Some((width, height, bit_depth, color_type, _, _, interlace)) => {
                format!(
                    "PNG image {width}x{height}, bit depth {bit_depth}, color type {color_type}, interlace {interlace}"
                )
            }
            None => "PNG header is malformed or truncated".to_string(),
        },
        details: serde_json::json!({
            "magic": bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
            "ihdr": ihdr.map(|(width, height, bit_depth, color_type, compression, filter, interlace)| {
                serde_json::json!({
                    "width": width,
                    "height": height,
                    "bit_depth": bit_depth,
                    "color_type": color_type,
                    "compression_method": compression,
                    "filter_method": filter,
                    "interlace_method": interlace,
                })
            }),
        }),
        evidence_ids: vec![format!("analysis:{object_id}:png_header")],
    }
}

fn analyze_jpeg_header(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    let frame = parse_jpeg_frame_header(bytes);
    ObjectAnalysisSummary {
        analyzer: "jpeg_header".to_string(),
        status: if bytes.starts_with(b"\xff\xd8\xff") && frame.is_some() {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Failed
        },
        summary: match frame {
            Some((width, height, precision, marker, components)) => {
                format!(
                    "JPEG image {width}x{height}, precision {precision}, frame marker {marker}, components {components}"
                )
            }
            None => "JPEG header is malformed or truncated".to_string(),
        },
        details: serde_json::json!({
            "magic": bytes.starts_with(b"\xff\xd8\xff"),
            "frame": frame.map(|(width, height, precision, marker, components)| {
                serde_json::json!({
                    "width": width,
                    "height": height,
                    "precision": precision,
                    "marker": format!("ff{marker:02x}"),
                    "components": components,
                })
            }),
        }),
        evidence_ids: vec![format!("analysis:{object_id}:jpeg_header")],
    }
}

fn analyze_gif_header(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    let header = parse_gif_header(bytes);
    ObjectAnalysisSummary {
        analyzer: "gif_header".to_string(),
        status: if header.is_some() {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Failed
        },
        summary: match header {
            Some((version, width, height, has_global_color_table, global_color_table_size)) => {
                format!(
                    "GIF{version} image {width}x{height}, global color table: {has_global_color_table}, colors: {global_color_table_size}"
                )
            }
            None => "GIF header is malformed or truncated".to_string(),
        },
        details: serde_json::json!({
            "magic": bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
            "header": header.map(|(version, width, height, has_global_color_table, global_color_table_size)| {
                serde_json::json!({
                    "version": version,
                    "width": width,
                    "height": height,
                    "has_global_color_table": has_global_color_table,
                    "global_color_table_size": global_color_table_size,
                })
            }),
        }),
        evidence_ids: vec![format!("analysis:{object_id}:gif_header")],
    }
}

fn analyze_ico_header(object_id: &str, bytes: &[u8]) -> ObjectAnalysisSummary {
    let entries = parse_ico_directory(bytes);
    ObjectAnalysisSummary {
        analyzer: "ico_header".to_string(),
        status: if entries.is_ok() {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Failed
        },
        summary: match entries.as_ref() {
            Ok(entries) => format!("ICO image container with {} image entries", entries.len()),
            Err(_) => "ICO header is malformed or truncated".to_string(),
        },
        details: match entries {
            Ok(entries) => serde_json::json!({
                "reserved": read_le_u16(bytes, 0),
                "type": read_le_u16(bytes, 2),
                "entry_count": entries.len(),
                "entries": entries
                    .iter()
                    .enumerate()
                    .map(|(index, entry)| {
                        serde_json::json!({
                            "index": index,
                            "width": entry.width,
                            "height": entry.height,
                            "color_count": entry.color_count,
                            "planes": entry.planes,
                            "bit_count": entry.bit_count,
                            "image_size": entry.image_size,
                            "image_offset": entry.image_offset,
                            "image_format": ico_entry_image_format(bytes, entry),
                        })
                    })
                    .collect::<Vec<_>>(),
            }),
            Err(err) => serde_json::json!({
                "error": err.to_string(),
                "magic": bytes.iter().take(6).map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(""),
            }),
        },
        evidence_ids: vec![format!("analysis:{object_id}:ico_header")],
    }
}

fn analyze_bmp_header(
    object_id: &str,
    format: Option<&str>,
    bytes: &[u8],
) -> ObjectAnalysisSummary {
    let header = parse_bmp_or_dib_header(bytes);
    ObjectAnalysisSummary {
        analyzer: "bmp_header".to_string(),
        status: if header.is_some() {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Failed
        },
        summary: match header {
            Some(header) => format!(
                "{} bitmap {}x{}, {} bpp, compression {}",
                if header.has_file_header { "BMP" } else { "DIB" },
                header.width,
                header.height,
                header.bit_count,
                header.compression
            ),
            None => "BMP/DIB header is malformed or truncated".to_string(),
        },
        details: serde_json::json!({
            "format": format,
            "header": header.map(|header| {
                serde_json::json!({
                    "has_file_header": header.has_file_header,
                    "file_size": header.file_size,
                    "pixel_offset": header.pixel_offset,
                    "dib_header_size": header.dib_header_size,
                    "width": header.width,
                    "height": header.height,
                    "planes": header.planes,
                    "bit_count": header.bit_count,
                    "compression": header.compression,
                    "image_size": header.image_size,
                    "x_pixels_per_meter": header.x_pixels_per_meter,
                    "y_pixels_per_meter": header.y_pixels_per_meter,
                    "colors_used": header.colors_used,
                    "colors_important": header.colors_important,
                })
            }),
        }),
        evidence_ids: vec![format!("analysis:{object_id}:bmp_header")],
    }
}

fn analyze_riff_header(
    object_id: &str,
    format: Option<&str>,
    bytes: &[u8],
) -> ObjectAnalysisSummary {
    let riff = parse_riff_container(bytes);
    ObjectAnalysisSummary {
        analyzer: "riff_header".to_string(),
        status: match riff.as_ref() {
            Ok(summary) if !summary.truncated && summary.warnings.is_empty() => {
                ObjectAnalysisStatus::Completed
            }
            Ok(_) => ObjectAnalysisStatus::Partial,
            Err(_) => ObjectAnalysisStatus::Failed,
        },
        summary: match riff.as_ref() {
            Ok(summary) => format!(
                "RIFF {} container with {} chunks",
                summary.form_type,
                summary.chunks.len()
            ),
            Err(_) => "RIFF header is malformed or truncated".to_string(),
        },
        details: match riff {
            Ok(summary) => serde_json::json!({
                "format": format,
                "form_type": summary.form_type,
                "declared_size": summary.declared_size,
                "declared_end": summary.declared_end,
                "actual_size": bytes.len(),
                "chunk_count": summary.chunks.len(),
                "truncated": summary.truncated,
                "chunks": summary.chunks
                    .iter()
                    .take(64)
                    .map(|chunk| {
                        serde_json::json!({
                            "id": chunk.id,
                            "offset": chunk.offset,
                            "data_offset": chunk.data_offset,
                            "declared_size": chunk.declared_size,
                            "available_size": chunk.available_size,
                            "padded_size": chunk.padded_size,
                            "truncated": chunk.truncated,
                            "list_type": chunk.list_type,
                            "format_hint": riff_chunk_format_hint(&summary.form_type, chunk),
                        })
                    })
                    .collect::<Vec<_>>(),
                "warnings": summary.warnings,
            }),
            Err(err) => serde_json::json!({
                "format": format,
                "error": err.to_string(),
                "magic": bytes.iter().take(12).map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(""),
            }),
        },
        evidence_ids: vec![format!("analysis:{object_id}:riff_header")],
    }
}

fn analyze_pcap_header(
    object_id: &str,
    format: Option<&str>,
    bytes: &[u8],
) -> ObjectAnalysisSummary {
    let header = parse_pcap_header(bytes);
    ObjectAnalysisSummary {
        analyzer: "pcap_header".to_string(),
        status: if header.is_some() {
            ObjectAnalysisStatus::Completed
        } else {
            ObjectAnalysisStatus::Failed
        },
        summary: match header.as_ref() {
            Some(PcapHeaderSummary::Classic(header)) => format!(
                "PCAP capture v{}.{} {}, snaplen {}, linktype {}",
                header.version_major,
                header.version_minor,
                header.timestamp_precision,
                header.snaplen,
                pcap_linktype_name(header.network)
            ),
            Some(PcapHeaderSummary::Ng(header)) => format!(
                "PCAPNG section {}, byte order {}, block length {}",
                header.version, header.byte_order, header.block_total_length
            ),
            None => "PCAP/PCAPNG header is malformed or truncated".to_string(),
        },
        details: match header {
            Some(PcapHeaderSummary::Classic(header)) => serde_json::json!({
                "format": format,
                "container": "pcap",
                "endianness": header.endianness,
                "timestamp_precision": header.timestamp_precision,
                "version_major": header.version_major,
                "version_minor": header.version_minor,
                "thiszone": header.thiszone,
                "sigfigs": header.sigfigs,
                "snaplen": header.snaplen,
                "network": header.network,
                "network_name": pcap_linktype_name(header.network),
            }),
            Some(PcapHeaderSummary::Ng(header)) => serde_json::json!({
                "format": format,
                "container": "pcapng",
                "endianness": header.endianness,
                "byte_order": header.byte_order,
                "block_type": format!("0x{:08x}", header.block_type),
                "block_total_length": header.block_total_length,
                "version": header.version,
                "section_length": header.section_length,
            }),
            None => serde_json::json!({
                "format": format,
                "magic": bytes.iter().take(16).map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(""),
            }),
        },
        evidence_ids: vec![format!("analysis:{object_id}:pcap_header")],
    }
}

fn analyze_binary_header(
    object_id: &str,
    format: Option<&str>,
    bytes: &[u8],
) -> ObjectAnalysisSummary {
    ObjectAnalysisSummary {
        analyzer: "binary_header".to_string(),
        status: ObjectAnalysisStatus::Completed,
        summary: format!(
            "Binary header identified as {} with {} bytes",
            format.unwrap_or("unknown"),
            bytes.len()
        ),
        details: serde_json::json!({
            "format": format,
            "size": bytes.len(),
            "magic": bytes.iter().take(16).map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(""),
        }),
        evidence_ids: vec![format!("analysis:{object_id}:binary_header")],
    }
}

fn read_be_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([slice[0], slice[1]]))
}

fn read_le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn read_le_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(i32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn count_subsequence(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn parse_png_ihdr(bytes: &[u8]) -> Option<(u32, u32, u8, u8, u8, u8, u8)> {
    if bytes.len() < 33 || !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return None;
    }
    let chunk_len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if chunk_len != 13 || &bytes[12..16] != b"IHDR" {
        return None;
    }
    Some((
        u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
        u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
        bytes[24],
        bytes[25],
        bytes[26],
        bytes[27],
        bytes[28],
    ))
}

fn parse_jpeg_frame_header(bytes: &[u8]) -> Option<(u16, u16, u8, u8, u8)> {
    if bytes.len() < 4 || !bytes.starts_with(b"\xff\xd8") {
        return None;
    }

    let mut cursor = 2usize;
    while cursor + 1 < bytes.len() {
        if bytes[cursor] != 0xff {
            cursor += 1;
            continue;
        }
        while cursor < bytes.len() && bytes[cursor] == 0xff {
            cursor += 1;
        }
        if cursor >= bytes.len() {
            return None;
        }
        let marker = bytes[cursor];
        cursor += 1;
        if marker == 0x00 {
            continue;
        }
        if marker == 0xd9 {
            return None;
        }
        if jpeg_marker_is_standalone(marker) {
            continue;
        }
        if cursor + 2 > bytes.len() {
            return None;
        }
        let length = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
        if length < 2 {
            return None;
        }
        let payload_start = cursor + 2;
        let payload_end = cursor.checked_add(length)?;
        if payload_end > bytes.len() {
            return None;
        }
        if jpeg_marker_is_sof(marker) {
            if payload_start + 6 > payload_end {
                return None;
            }
            return Some((
                u16::from_be_bytes([bytes[payload_start + 3], bytes[payload_start + 4]]),
                u16::from_be_bytes([bytes[payload_start + 1], bytes[payload_start + 2]]),
                bytes[payload_start],
                marker,
                bytes[payload_start + 5],
            ));
        }
        if marker == 0xda {
            return None;
        }
        cursor = payload_end;
    }
    None
}

fn jpeg_marker_is_standalone(marker: u8) -> bool {
    marker == 0x01 || marker == 0xd8 || marker == 0xd9 || (0xd0..=0xd7).contains(&marker)
}

fn jpeg_marker_is_sof(marker: u8) -> bool {
    matches!(
        marker,
        0xc0 | 0xc1 | 0xc2 | 0xc3 | 0xc5 | 0xc6 | 0xc7 | 0xc9 | 0xca | 0xcb | 0xcd | 0xce | 0xcf
    )
}

fn parse_gif_header(bytes: &[u8]) -> Option<(&'static str, u16, u16, bool, u16)> {
    let version = if bytes.starts_with(b"GIF87a") {
        "87a"
    } else if bytes.starts_with(b"GIF89a") {
        "89a"
    } else {
        return None;
    };
    if bytes.len() < 13 {
        return None;
    }
    let width = u16::from_le_bytes([bytes[6], bytes[7]]);
    let height = u16::from_le_bytes([bytes[8], bytes[9]]);
    let packed = bytes[10];
    let has_global_color_table = packed & 0x80 != 0;
    let global_color_table_size = if has_global_color_table {
        1u16 << (((packed & 0x07) as u16) + 1)
    } else {
        0
    };
    Some((
        version,
        width,
        height,
        has_global_color_table,
        global_color_table_size,
    ))
}

#[derive(Debug, Clone)]
struct IcoDirectoryEntry {
    width: u16,
    height: u16,
    color_count: u8,
    planes: u16,
    bit_count: u16,
    image_size: usize,
    image_offset: usize,
}

fn is_ico_file(bytes: &[u8]) -> bool {
    if bytes.len() < 6 {
        return false;
    }
    let reserved = u16::from_le_bytes([bytes[0], bytes[1]]);
    let icon_type = u16::from_le_bytes([bytes[2], bytes[3]]);
    let count = u16::from_le_bytes([bytes[4], bytes[5]]);
    reserved == 0 && matches!(icon_type, 1 | 2) && count > 0
}

fn parse_ico_directory(bytes: &[u8]) -> Result<Vec<IcoDirectoryEntry>> {
    if !is_ico_file(bytes) {
        anyhow::bail!("missing ICO directory header");
    }
    let count = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
    let directory_len = 6usize
        .checked_add(count.checked_mul(16).context("ICO entry count overflows")?)
        .context("ICO directory length overflows")?;
    if directory_len > bytes.len() {
        anyhow::bail!("truncated ICO directory");
    }
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let offset = 6 + index * 16;
        let width = match bytes[offset] {
            0 => 256,
            value => value as u16,
        };
        let height = match bytes[offset + 1] {
            0 => 256,
            value => value as u16,
        };
        let color_count = bytes[offset + 2];
        let planes = u16::from_le_bytes([bytes[offset + 4], bytes[offset + 5]]);
        let bit_count = u16::from_le_bytes([bytes[offset + 6], bytes[offset + 7]]);
        let image_size = u32::from_le_bytes([
            bytes[offset + 8],
            bytes[offset + 9],
            bytes[offset + 10],
            bytes[offset + 11],
        ]) as usize;
        let image_offset = u32::from_le_bytes([
            bytes[offset + 12],
            bytes[offset + 13],
            bytes[offset + 14],
            bytes[offset + 15],
        ]) as usize;
        entries.push(IcoDirectoryEntry {
            width,
            height,
            color_count,
            planes,
            bit_count,
            image_size,
            image_offset,
        });
    }
    Ok(entries)
}

fn ico_entry_name(index: usize, entry: &IcoDirectoryEntry, bytes: &[u8]) -> String {
    let extension = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        "png"
    } else {
        "dib"
    };
    format!(
        "icon_{index}_{}x{}_{}bpp.{extension}",
        entry.width, entry.height, entry.bit_count
    )
}

fn ico_entry_image_format(bytes: &[u8], entry: &IcoDirectoryEntry) -> &'static str {
    let end = entry.image_offset.saturating_add(entry.image_size);
    if end <= bytes.len() && bytes[entry.image_offset..end].starts_with(b"\x89PNG\r\n\x1a\n") {
        "png"
    } else if end <= bytes.len()
        && parse_bmp_or_dib_header(&bytes[entry.image_offset..end]).is_some()
    {
        "dib"
    } else {
        "unknown"
    }
}

#[derive(Debug, Clone, Copy)]
struct BmpHeaderSummary {
    has_file_header: bool,
    file_size: Option<u32>,
    pixel_offset: Option<u32>,
    dib_header_size: u32,
    width: i32,
    height: i32,
    planes: u16,
    bit_count: u16,
    compression: u32,
    image_size: u32,
    x_pixels_per_meter: Option<i32>,
    y_pixels_per_meter: Option<i32>,
    colors_used: Option<u32>,
    colors_important: Option<u32>,
}

fn parse_bmp_or_dib_header(bytes: &[u8]) -> Option<BmpHeaderSummary> {
    let has_file_header = bytes.starts_with(b"BM");
    let dib_offset = if has_file_header { 14 } else { 0 };
    if bytes.len() < dib_offset + 16 {
        return None;
    }
    let dib_header_size = read_le_u32(bytes, dib_offset)?;
    if dib_header_size < 12 || dib_offset + dib_header_size as usize > bytes.len() {
        return None;
    }

    if dib_header_size == 12 {
        let width = read_le_u16(bytes, dib_offset + 4)? as i32;
        let height = read_le_u16(bytes, dib_offset + 6)? as i32;
        let planes = read_le_u16(bytes, dib_offset + 8)?;
        let bit_count = read_le_u16(bytes, dib_offset + 10)?;
        return Some(BmpHeaderSummary {
            has_file_header,
            file_size: has_file_header.then(|| read_le_u32(bytes, 2)).flatten(),
            pixel_offset: has_file_header.then(|| read_le_u32(bytes, 10)).flatten(),
            dib_header_size,
            width,
            height,
            planes,
            bit_count,
            compression: 0,
            image_size: 0,
            x_pixels_per_meter: None,
            y_pixels_per_meter: None,
            colors_used: None,
            colors_important: None,
        });
    }

    if dib_header_size < 40 || bytes.len() < dib_offset + 40 {
        return None;
    }
    Some(BmpHeaderSummary {
        has_file_header,
        file_size: has_file_header.then(|| read_le_u32(bytes, 2)).flatten(),
        pixel_offset: has_file_header.then(|| read_le_u32(bytes, 10)).flatten(),
        dib_header_size,
        width: read_le_i32(bytes, dib_offset + 4)?,
        height: read_le_i32(bytes, dib_offset + 8)?,
        planes: read_le_u16(bytes, dib_offset + 12)?,
        bit_count: read_le_u16(bytes, dib_offset + 14)?,
        compression: read_le_u32(bytes, dib_offset + 16)?,
        image_size: read_le_u32(bytes, dib_offset + 20)?,
        x_pixels_per_meter: read_le_i32(bytes, dib_offset + 24),
        y_pixels_per_meter: read_le_i32(bytes, dib_offset + 28),
        colors_used: read_le_u32(bytes, dib_offset + 32),
        colors_important: read_le_u32(bytes, dib_offset + 36),
    })
}

#[derive(Debug, Clone)]
struct RiffContainerSummary {
    form_type: String,
    declared_size: u32,
    declared_end: usize,
    chunks: Vec<RiffChunkSummary>,
    truncated: bool,
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct RiffChunkSummary {
    id: String,
    offset: usize,
    data_offset: usize,
    declared_size: usize,
    available_size: usize,
    padded_size: usize,
    truncated: bool,
    list_type: Option<String>,
}

fn is_riff_container(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && bytes.starts_with(b"RIFF") && is_fourcc(&bytes[8..12])
}

fn parse_riff_container(bytes: &[u8]) -> Result<RiffContainerSummary> {
    if !is_riff_container(bytes) {
        anyhow::bail!("missing RIFF header");
    }
    let declared_size = read_le_u32(bytes, 4).context("missing RIFF declared size")?;
    let declared_end = 8usize
        .checked_add(declared_size as usize)
        .context("RIFF declared size overflows")?;
    let form_type = riff_fourcc_to_string(&bytes[8..12]);
    let parse_end = declared_end.min(bytes.len());
    let mut cursor = 12usize;
    let mut chunks = Vec::new();
    let mut truncated = declared_end > bytes.len();
    let mut warnings = Vec::new();
    if declared_end > bytes.len() {
        warnings.push(format!(
            "RIFF declared end {declared_end} exceeds object size {}",
            bytes.len()
        ));
    }
    while cursor < parse_end {
        if parse_end - cursor < 8 {
            warnings.push(format!("truncated RIFF chunk header at offset {cursor}"));
            truncated = true;
            break;
        }
        let id = riff_fourcc_to_string(&bytes[cursor..cursor + 4]);
        let declared_size =
            read_le_u32(bytes, cursor + 4).context("missing RIFF chunk size")? as usize;
        let data_offset = cursor + 8;
        let padded_size = declared_size.saturating_add(declared_size % 2);
        let declared_data_end = data_offset
            .checked_add(declared_size)
            .context("RIFF chunk data range overflows")?;
        let padded_end = data_offset
            .checked_add(padded_size)
            .context("RIFF chunk padded range overflows")?;
        let available_end = declared_data_end.min(parse_end);
        let available_size = available_end.saturating_sub(data_offset);
        let chunk_truncated = declared_data_end > parse_end;
        let list_type = if matches!(id.as_str(), "LIST" | "RIFF") && available_size >= 4 {
            Some(riff_fourcc_to_string(&bytes[data_offset..data_offset + 4]))
        } else {
            None
        };
        if chunk_truncated {
            warnings.push(format!(
                "RIFF chunk {id} at offset {cursor} declares {declared_size} bytes but only {available_size} are available"
            ));
            truncated = true;
        }
        chunks.push(RiffChunkSummary {
            id,
            offset: cursor,
            data_offset,
            declared_size,
            available_size,
            padded_size,
            truncated: chunk_truncated,
            list_type,
        });
        if padded_end > parse_end {
            break;
        }
        cursor = padded_end;
    }

    Ok(RiffContainerSummary {
        form_type,
        declared_size,
        declared_end,
        chunks,
        truncated,
        warnings,
    })
}

fn riff_fourcc_to_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(4)
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

fn is_fourcc(bytes: &[u8]) -> bool {
    bytes.len() == 4
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
}

fn riff_signature_for_form(form_type: &str) -> (ObjectKind, &'static str, &'static str) {
    match form_type {
        "WEBP" => (ObjectKind::Image, "webp", "image/webp"),
        "WAVE" => (ObjectKind::File, "wav", "audio/wav"),
        "AVI " => (ObjectKind::File, "avi", "video/x-msvideo"),
        _ => (ObjectKind::File, "riff", "application/octet-stream"),
    }
}

fn riff_chunk_format_hint(form_type: &str, chunk: &RiffChunkSummary) -> &'static str {
    match (form_type, chunk.id.as_str()) {
        ("WEBP", "VP8 ") => "webp_vp8_bitstream",
        ("WEBP", "VP8L") => "webp_vp8l_bitstream",
        ("WEBP", "VP8X") => "webp_extended_header",
        ("WEBP", "ALPH") => "webp_alpha",
        ("WEBP", "ANIM") => "webp_animation",
        ("WEBP", "ANMF") => "webp_animation_frame",
        ("WEBP", "ICCP") => "icc_profile",
        ("WEBP", "EXIF") => "exif_metadata",
        ("WEBP", "XMP ") => "xmp_metadata",
        ("WAVE", "fmt ") => "wav_format",
        ("WAVE", "data") => "wav_audio_data",
        ("WAVE", "fact") => "wav_fact",
        ("AVI ", "hdrl") => "avi_header_list",
        ("AVI ", "movi") => "avi_movie_list",
        (_, "LIST") => "riff_list",
        (_, "RIFF") => "nested_riff",
        _ => "riff_chunk",
    }
}

fn riff_chunk_extension(form_type: &str, chunk: &RiffChunkSummary) -> &'static str {
    match riff_chunk_format_hint(form_type, chunk) {
        "icc_profile" => "icc",
        "exif_metadata" => "exif",
        "xmp_metadata" => "xmp",
        "wav_format" => "wavfmt",
        "wav_audio_data" => "pcm",
        "nested_riff" => "riff",
        _ => "bin",
    }
}

fn riff_chunk_entry_name(index: usize, form_type: &str, chunk: &RiffChunkSummary) -> String {
    let id = chunk.id.trim().replace(' ', "_");
    let extension = riff_chunk_extension(form_type, chunk);
    format!(
        "riff_{index:03}_{form}_{id}.{extension}",
        form = form_type.trim().replace(' ', "_")
    )
}

#[derive(Debug, Clone)]
enum PcapHeaderSummary {
    Classic(ClassicPcapHeader),
    Ng(PcapNgHeader),
}

#[derive(Debug, Clone)]
struct ClassicPcapHeader {
    endianness: &'static str,
    timestamp_precision: &'static str,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: u32,
}

#[derive(Debug, Clone)]
struct PcapNgHeader {
    endianness: &'static str,
    byte_order: &'static str,
    block_type: u32,
    block_total_length: u32,
    version: String,
    section_length: Option<i64>,
}

fn parse_pcap_header(bytes: &[u8]) -> Option<PcapHeaderSummary> {
    if let Some(header) = parse_classic_pcap_header(bytes) {
        return Some(PcapHeaderSummary::Classic(header));
    }
    parse_pcapng_header(bytes).map(PcapHeaderSummary::Ng)
}

fn parse_classic_pcap_header(bytes: &[u8]) -> Option<ClassicPcapHeader> {
    if bytes.len() < 24 {
        return None;
    }
    let (endianness, timestamp_precision, little) = match bytes.get(0..4)? {
        [0xd4, 0xc3, 0xb2, 0xa1] => ("little", "microsecond", true),
        [0xa1, 0xb2, 0xc3, 0xd4] => ("big", "microsecond", false),
        [0x4d, 0x3c, 0xb2, 0xa1] => ("little", "nanosecond", true),
        [0xa1, 0xb2, 0x3c, 0x4d] => ("big", "nanosecond", false),
        _ => return None,
    };
    Some(ClassicPcapHeader {
        endianness,
        timestamp_precision,
        version_major: read_u16_endian(bytes, 4, little)?,
        version_minor: read_u16_endian(bytes, 6, little)?,
        thiszone: read_i32_endian(bytes, 8, little)?,
        sigfigs: read_u32_endian(bytes, 12, little)?,
        snaplen: read_u32_endian(bytes, 16, little)?,
        network: read_u32_endian(bytes, 20, little)?,
    })
}

fn parse_pcapng_header(bytes: &[u8]) -> Option<PcapNgHeader> {
    if bytes.len() < 28 || bytes.get(0..4)? != [0x0a, 0x0d, 0x0d, 0x0a] {
        return None;
    }
    let block_total_length = u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?);
    let (endianness, byte_order, little) = match bytes.get(8..12)? {
        [0x4d, 0x3c, 0x2b, 0x1a] => ("little", "1a2b3c4d", true),
        [0x1a, 0x2b, 0x3c, 0x4d] => ("big", "1a2b3c4d", false),
        _ => return None,
    };
    let version_major = read_u16_endian(bytes, 12, little)?;
    let version_minor = read_u16_endian(bytes, 14, little)?;
    let section_length = read_i64_endian(bytes, 16, little).filter(|value| *value >= 0);
    Some(PcapNgHeader {
        endianness,
        byte_order,
        block_type: 0x0a0d0d0a,
        block_total_length,
        version: format!("{version_major}.{version_minor}"),
        section_length,
    })
}

fn pcap_linktype_name(value: u32) -> &'static str {
    match value {
        0 => "NULL",
        1 => "ETHERNET",
        6 => "IEEE802_5",
        7 => "ARCNET_BSD",
        9 => "PPP",
        101 => "RAW_IP",
        105 => "IEEE802_11",
        113 => "LINUX_SLL",
        127 => "RADIOTAP",
        228 => "IPV4",
        229 => "IPV6",
        276 => "LINUX_SLL2",
        _ => "UNKNOWN",
    }
}

fn read_u16_endian(bytes: &[u8], offset: usize, little: bool) -> Option<u16> {
    let slice: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
    Some(if little {
        u16::from_le_bytes(slice)
    } else {
        u16::from_be_bytes(slice)
    })
}

fn read_u32_endian(bytes: &[u8], offset: usize, little: bool) -> Option<u32> {
    let slice: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(if little {
        u32::from_le_bytes(slice)
    } else {
        u32::from_be_bytes(slice)
    })
}

fn read_i32_endian(bytes: &[u8], offset: usize, little: bool) -> Option<i32> {
    let slice: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(if little {
        i32::from_le_bytes(slice)
    } else {
        i32::from_be_bytes(slice)
    })
}

fn read_i64_endian(bytes: &[u8], offset: usize, little: bool) -> Option<i64> {
    let slice: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
    Some(if little {
        i64::from_le_bytes(slice)
    } else {
        i64::from_be_bytes(slice)
    })
}

struct Signature {
    kind: ObjectKind,
    format: String,
    media_type: Option<String>,
}

fn detect_signature(path: &Path, bytes: &[u8]) -> Signature {
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());

    if is_lnk_like(bytes) {
        return signature(ObjectKind::File, "lnk", "application/x-ms-shortcut");
    }
    if is_safetensors_like(bytes) {
        return signature(
            ObjectKind::Model,
            "safetensors",
            "application/x-safetensors",
        );
    }
    if is_safetensors_index_path(path) || is_safetensors_index_like(bytes) {
        return signature(ObjectKind::Model, "safetensors_index", "application/json");
    }
    if is_gguf_like(bytes) {
        return signature(ObjectKind::Model, "gguf", "application/x-gguf");
    }
    if is_pytorch_like(path, bytes) {
        return signature(ObjectKind::Model, "pytorch", "application/x-pytorch");
    }
    if bytes.starts_with(b"\x7fELF") {
        return signature(ObjectKind::Binary, "elf", "application/x-elf");
    }
    if bytes.starts_with(b"MZ") {
        return signature(
            ObjectKind::Binary,
            "pe",
            "application/vnd.microsoft.portable-executable",
        );
    }
    if ext.as_deref() == Some("class") && bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
        return signature(ObjectKind::Binary, "jvm_class", "application/java-vm");
    }
    if has_any_prefix(
        bytes,
        &[
            &[0xfe, 0xed, 0xfa, 0xcf],
            &[0xcf, 0xfa, 0xed, 0xfe],
            &[0xfe, 0xed, 0xfa, 0xce],
            &[0xce, 0xfa, 0xed, 0xfe],
            &[0xca, 0xfe, 0xba, 0xbe],
            &[0xbe, 0xba, 0xfe, 0xca],
        ],
    ) {
        return signature(ObjectKind::Binary, "macho", "application/x-mach-binary");
    }
    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
    {
        let format = match ext.as_deref() {
            Some("apk") => {
                return signature(
                    ObjectKind::Package,
                    "apk",
                    "application/vnd.android.package-archive",
                );
            }
            Some("ipa") => {
                return signature(ObjectKind::Package, "ipa", "application/octet-stream");
            }
            Some("jar") => {
                return signature(ObjectKind::Package, "jar", "application/java-archive");
            }
            Some("docx") => {
                return signature(
                    ObjectKind::Document,
                    "docx",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                );
            }
            Some("docm") => {
                return signature(
                    ObjectKind::Document,
                    "docm",
                    "application/vnd.ms-word.document.macroEnabled.12",
                );
            }
            Some("xlsx") => {
                return signature(
                    ObjectKind::Document,
                    "xlsx",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                );
            }
            Some("xlsm") => {
                return signature(
                    ObjectKind::Document,
                    "xlsm",
                    "application/vnd.ms-excel.sheet.macroEnabled.12",
                );
            }
            Some("pptx") => {
                return signature(
                    ObjectKind::Document,
                    "pptx",
                    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                );
            }
            Some("pptm") => {
                return signature(
                    ObjectKind::Document,
                    "pptm",
                    "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
                );
            }
            _ => "zip",
        };
        return signature(ObjectKind::Archive, format, "application/zip");
    }
    if is_tar_archive(path, bytes) {
        return signature(ObjectKind::Archive, "tar", "application/x-tar");
    }
    if bytes.starts_with(b"\x1f\x8b") {
        if is_compressed_tar(path, CompressedFormat::Gzip) {
            return signature(ObjectKind::Archive, "tar.gz", "application/gzip");
        }
        return signature(ObjectKind::Archive, "gzip", "application/gzip");
    }
    if bytes.starts_with(b"BZh") {
        if is_compressed_tar(path, CompressedFormat::Bzip2) {
            return signature(ObjectKind::Archive, "tar.bz2", "application/x-bzip2");
        }
        return signature(ObjectKind::Archive, "bzip2", "application/x-bzip2");
    }
    if bytes.starts_with(b"\xfd7zXZ\x00") {
        if is_compressed_tar(path, CompressedFormat::Xz) {
            return signature(ObjectKind::Archive, "tar.xz", "application/x-xz");
        }
        return signature(ObjectKind::Archive, "xz", "application/x-xz");
    }
    if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        if is_compressed_tar(path, CompressedFormat::Zstd) {
            return signature(ObjectKind::Archive, "tar.zst", "application/zstd");
        }
        return signature(ObjectKind::Archive, "zstd", "application/zstd");
    }
    if bytes.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return signature(ObjectKind::Archive, "7z", "application/x-7z-compressed");
    }
    if bytes.starts_with(b"Rar!\x1a\x07") {
        return signature(ObjectKind::Archive, "rar", "application/vnd.rar");
    }
    if bytes.starts_with(b"%PDF-") {
        return signature(ObjectKind::Document, "pdf", "application/pdf");
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return signature(ObjectKind::Image, "png", "image/png");
    }
    if bytes.starts_with(b"\xff\xd8\xff") {
        return signature(ObjectKind::Image, "jpeg", "image/jpeg");
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return signature(ObjectKind::Image, "gif", "image/gif");
    }
    if is_ico_file(bytes) {
        return signature(ObjectKind::Image, "ico", "image/vnd.microsoft.icon");
    }
    if bytes.starts_with(b"BM") && parse_bmp_or_dib_header(bytes).is_some() {
        return signature(ObjectKind::Image, "bmp", "image/bmp");
    }
    if matches!(ext.as_deref(), Some("dib" | "bmp")) && parse_bmp_or_dib_header(bytes).is_some() {
        return signature(ObjectKind::Image, "dib", "image/bmp");
    }
    if is_riff_container(bytes) {
        let form_type = riff_fourcc_to_string(&bytes[8..12]);
        let (kind, format, media_type) = riff_signature_for_form(&form_type);
        return signature(kind, format, media_type);
    }
    if is_compound_file(bytes) {
        return compound_signature(ext.as_deref());
    }
    if bytes.starts_with(b"SQLite format 3\x00") {
        return signature(ObjectKind::Database, "sqlite", "application/vnd.sqlite3");
    }
    if parse_pcapng_header(bytes).is_some() {
        return signature(
            ObjectKind::NetworkCapture,
            "pcapng",
            "application/vnd.tcpdump.pcap",
        );
    }
    if parse_classic_pcap_header(bytes).is_some() {
        return signature(
            ObjectKind::NetworkCapture,
            "pcap",
            "application/vnd.tcpdump.pcap",
        );
    }
    if bytes.starts_with(b"dex\n") {
        return signature(ObjectKind::Binary, "dex", "application/vnd.android.dex");
    }
    if ext.as_deref() == Some("pyc") && is_python_bytecode_like(bytes) {
        return signature(
            ObjectKind::Binary,
            "python_bytecode",
            "application/x-python-code",
        );
    }
    if bytes.starts_with(b"\0asm") {
        return signature(ObjectKind::Binary, "wasm", "application/wasm");
    }
    if bytes.starts_with(b"MSCF") {
        return signature(ObjectKind::Archive, "cab", "application/vnd.ms-cab-compressed");
    }
    if is_tiff_like(bytes) {
        return signature(ObjectKind::Image, "tiff", "image/tiff");
    }
    if bytes.starts_with(b"fLaC") {
        return signature(ObjectKind::File, "flac", "audio/flac");
    }
    if bytes.starts_with(b"OggS") {
        return signature(ObjectKind::File, "ogg", "application/ogg");
    }
    if is_mp3_like(bytes) {
        return signature(ObjectKind::File, "mp3", "audio/mpeg");
    }
    if is_mp4_family_like(bytes) {
        let brand = mp4_major_brand(bytes).unwrap_or("isom");
        let (format, media_type) = match brand {
            "qt  " => ("mov", "video/quicktime"),
            "M4A " | "M4B " | "M4P " => ("m4a", "audio/mp4"),
            "M4V " => ("m4v", "video/x-m4v"),
            "heic" | "heix" | "mif1" | "msf1" => ("heif", "image/heif"),
            "avif" | "avis" => ("avif", "image/avif"),
            _ => ("mp4", "video/mp4"),
        };
        return signature(ObjectKind::File, format, media_type);
    }
    if bytes.starts_with(b"wOFF") {
        return signature(ObjectKind::File, "woff", "font/woff");
    }
    if bytes.starts_with(b"wOF2") {
        return signature(ObjectKind::File, "woff2", "font/woff2");
    }
    if bytes.starts_with(b"OTTO") {
        return signature(ObjectKind::File, "otf", "font/otf");
    }
    if is_truetype_like(bytes) {
        return signature(ObjectKind::File, "ttf", "font/ttf");
    }
    if bytes.starts_with(b"!<arch>\n") {
        return signature(ObjectKind::Archive, "ar", "application/x-archive");
    }
    if is_qcow2_like(bytes) {
        return signature(ObjectKind::FilesystemImage, "qcow2", "application/x-qemu-disk");
    }
    if is_iso9660_like(bytes) {
        return signature(ObjectKind::FilesystemImage, "iso", "application/x-iso9660-image");
    }
    if is_dmg_like(bytes) {
        return signature(ObjectKind::FilesystemImage, "dmg", "application/x-apple-diskimage");
    }
    if looks_like_pem(bytes) {
        return signature(ObjectKind::Text, "pem", "application/x-pem-file");
    }
    if looks_like_html(bytes) {
        return signature(ObjectKind::Text, "html", "text/html");
    }
    if looks_like_xml(bytes) {
        return signature(ObjectKind::Text, "xml", "application/xml");
    }
    if looks_like_json(bytes) {
        return signature(ObjectKind::Text, "json", "application/json");
    }

    match ext.as_deref() {
        Some("img" | "iso" | "vmdk" | "qcow2" | "dmg") => signature(
            ObjectKind::FilesystemImage,
            ext.as_deref().unwrap(),
            "application/octet-stream",
        ),
        Some("dmp" | "dump" | "core") => signature(
            ObjectKind::MemoryDump,
            ext.as_deref().unwrap(),
            "application/octet-stream",
        ),
        Some("pcap" | "pcapng") => signature(
            ObjectKind::NetworkCapture,
            ext.as_deref().unwrap(),
            "application/vnd.tcpdump.pcap",
        ),
        Some("lnk") => signature(ObjectKind::File, "lnk", "application/x-ms-shortcut"),
        Some("doc" | "xls" | "ppt" | "msi" | "msg") if is_compound_file(bytes) => {
            compound_signature(ext.as_deref())
        }
        Some("webp") => signature(ObjectKind::Image, "webp", "image/webp"),
        Some("tiff" | "tif") => signature(ObjectKind::Image, "tiff", "image/tiff"),
        Some("wav" | "wave") => signature(ObjectKind::File, "wav", "audio/wav"),
        Some("flac") => signature(ObjectKind::File, "flac", "audio/flac"),
        Some("ogg" | "oga" | "ogv") => signature(ObjectKind::File, "ogg", "application/ogg"),
        Some("mp3") => signature(ObjectKind::File, "mp3", "audio/mpeg"),
        Some("mp4" | "m4a" | "m4v" | "mov" | "heic" | "heif" | "avif") => signature(
            ObjectKind::File,
            ext.as_deref().unwrap(),
            "application/octet-stream",
        ),
        Some("woff") => signature(ObjectKind::File, "woff", "font/woff"),
        Some("woff2") => signature(ObjectKind::File, "woff2", "font/woff2"),
        Some("ttf") => signature(ObjectKind::File, "ttf", "font/ttf"),
        Some("otf") => signature(ObjectKind::File, "otf", "font/otf"),
        Some("cab") => signature(ObjectKind::Archive, "cab", "application/vnd.ms-cab-compressed"),
        Some("a" | "ar" | "deb" | "lib") => {
            signature(ObjectKind::Archive, "ar", "application/x-archive")
        }
        Some("avi") => signature(ObjectKind::File, "avi", "video/x-msvideo"),
        Some("safetensors") => signature(
            ObjectKind::Model,
            "safetensors",
            "application/x-safetensors",
        ),
        Some("gguf") => signature(ObjectKind::Model, "gguf", "application/x-gguf"),
        Some("onnx" | "tflite" | "pt" | "pth") => signature(
            ObjectKind::Model,
            ext.as_deref().unwrap(),
            "application/octet-stream",
        ),
        Some("pem" | "crt" | "cer" | "key") => {
            signature(ObjectKind::Text, "pem", "application/x-pem-file")
        }
        Some("html" | "htm") => signature(ObjectKind::Text, "html", "text/html"),
        Some("json" | "xml" | "txt" | "md" | "csv" | "toml" | "yaml" | "yml" | "ini" | "properties" | "plist") => {
            let format = ext.as_deref().unwrap();
            let media = match format {
                "json" => "application/json",
                "xml" | "plist" => "application/xml",
                "yaml" | "yml" => "application/x-yaml",
                "toml" => "application/toml",
                "csv" => "text/csv",
                "md" => "text/markdown",
                _ => "text/plain",
            };
            signature(ObjectKind::Text, format, media)
        }
        _ if is_probably_text(bytes) => signature(ObjectKind::Text, "text", "text/plain"),
        _ => signature(ObjectKind::File, "unknown", "application/octet-stream"),
    }
}

fn compound_signature(ext: Option<&str>) -> Signature {
    match ext {
        Some("doc") => signature(ObjectKind::Document, "doc", "application/msword"),
        Some("xls") => signature(ObjectKind::Document, "xls", "application/vnd.ms-excel"),
        Some("ppt") => signature(ObjectKind::Document, "ppt", "application/vnd.ms-powerpoint"),
        Some("msi") => signature(ObjectKind::Package, "msi", "application/x-msi"),
        Some("msg") => signature(ObjectKind::Document, "msg", "application/vnd.ms-outlook"),
        _ => signature(ObjectKind::Document, "ole", "application/vnd.ms-office"),
    }
}

fn signature(kind: ObjectKind, format: &str, media_type: &str) -> Signature {
    Signature {
        kind,
        format: format.to_string(),
        media_type: Some(media_type.to_string()),
    }
}

fn is_lnk_like(bytes: &[u8]) -> bool {
    bytes.len() >= 76
        && bytes.get(0..4) == Some(&[0x4c, 0x00, 0x00, 0x00])
        && bytes.get(4..20)
            == Some(&[
                0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46,
            ])
}

fn is_safetensors_like(bytes: &[u8]) -> bool {
    parse_safetensors_header(bytes).is_some()
}

fn is_gguf_like(bytes: &[u8]) -> bool {
    parse_gguf_header(bytes).is_some()
}

fn is_pytorch_like(path: &Path, bytes: &[u8]) -> bool {
    #[cfg(feature = "containers")]
    if parse_pytorch_zip_header(bytes).is_some() {
        return true;
    }
    matches!(
        path.extension()
            .and_then(|value| value.to_str())
            .map(|value| value.to_ascii_lowercase())
            .as_deref(),
        Some("pt" | "pth" | "ckpt")
    ) && is_pickle_like(bytes)
}

fn is_safetensors_index_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("model.safetensors.index.json"))
}

fn is_safetensors_index_like(bytes: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    let Some(weight_map) = value.get("weight_map").and_then(|item| item.as_object()) else {
        return false;
    };
    !weight_map.is_empty()
        && weight_map.values().any(|value| {
            value
                .as_str()
                .is_some_and(|shard| shard.to_ascii_lowercase().ends_with(".safetensors"))
        })
}

fn parse_safetensors_header(bytes: &[u8]) -> Option<(u64, usize, bool)> {
    if bytes.len() < 8 {
        return None;
    }
    let header_len = u64::from_le_bytes(bytes.get(0..8)?.try_into().ok()?);
    if header_len == 0 || header_len > 16 * 1024 * 1024 {
        return None;
    }
    let header_start = 8usize;
    let header_end = header_start.checked_add(header_len as usize)?;
    if header_end > bytes.len() {
        return None;
    }
    let header = std::str::from_utf8(bytes.get(header_start..header_end)?).ok()?;
    let value: serde_json::Value = serde_json::from_str(header).ok()?;
    let object = value.as_object()?;
    let tensor_count = object
        .iter()
        .filter(|(name, value)| {
            name.as_str() != "__metadata__"
                && value.get("dtype").and_then(|item| item.as_str()).is_some()
                && value
                    .get("shape")
                    .and_then(|item| item.as_array())
                    .is_some()
                && value
                    .get("data_offsets")
                    .and_then(|item| item.as_array())
                    .is_some_and(|items| items.len() == 2)
        })
        .count();
    if tensor_count == 0 && !object.contains_key("__metadata__") {
        return None;
    }
    Some((
        header_len,
        tensor_count,
        object.contains_key("__metadata__"),
    ))
}

fn parse_gguf_header(bytes: &[u8]) -> Option<(u32, u64, u64)> {
    if bytes.len() < 24 || bytes.get(0..4)? != b"GGUF" {
        return None;
    }
    let version = read_le_u32(bytes, 4)?;
    let tensor_count = read_le_u64(bytes, 8)?;
    let metadata_kv_count = read_le_u64(bytes, 16)?;
    if version == 0 || version > 16 {
        return None;
    }
    Some((version, tensor_count, metadata_kv_count))
}

fn parse_pytorch_header(bytes: &[u8]) -> Option<(&'static str, usize, bool)> {
    if is_pickle_like(bytes) {
        return Some(("pickle", 0, true));
    }
    #[cfg(feature = "containers")]
    {
        return parse_pytorch_zip_header(bytes);
    }
    #[cfg(not(feature = "containers"))]
    {
        let _ = bytes;
        None
    }
}

#[cfg(feature = "containers")]
fn parse_pytorch_zip_header(bytes: &[u8]) -> Option<(&'static str, usize, bool)> {
    let cursor = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).ok()?;
    let entry_count = archive.len();
    let mut pickle_present = false;
    let mut torch_marker_present = false;
    for index in 0..entry_count.min(512) {
        let file = archive.by_index(index).ok()?;
        let name = file.name().to_ascii_lowercase();
        if name.ends_with("data.pkl") || name.ends_with(".pkl") {
            pickle_present = true;
        }
        if name.ends_with("version")
            || name.ends_with("byteorder")
            || name.contains("/data/")
            || name == "data.pkl"
        {
            torch_marker_present = true;
        }
    }
    (pickle_present && torch_marker_present).then_some(("zip", entry_count, pickle_present))
}

fn is_pickle_like(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(0..2),
        Some([0x80, 0x02..=0x05]) | Some([b'(', _]) | Some([b'c', _])
    )
}

fn is_python_bytecode_like(bytes: &[u8]) -> bool {
    bytes.len() >= 16 && bytes.get(2..4) == Some(b"\r\n")
}

fn is_tar_archive(path: &Path, bytes: &[u8]) -> bool {
    let ext_is_tar = path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("tar"));
    ext_is_tar || bytes.get(257..262).is_some_and(|magic| magic == b"ustar")
}

fn is_compressed_tar(path: &Path, compressed_format: CompressedFormat) -> bool {
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    let file_name = file_name.to_ascii_lowercase();
    match compressed_format {
        CompressedFormat::Gzip => file_name.ends_with(".tar.gz") || file_name.ends_with(".tgz"),
        CompressedFormat::Bzip2 => {
            file_name.ends_with(".tar.bz2")
                || file_name.ends_with(".tbz2")
                || file_name.ends_with(".tbz")
        }
        CompressedFormat::Xz => file_name.ends_with(".tar.xz") || file_name.ends_with(".txz"),
        CompressedFormat::Zstd => file_name.ends_with(".tar.zst") || file_name.ends_with(".tzst"),
    }
}

fn has_any_prefix(bytes: &[u8], prefixes: &[&[u8]]) -> bool {
    prefixes.iter().any(|prefix| bytes.starts_with(prefix))
}


fn is_tiff_like(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(0..4),
        Some([0x49, 0x49, 0x2a, 0x00] | [0x4d, 0x4d, 0x00, 0x2a] | [0x49, 0x49, 0x2b, 0x00] | [0x4d, 0x4d, 0x00, 0x2b])
    )
}

fn is_mp3_like(bytes: &[u8]) -> bool {
    if bytes.starts_with(b"ID3") {
        return true;
    }
    if bytes.len() < 2 {
        return false;
    }
    bytes[0] == 0xff && (bytes[1] & 0xe0) == 0xe0
}

fn is_mp4_family_like(bytes: &[u8]) -> bool {
    if bytes.len() < 12 {
        return false;
    }
    &bytes[4..8] == b"ftyp"
}

fn mp4_major_brand(bytes: &[u8]) -> Option<&str> {
    if !is_mp4_family_like(bytes) || bytes.len() < 12 {
        return None;
    }
    std::str::from_utf8(&bytes[8..12]).ok()
}

fn is_truetype_like(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(0..4),
        Some([0x00, 0x01, 0x00, 0x00] | [b't', b'r', b'u', b'e'] | [b't', b'y', b'p', b'1'])
    )
}

fn is_qcow2_like(bytes: &[u8]) -> bool {
    bytes.starts_with(b"QFI\xfb")
}

fn is_iso9660_like(bytes: &[u8]) -> bool {
    const OFFSETS: &[usize] = &[0x8001, 0x8801, 0x9001];
    OFFSETS.iter().any(|offset| {
        bytes
            .get(*offset..*offset + 5)
            .is_some_and(|magic| magic == b"CD001")
    })
}

fn is_dmg_like(bytes: &[u8]) -> bool {
    if bytes.len() >= 512 {
        let tail = &bytes[bytes.len() - 512..];
        if tail.starts_with(b"koly") {
            return true;
        }
    }
    bytes.starts_with(b"koly")
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    let sample = &bytes[..bytes.len().min(4096)];
    let Ok(text) = std::str::from_utf8(sample) else {
        return false;
    };
    text.contains("-----BEGIN ") && text.contains("-----")
}

fn looks_like_html(bytes: &[u8]) -> bool {
    let sample = trim_utf8_bom(&bytes[..bytes.len().min(8192)]);
    let Ok(text) = std::str::from_utf8(sample) else {
        return false;
    };
    let trimmed = text.trim_start();
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("<!doctype html")
        || lower.starts_with("<html")
        || lower.starts_with("<head")
        || lower.starts_with("<body")
        || lower.starts_with("<script")
        || lower.starts_with("<div")
        || lower.starts_with("<!--")
}

fn looks_like_xml(bytes: &[u8]) -> bool {
    if looks_like_html(bytes) {
        return false;
    }
    let sample = trim_utf8_bom(&bytes[..bytes.len().min(8192)]);
    let Ok(text) = std::str::from_utf8(sample) else {
        return false;
    };
    let trimmed = text.trim_start();
    trimmed.starts_with("<?xml")
        || (trimmed.starts_with('<')
            && trimmed.contains('>')
            && !trimmed.as_bytes().iter().take(256).any(|b| b.is_ascii_control() && !matches!(b, b'\n' | b'\r' | b'\t')))
}

fn looks_like_json(bytes: &[u8]) -> bool {
    let sample = trim_utf8_bom(&bytes[..bytes.len().min(64 * 1024)]);
    let Ok(text) = std::str::from_utf8(sample) else {
        return false;
    };
    let trimmed = text.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return false;
    }
    serde_json::from_str::<serde_json::Value>(trimmed).is_ok()
        || (trimmed.ends_with('}') || trimmed.ends_with(']') || trimmed.ends_with(','))
            && trimmed.bytes().filter(|b| *b == b'"').count() >= 2
}

fn trim_utf8_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes)
}

fn is_probably_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let sample = &bytes[..bytes.len().min(4096)];
    let suspicious = sample
        .iter()
        .filter(|byte| !(byte.is_ascii_graphic() || byte.is_ascii_whitespace() || **byte == b'\0'))
        .count();
    suspicious * 100 / sample.len() < 5
        && sample.iter().filter(|byte| **byte == b'\0').count() * 100 / sample.len() < 1
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn directory_object_id(path: &Path) -> String {
    let digest = blake3::hash(path.display().to_string().as_bytes());
    format!("dir:{}", digest.to_hex())
}

fn virtual_directory_object_id(container_id: &str, entry_name: &str) -> String {
    let digest = blake3::hash(format!("{container_id}!/{entry_name}").as_bytes());
    format!("dir:{}", digest.to_hex())
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| path.display().to_string())
}

fn import_debug_info(
    path: &Path,
    bytes: &[u8],
    file: &object::File<'_>,
    format: BinaryFormat,
    architecture: Architecture,
) -> DebugImportSummary {
    #[cfg(feature = "debug-info")]
    {
        match (format, architecture) {
            (BinaryFormat::Elf | BinaryFormat::MachO, Architecture::X86_64 | Architecture::Arm64) => {
                dwarf_import(path, bytes, file)
            }
            (BinaryFormat::Pe, Architecture::X86_64) => pdb_import(path, file),
            _ => DebugImportSummary::default(),
        }
    }
    #[cfg(not(feature = "debug-info"))]
    {
        let _ = (path, bytes, file, format, architecture);
        DebugImportSummary::default()
    }
}

#[cfg(feature = "debug-info")]
fn dwarf_import(path: &Path, bytes: &[u8], file: &object::File<'_>) -> DebugImportSummary {
    match dwarf_import_inner(path, bytes, file) {
        Ok(summary) => summary,
        Err(err) => DebugImportSummary {
            status: DebugImportStatus::Failed,
            source_kind: Some("dwarf".to_string()),
            artifact_path: None,
            imported_type_count: 0,
            imported_function_hint_count: 0,
            imported_variable_hint_count: 0,
            type_defs: Vec::new(),
            function_hints: Vec::new(),
            variable_hints: Vec::new(),
            source_anchors: Vec::new(),
            evidence_ids: Vec::new(),
            notes: vec![format!("DWARF import failed: {err:#}")],
        },
    }
}

#[cfg(feature = "debug-info")]
fn dwarf_import_inner(
    path: &Path,
    bytes: &[u8],
    file: &object::File<'_>,
) -> Result<DebugImportSummary> {
    let endian = if file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };

    let load_section = |id: SectionId| -> Result<Cow<'_, [u8]>> {
        if let Some(section) = file.section_by_name(id.name()) {
            Ok(section.uncompressed_data().unwrap_or(Cow::Borrowed(&[])))
        } else {
            Ok(Cow::Borrowed(&[]))
        }
    };

    let dwarf_sections = gimli::DwarfSections::load(&load_section)
        .with_context(|| format!("failed to load DWARF sections from {}", path.display()))?;
    let dwarf = dwarf_sections.borrow(|section| EndianSlice::new(section, endian));
    let mut units = dwarf.units();
    let mut types = Vec::new();
    let mut functions = Vec::new();
    let mut variable_hints = Vec::new();
    let mut source_anchors = Vec::new();

    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();
        while let Some((_, entry)) = entries.next_dfs()? {
            let tag_name = format!("{:?}", entry.tag());
            let name = attr_string(&dwarf, &unit, entry.attr(gimli::DW_AT_name)?)?;
            let decl_file = entry.attr(gimli::DW_AT_decl_file)?;
            let decl_line = attr_u64(entry.attr(gimli::DW_AT_decl_line)?);
            let source_anchor = source_anchor_for(&dwarf, &unit, decl_file, decl_line);
            if let Some(anchor) = source_anchor.clone() {
                source_anchors.push(anchor);
            }
            match entry.tag() {
                gimli::DW_TAG_structure_type
                | gimli::DW_TAG_union_type
                | gimli::DW_TAG_base_type
                | gimli::DW_TAG_typedef
                | gimli::DW_TAG_enumeration_type => {
                    if let Some(name) = name.clone() {
                        types.push(TypeDef {
                            id: format!("dbg:type:{}:{}", path.display(), name),
                            name,
                            kind: tag_name.clone(),
                            source: TypeSource::Debug,
                            size: attr_u64(entry.attr(gimli::DW_AT_byte_size)?),
                            evidence_ids: Vec::new(),
                        });
                    }
                }
                gimli::DW_TAG_subprogram => {
                    if let Some(name) = name.clone() {
                        let address = attr_u64(entry.attr(gimli::DW_AT_low_pc)?);
                        functions.push(DebugFunctionHint {
                            address,
                            name,
                            return_type: None,
                            calling_convention: Some("system_default_x64".to_string()),
                            arguments: Vec::new(),
                            locals: Vec::new(),
                            source_anchor,
                            evidence_ids: Vec::new(),
                        });
                    }
                }
                gimli::DW_TAG_formal_parameter | gimli::DW_TAG_variable => {
                    if let Some(name) = name {
                        let function_name = functions.last().map(|item| item.name.clone());
                        let function_address = functions.last().and_then(|item| item.address);
                        let role = if entry.tag() == gimli::DW_TAG_formal_parameter {
                            VariableRole::Argument
                        } else {
                            VariableRole::Local
                        };
                        let variable = Variable {
                            name,
                            role,
                            storage: VariableStorage::Stack,
                            type_name: None,
                            confidence: 0.9,
                            location: "debug".to_string(),
                            evidence_ids: Vec::new(),
                        };
                        if let Some(last) = functions.last_mut() {
                            match role {
                                VariableRole::Argument => last.arguments.push(variable.clone()),
                                VariableRole::Local => last.locals.push(variable.clone()),
                                VariableRole::Temporary => {}
                            }
                        }
                        variable_hints.push(DebugVariableHint {
                            function_name,
                            function_address,
                            variable,
                            source_anchor,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    if types.is_empty() && functions.is_empty() && variable_hints.is_empty() {
        return Ok(DebugImportSummary {
            status: DebugImportStatus::NotFound,
            source_kind: Some("dwarf".to_string()),
            artifact_path: find_external_dsym(path).map(|p| p.display().to_string()),
            imported_type_count: 0,
            imported_function_hint_count: 0,
            imported_variable_hint_count: 0,
            type_defs: Vec::new(),
            function_hints: Vec::new(),
            variable_hints: Vec::new(),
            source_anchors: Vec::new(),
            evidence_ids: Vec::new(),
            notes: vec!["No DWARF entries were imported".to_string()],
        });
    }

    Ok(DebugImportSummary {
        status: DebugImportStatus::Parsed,
        source_kind: Some("dwarf".to_string()),
        artifact_path: find_external_dsym(path).map(|p| p.display().to_string()),
        imported_type_count: types.len(),
        imported_function_hint_count: functions.len(),
        imported_variable_hint_count: variable_hints.len(),
        type_defs: types,
        function_hints: functions,
        variable_hints,
        source_anchors,
        evidence_ids: Vec::new(),
        notes: vec![
            format!("Loaded DWARF from {}", path.display()),
            format!("Binary size: {}", bytes.len()),
        ],
    })
}

#[cfg(feature = "debug-info")]
fn pdb_import(path: &Path, file: &object::File<'_>) -> DebugImportSummary {
    match pdb_import_inner(path, file) {
        Ok(summary) => summary,
        Err(err) => DebugImportSummary {
            status: DebugImportStatus::Failed,
            source_kind: Some("pdb".to_string()),
            artifact_path: None,
            imported_type_count: 0,
            imported_function_hint_count: 0,
            imported_variable_hint_count: 0,
            type_defs: Vec::new(),
            function_hints: Vec::new(),
            variable_hints: Vec::new(),
            source_anchors: Vec::new(),
            evidence_ids: Vec::new(),
            notes: vec![format!("PDB import failed: {err:#}")],
        },
    }
}

#[cfg(feature = "debug-info")]
fn pdb_import_inner(path: &Path, file: &object::File<'_>) -> Result<DebugImportSummary> {
    let Some(codeview) = file.pdb_info()? else {
        return Ok(DebugImportSummary {
            status: DebugImportStatus::NotFound,
            source_kind: Some("pdb".to_string()),
            artifact_path: None,
            imported_type_count: 0,
            imported_function_hint_count: 0,
            imported_variable_hint_count: 0,
            type_defs: Vec::new(),
            function_hints: Vec::new(),
            variable_hints: Vec::new(),
            source_anchors: Vec::new(),
            evidence_ids: Vec::new(),
            notes: vec!["No PDB CodeView info found".to_string()],
        });
    };

    let pdb_path = resolve_pdb_path(path, &String::from_utf8_lossy(codeview.path()));
    let Some(pdb_path) = pdb_path else {
        return Ok(DebugImportSummary {
            status: DebugImportStatus::NotFound,
            source_kind: Some("pdb".to_string()),
            artifact_path: None,
            imported_type_count: 0,
            imported_function_hint_count: 0,
            imported_variable_hint_count: 0,
            type_defs: Vec::new(),
            function_hints: Vec::new(),
            variable_hints: Vec::new(),
            source_anchors: Vec::new(),
            evidence_ids: Vec::new(),
            notes: vec![format!(
                "PDB hinted by PE debug directory but file was not found: {}",
                String::from_utf8_lossy(codeview.path())
            )],
        });
    };

    let pdb_file = fs::File::open(&pdb_path)
        .with_context(|| format!("failed to open {}", pdb_path.display()))?;
    let mut pdb =
        PDB::open(pdb_file).with_context(|| format!("failed to parse {}", pdb_path.display()))?;
    let _ = pdb.address_map().ok();
    let information = pdb.pdb_information()?;
    let mut types = Vec::new();
    if let Ok(type_information) = pdb.type_information() {
        types.push(TypeDef {
            id: format!("dbg:type:{}:tpi", pdb_path.display()),
            name: format!("pdb_types_{:?}", information.guid),
            kind: "pdb_tpi".to_string(),
            source: TypeSource::Debug,
            size: Some(type_information.len() as u64),
            evidence_ids: Vec::new(),
        });
    }

    // Extract function hints from PDB global symbols.
    let mut function_hints = Vec::new();
    let variable_hints = Vec::new();

    if let Ok(symbol_table) = pdb.global_symbols() {
        let mut symbols = symbol_table.iter();
        while let Ok(Some(symbol)) = symbols.next() {
            if let Ok(pdb::SymbolData::Public(data)) = symbol.parse() {
                let name = String::from_utf8_lossy(data.name.as_bytes()).into_owned();
                let addr = data.offset.offset;
                // Distinguish functions from data symbols by name conventions.
                // Mangled C++ names start with '?', C names are plain identifiers.
                // Data symbols often start with '__' or contain '$'.
                let is_likely_function = !name.starts_with("__")
                    && !name.is_empty()
                    && (name.starts_with('?')
                        || name.starts_with('_')
                        || name.chars().next().is_some_and(|c| c.is_alphabetic()));
                if is_likely_function {
                    function_hints.push(DebugFunctionHint {
                        address: Some(addr as u64),
                        name,
                        return_type: None,
                        calling_convention: None,
                        arguments: Vec::new(),
                        locals: Vec::new(),
                        source_anchor: None,
                        evidence_ids: Vec::new(),
                    });
                }
            }
        }
    }

    let function_count = function_hints.len();
    let variable_count = variable_hints.len();

    Ok(DebugImportSummary {
        status: DebugImportStatus::Parsed,
        source_kind: Some("pdb".to_string()),
        artifact_path: Some(pdb_path.display().to_string()),
        imported_type_count: types.len(),
        imported_function_hint_count: function_count,
        imported_variable_hint_count: variable_count,
        type_defs: types,
        function_hints,
        variable_hints,
        source_anchors: Vec::new(),
        evidence_ids: Vec::new(),
        notes: vec![format!(
            "Loaded PDB from {} (age {}, {} functions, {} variables)",
            pdb_path.display(),
            codeview.age(),
            function_count,
            variable_count
        )],
    })
}

fn file_imports(
    file: &object::File<'_>,
    format: BinaryFormat,
    architecture: Architecture,
    bytes: &[u8],
    cap: usize,
    lean: bool,
) -> Vec<Import> {
    let mut imports = match file.imports() {
        Ok(list) => {
            let mut out = Vec::with_capacity(cap.min(1024));
            for imp in list {
                if out.len() >= cap {
                    break;
                }
                out.push(Import {
                    library: Some(String::from_utf8_lossy(imp.library()).into_owned()),
                    name: String::from_utf8_lossy(imp.name()).into_owned(),
                    address: None,
                });
            }
            out
        }
        Err(_) => Vec::new(),
    };

    if !lean && format == BinaryFormat::Elf && architecture == Architecture::Arm64 {
        assign_elf_arm64_plt_stub_addresses(file, &mut imports);
    }
    if !lean && format == BinaryFormat::MachO {
        assign_macho_stub_addresses(file, bytes, &mut imports);
    }

    imports
}

fn assign_macho_stub_addresses(
    file: &object::File<'_>,
    bytes: &[u8],
    imports: &mut [Import],
) {
    let stubs = macho_stub_import_addrs(file, bytes);
    if stubs.is_empty() {
        return;
    }
    let mut by_name = HashMap::<String, VecDeque<u64>>::new();
    for (name, address) in stubs {
        by_name.entry(name).or_default().push_back(address);
    }
    for import in imports.iter_mut() {
        if import.address.is_some() {
            continue;
        }
        let bare = import.name.trim_start_matches('_');
        for name in [
            import.name.clone(),
            bare.to_string(),
            format!("_{bare}"),
        ] {
            if let Some(queue) = by_name.get_mut(&name) {
                if let Some(address) = queue.pop_front() {
                    import.address = Some(address);
                    break;
                }
            }
        }
    }
}

fn macho_stub_import_addrs(file: &object::File<'_>, bytes: &[u8]) -> Vec<(String, u64)> {
    let mut chosen: Option<(u64, u64, u32, u64, usize)> = None;
    for section in file.sections() {
        let Ok(name) = section.name() else {
            continue;
        };
        let short = name.rsplit(',').next().unwrap_or(name);
        if short != "__auth_stubs" && short != "__stubs" {
            continue;
        }
        let Some((_, file_size)) = section.file_range() else {
            continue;
        };
        if file_size == 0 {
            continue;
        }
        let (index0, reserved2) =
            macho_section_stub_meta(bytes, section.address()).unwrap_or((0, 16));
        let stub_size = if reserved2 != 0 {
            reserved2 as u64
        } else if short == "__auth_stubs" {
            16
        } else {
            12
        };
        if stub_size == 0 || file_size < stub_size {
            continue;
        }
        let score = if short == "__auth_stubs" { 2u64 } else { 1u64 };
        let stub_count = (file_size / stub_size) as usize;
        let replace = match &chosen {
            None => true,
            Some((_, _, _, prev_score, _)) => score > *prev_score,
        };
        if replace {
            chosen = Some((section.address(), stub_size, index0, score, stub_count));
        }
    }
    let Some((section_addr, stub_size, index0, _, stub_count)) = chosen else {
        return Vec::new();
    };
    let Some((symoff, nsyms, stroff, strsize, indirectoff, nindirect)) =
        macho_symtab_and_indirect(bytes)
    else {
        return Vec::new();
    };
    let index0 = index0 as usize;
    if index0 >= nindirect {
        return Vec::new();
    }
    let stub_count = stub_count.min(nindirect.saturating_sub(index0));
    let mut out = Vec::with_capacity(stub_count);
    for i in 0..stub_count {
        let indirect_index = index0 + i;
        let entry_off = indirectoff + indirect_index * 4;
        if entry_off + 4 > bytes.len() {
            break;
        }
        let sym_index =
            u32::from_le_bytes(bytes[entry_off..entry_off + 4].try_into().unwrap_or([0; 4]));
        if sym_index & 0x8000_0000 != 0 {
            continue;
        }
        let sym_index = sym_index as usize;
        if sym_index >= nsyms {
            continue;
        }
        let Some(name) = macho_symbol_name(bytes, symoff, stroff, strsize, sym_index) else {
            continue;
        };
        let address = section_addr.saturating_add((i as u64).saturating_mul(stub_size));
        out.push((name, address));
    }
    out
}

fn macho_section_stub_meta(bytes: &[u8], section_addr: u64) -> Option<(u32, u32)> {
    // Walk load commands to find section with matching addr; return (reserved1, reserved2).
    if bytes.len() < 32 {
        return None;
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let (mut cursor, ncmds, is64) = match magic {
        0xfeedfacf => (
            32usize,
            u32::from_le_bytes(bytes[16..20].try_into().ok()?) as usize,
            true,
        ),
        0xfeedface => (
            28usize,
            u32::from_le_bytes(bytes[16..20].try_into().ok()?) as usize,
            false,
        ),
        _ => return None,
    };
    for _ in 0..ncmds {
        if cursor + 8 > bytes.len() {
            break;
        }
        let cmd = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().ok()?);
        let cmdsize = u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().ok()?) as usize;
        if cmdsize < 8 || cursor + cmdsize > bytes.len() {
            break;
        }
        let is_segment = cmd == 0x19 || cmd == 0x1 || cmd == 0x32; // SEGMENT_64/SEGMENT/SEGMENT_SPLIT
        if is_segment {
            let (seg_header, sectsize, nsects_off) = if is64 {
                (72usize, 80usize, 64usize)
            } else {
                (56usize, 68usize, 48usize)
            };
            if cursor + seg_header > bytes.len() {
                break;
            }
            let nsects = u32::from_le_bytes(
                bytes[cursor + nsects_off..cursor + nsects_off + 4]
                    .try_into()
                    .ok()?,
            ) as usize;
            let mut sect_off = cursor + seg_header;
            for _ in 0..nsects {
                if sect_off + sectsize > bytes.len() {
                    break;
                }
                let addr = if is64 {
                    u64::from_le_bytes(bytes[sect_off + 32..sect_off + 40].try_into().ok()?)
                } else {
                    u32::from_le_bytes(bytes[sect_off + 32..sect_off + 36].try_into().ok()?) as u64
                };
                if addr == section_addr {
                    // section_64: reserved1@68 reserved2@72 reserved3@76
                    // section_32: reserved1@56 reserved2@60
                    let reserved1 = if is64 {
                        u32::from_le_bytes(bytes[sect_off + 68..sect_off + 72].try_into().ok()?)
                    } else {
                        u32::from_le_bytes(bytes[sect_off + 56..sect_off + 60].try_into().ok()?)
                    };
                    let reserved2 = if is64 {
                        u32::from_le_bytes(bytes[sect_off + 72..sect_off + 76].try_into().ok()?)
                    } else {
                        u32::from_le_bytes(bytes[sect_off + 60..sect_off + 64].try_into().ok()?)
                    };
                    return Some((reserved1, reserved2));
                }
                sect_off += sectsize;
            }
        }
        cursor += cmdsize;
    }
    None
}

fn macho_symtab_and_indirect(bytes: &[u8]) -> Option<(usize, usize, usize, usize, usize, usize)> {
    if bytes.len() < 32 {
        return None;
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let (mut cursor, ncmds) = match magic {
        0xfeedfacf => (
            32usize,
            u32::from_le_bytes(bytes[16..20].try_into().ok()?) as usize,
        ),
        0xfeedface => (
            28usize,
            u32::from_le_bytes(bytes[16..20].try_into().ok()?) as usize,
        ),
        _ => return None,
    };
    let mut symoff = None;
    let mut nsyms = None;
    let mut stroff = None;
    let mut strsize = None;
    let mut indirectoff = None;
    let mut nindirect = None;
    for _ in 0..ncmds {
        if cursor + 8 > bytes.len() {
            break;
        }
        let cmd = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().ok()?);
        let cmdsize = u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().ok()?) as usize;
        if cmdsize < 8 || cursor + cmdsize > bytes.len() {
            break;
        }
        if cmd == 0x2 && cmdsize >= 24 {
            symoff = Some(u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().ok()?) as usize);
            nsyms = Some(u32::from_le_bytes(bytes[cursor + 12..cursor + 16].try_into().ok()?) as usize);
            stroff = Some(u32::from_le_bytes(bytes[cursor + 16..cursor + 20].try_into().ok()?) as usize);
            strsize = Some(u32::from_le_bytes(bytes[cursor + 20..cursor + 24].try_into().ok()?) as usize);
        } else if cmd == 0xb && cmdsize >= 80 {
            indirectoff =
                Some(u32::from_le_bytes(bytes[cursor + 56..cursor + 60].try_into().ok()?) as usize);
            nindirect =
                Some(u32::from_le_bytes(bytes[cursor + 60..cursor + 64].try_into().ok()?) as usize);
        }
        cursor += cmdsize;
    }
    Some((symoff?, nsyms?, stroff?, strsize?, indirectoff?, nindirect?))
}

fn macho_symbol_name(
    bytes: &[u8],
    symoff: usize,
    stroff: usize,
    strsize: usize,
    index: usize,
) -> Option<String> {
    let entry_off = symoff.checked_add(index.checked_mul(16)?)?;
    if entry_off + 4 > bytes.len() {
        return None;
    }
    let strx = u32::from_le_bytes(bytes[entry_off..entry_off + 4].try_into().ok()?) as usize;
    if strx >= strsize {
        return None;
    }
    let start = stroff.checked_add(strx)?;
    if start >= bytes.len() {
        return None;
    }
    let end = bytes[start..]
        .iter()
        .position(|b| *b == 0)
        .map(|rel| start + rel)
        .unwrap_or(bytes.len());
    let name = std::str::from_utf8(&bytes[start..end]).ok()?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn assign_elf_arm64_plt_stub_addresses(file: &object::File<'_>, imports: &mut [Import]) {
    let mut stub_addrs_by_name = HashMap::<String, VecDeque<u64>>::new();
    for (name, address) in elf_arm64_plt_import_stub_addrs(file) {
        stub_addrs_by_name
            .entry(name)
            .or_default()
            .push_back(address);
    }

    for import in imports {
        if import.address.is_some() {
            continue;
        }
        if let Some(queue) = stub_addrs_by_name.get_mut(&import.name) {
            import.address = queue.pop_front();
        }
    }
}

fn elf_arm64_plt_import_stub_addrs(file: &object::File<'_>) -> Vec<(String, u64)> {
    let Some((stub_start, stub_count)) = elf_arm64_plt_layout(file) else {
        return Vec::new();
    };
    let Some(got_plt) = file.section_by_name(".got.plt") else {
        return Vec::new();
    };
    let Some(dynamic_symbols) = file.dynamic_symbol_table() else {
        return Vec::new();
    };

    let got_plt_start = got_plt.address();
    let got_plt_end = got_plt_start.saturating_add(got_plt.size());
    let reserved_got_plt_bytes = 0x18u64;
    if got_plt_start == 0 || got_plt_end <= got_plt_start.saturating_add(reserved_got_plt_bytes) {
        return Vec::new();
    }

    let mut relocs = file
        .dynamic_relocations()
        .into_iter()
        .flatten()
        .filter_map(|(offset, relocation)| {
            if offset < got_plt_start.saturating_add(reserved_got_plt_bytes)
                || offset >= got_plt_end
            {
                return None;
            }
            let object::RelocationTarget::Symbol(index) = relocation.target() else {
                return None;
            };
            let symbol = dynamic_symbols.symbol_by_index(index).ok()?;
            let name = symbol.name().ok()?;
            if name.is_empty() {
                return None;
            }
            Some((offset, name.to_string()))
        })
        .collect::<Vec<_>>();
    relocs.sort_unstable_by_key(|(offset, _)| *offset);

    relocs
        .into_iter()
        .take(stub_count)
        .enumerate()
        .map(|(index, (_, name))| (name, stub_start + (index as u64 * 0x10)))
        .collect()
}

fn elf_arm64_plt_layout(file: &object::File<'_>) -> Option<(u64, usize)> {
    let plt = file.section_by_name(".plt")?;
    let reserved_bytes = 0x20u64;
    let entry_bytes = 0x10u64;
    if plt.address() == 0 || plt.size() <= reserved_bytes {
        return None;
    }
    let stub_count = ((plt.size() - reserved_bytes) / entry_bytes) as usize;
    Some((plt.address() + reserved_bytes, stub_count))
}

fn file_exports(file: &object::File<'_>, cap: usize) -> Vec<Export> {
    if cap == 0 {
        return Vec::new();
    }
    if revx_core::lean_mode() {
        let mut out = Vec::with_capacity(cap.min(256));
        for sym in file.dynamic_symbols() {
            if out.len() >= cap {
                break;
            }
            if !sym.is_global() || !sym.is_definition() {
                continue;
            }
            let address = sym.address();
            if address == 0 {
                continue;
            }
            let Ok(name) = sym.name() else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            out.push(Export {
                name: name.to_string(),
                address: Some(address),
            });
        }
        if !out.is_empty() {
            return out;
        }
    }
    match file.exports() {
        Ok(exports) => {
            let mut out = Vec::with_capacity(cap.min(1024));
            for exp in exports {
                if out.len() >= cap {
                    break;
                }
                out.push(Export {
                    name: String::from_utf8_lossy(exp.name()).into_owned(),
                    address: Some(exp.address()),
                });
            }
            out
        }
        Err(_) => Vec::new(),
    }
}

fn file_relocations(file: &object::File<'_>) -> Vec<Relocation> {
    let mut relocations = Vec::new();
    for section in file.sections() {
        for (offset, relocation) in section.relocations() {
            relocations.push(Relocation {
                address: section.address().saturating_add(offset),
                target: match relocation.target() {
                    object::RelocationTarget::Absolute => None,
                    object::RelocationTarget::Symbol(symbol_index) => file
                        .symbol_by_index(symbol_index)
                        .ok()
                        .map(|symbol| symbol.address())
                        .filter(|address| *address != 0),
                    object::RelocationTarget::Section(section_index) => file
                        .section_by_index(section_index)
                        .ok()
                        .map(|target_section| target_section.address())
                        .filter(|address| *address != 0),
                    _ => None,
                },
                symbol: match relocation.target() {
                    object::RelocationTarget::Symbol(symbol_index) => file
                        .symbol_by_index(symbol_index)
                        .ok()
                        .and_then(|symbol| symbol.name().ok().map(ToOwned::to_owned)),
                    _ => None,
                },
                kind: format!("{:?}", relocation.kind()),
            });
        }
    }
    relocations
}

fn file_debug_artifacts(
    path: &Path,
    file: &object::File<'_>,
    debug_import: &DebugImportSummary,
) -> Vec<DebugArtifact> {
    let mut artifacts = Vec::new();

    match debug_import.source_kind.as_deref() {
        Some("dwarf") => {
            artifacts.push(DebugArtifact {
                kind: "dwarf".to_string(),
                identifier: path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string()),
                path: Some(path.display().to_string()),
            });
            if let Some(dsym) = find_external_dsym(path) {
                artifacts.push(DebugArtifact {
                    kind: "dsym".to_string(),
                    identifier: dsym
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_else(|| dsym.display().to_string()),
                    path: Some(dsym.display().to_string()),
                });
            }
        }
        Some("pdb") => {
            if let Ok(Some(codeview)) = file.pdb_info() {
                artifacts.push(DebugArtifact {
                    kind: "pdb".to_string(),
                    identifier: String::from_utf8_lossy(codeview.path()).into_owned(),
                    path: resolve_pdb_path(path, &String::from_utf8_lossy(codeview.path()))
                        .map(|p| p.display().to_string()),
                });
            }
        }
        _ => {}
    }

    artifacts
}


fn hash_bytes_sample(bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    let head = bytes.len().min(4096);
    hasher.update(&bytes[..head]);
    if bytes.len() > 8192 {
        hasher.update(&bytes[bytes.len() - 4096..]);
    }
    hasher.finalize().to_hex().to_string()
}

fn hash_bytes_streaming(bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    const CHUNK: usize = 4096;
    let mut off = 0usize;
    while off < bytes.len() {
        let end = (off + CHUNK).min(bytes.len());
        hasher.update(&bytes[off..end]);
        off = end;
    }
    #[cfg(unix)]
    {
        advise_mmap_dontneed(bytes);
    }
    hasher.finalize().to_hex().to_string()
}

fn max_loaded_strings() -> usize {
    std::env::var("REVX_MAX_STRINGS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v >= 8)
        .unwrap_or(32)
}

fn max_string_bytes() -> usize {
    std::env::var("REVX_MAX_STRING_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v >= 256)
        .unwrap_or(4096)
}

fn extract_strings_capped(
    file: &object::File<'_>,
    max_count: usize,
    max_bytes: usize,
    max_section_scan: usize,
) -> Vec<StringLiteral> {
    let mut out = Vec::with_capacity(max_count.min(64));
    let mut total_bytes = 0usize;
    for section in file.sections() {
        if out.len() >= max_count || total_bytes >= max_bytes {
            break;
        }
        let kind = section.kind();
        if !matches!(
            kind,
            object::SectionKind::ReadOnlyString
                | object::SectionKind::ReadOnlyData
                | object::SectionKind::Data
        ) {
            continue;
        }
        let Ok(data) = section.data() else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        let slice = if data.len() > max_section_scan {
            &data[..max_section_scan]
        } else {
            data
        };
        extract_ascii_strings_into(
            section.address(),
            slice,
            max_count,
            max_bytes,
            &mut out,
            &mut total_bytes,
        );
    }
    dedupe_strings(out)
}

fn extract_ascii_strings_into(
    base_address: u64,
    bytes: &[u8],
    max_count: usize,
    max_bytes: usize,
    out: &mut Vec<StringLiteral>,
    total_bytes: &mut usize,
) {
    let mut start = None;
    for (idx, b) in bytes.iter().copied().enumerate() {
        if out.len() >= max_count || *total_bytes >= max_bytes {
            return;
        }
        let is_printable = matches!(b, 0x20..=0x7e);
        match (start, is_printable) {
            (None, true) => start = Some(idx),
            (Some(s), false) => {
                let len = idx - s;
                if b == 0 {
                    if len >= 1 {
                        let value = String::from_utf8_lossy(&bytes[s..idx]).into_owned();
                        *total_bytes = total_bytes.saturating_add(value.len());
                        out.push(StringLiteral {
                            address: Some(base_address + s as u64),
                            value,
                        });
                    }
                } else if len >= 4 {
                    let value = String::from_utf8_lossy(&bytes[s..idx]).into_owned();
                    *total_bytes = total_bytes.saturating_add(value.len());
                    out.push(StringLiteral {
                        address: Some(base_address + s as u64),
                        value,
                    });
                }
                start = None;
            }
            _ => {}
        }
    }
}

fn extract_strings(file: &object::File<'_>) -> Vec<StringLiteral> {
    let max_count = max_loaded_strings();
    let max_bytes = max_string_bytes();
    let mut out = Vec::with_capacity(max_count.min(4096));
    let mut total_bytes = 0usize;

    for section in file.sections() {
        let kind = section.kind();
        if !matches!(
            kind,
            object::SectionKind::ReadOnlyString
                | object::SectionKind::ReadOnlyData
                | object::SectionKind::Data
        ) {
            continue;
        }
        let Ok(data) = section.data() else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        for item in extract_ascii_strings(section.address(), data) {
            if out.len() >= max_count || total_bytes >= max_bytes {
                return dedupe_strings(out);
            }
            total_bytes = total_bytes.saturating_add(item.value.len());
            out.push(item);
        }
        for item in extract_utf16le_strings(section.address(), data) {
            if out.len() >= max_count || total_bytes >= max_bytes {
                return dedupe_strings(out);
            }
            total_bytes = total_bytes.saturating_add(item.value.len());
            out.push(item);
        }
    }
    if out.is_empty() {
        for section in file.sections() {
            let Ok(data) = section.data() else {
                continue;
            };
            if data.is_empty() || section.address() == 0 {
                continue;
            }
            for item in extract_ascii_strings(section.address(), data) {
                if out.len() >= max_count || total_bytes >= max_bytes {
                    return dedupe_strings(out);
                }
                total_bytes = total_bytes.saturating_add(item.value.len());
                out.push(item);
            }
            for item in extract_utf16le_strings(section.address(), data) {
                if out.len() >= max_count || total_bytes >= max_bytes {
                    return dedupe_strings(out);
                }
                total_bytes = total_bytes.saturating_add(item.value.len());
                out.push(item);
            }
        }
    }
    dedupe_strings(out)
}

fn extract_ascii_strings(base_address: u64, bytes: &[u8]) -> Vec<StringLiteral> {
    let mut out = Vec::new();
    let mut start = None;
    for (idx, b) in bytes.iter().copied().enumerate() {
        let is_printable = matches!(b, 0x20..=0x7e);
        match (start, is_printable) {
            (None, true) => start = Some(idx),
            (Some(s), false) => {
                let len = idx - s;
                if b == 0 {
                    if len >= 1 {
                        out.push(StringLiteral {
                            address: Some(base_address + s as u64),
                            value: String::from_utf8_lossy(&bytes[s..idx]).into_owned(),
                        });
                    }
                } else if len >= 4 {
                    out.push(StringLiteral {
                        address: Some(base_address + s as u64),
                        value: String::from_utf8_lossy(&bytes[s..idx]).into_owned(),
                    });
                }
                start = None;
            }
            (None, false) => {
                if b == 0 {
                    let next_printable = bytes
                        .get(idx + 1)
                        .copied()
                        .map(|n| matches!(n, 0x20..=0x7e))
                        .unwrap_or(false);
                    if next_printable {
                        out.push(StringLiteral {
                            address: Some(base_address + idx as u64),
                            value: String::new(),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(s) = start
        && bytes.len() - s >= 4
    {
        out.push(StringLiteral {
            address: Some(base_address + s as u64),
            value: String::from_utf8_lossy(&bytes[s..]).into_owned(),
        });
    }
    out
}

/// Extract UTF-16LE encoded strings from binary data.
///
/// Scans for sequences of printable ASCII characters encoded as 16-bit little-endian
/// values (i.e., every other byte is 0x00). Minimum length is 4 characters.
/// This catches wide strings commonly used in Windows PE binaries.
fn extract_utf16le_strings(base_address: u64, bytes: &[u8]) -> Vec<StringLiteral> {
    let mut out = Vec::new();
    let mut start = None;
    let mut idx = 0usize;

    while idx + 1 < bytes.len() {
        let lo = bytes[idx];
        let hi = bytes[idx + 1];
        // UTF-16LE printable ASCII range: 0x0020..=0x007e
        let is_printable = hi == 0x00 && (0x20..=0x7e).contains(&lo);
        match (start, is_printable) {
            (None, true) => start = Some(idx),
            (Some(s), false) => {
                let char_count = (idx - s) / 2;
                if char_count >= 4 {
                    let utf16: Vec<u16> = bytes[s..idx]
                        .chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect();
                    if let Ok(value) = String::from_utf16(&utf16) {
                        out.push(StringLiteral {
                            address: Some(base_address + s as u64),
                            value,
                        });
                    }
                }
                start = None;
            }
            _ => {}
        }
        idx += 2;
    }
    if let Some(s) = start {
        let char_count = (bytes.len() - s) / 2;
        if char_count >= 4 {
            let utf16: Vec<u16> = bytes[s..]
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            if let Ok(value) = String::from_utf16(&utf16) {
                out.push(StringLiteral {
                    address: Some(base_address + s as u64),
                    value,
                });
            }
        }
    }
    out
}

fn dedupe_strings(mut strings: Vec<StringLiteral>) -> Vec<StringLiteral> {
    strings.sort_by(|a, b| {
        a.address
            .unwrap_or_default()
            .cmp(&b.address.unwrap_or_default())
            .then_with(|| a.value.cmp(&b.value))
    });
    strings.dedup_by(|a, b| a.address == b.address && a.value == b.value);
    strings
}

#[cfg(feature = "debug-info")]
fn attr_string<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    attr: Option<gimli::Attribute<R>>,
) -> Result<Option<String>> {
    let Some(attr) = attr else {
        return Ok(None);
    };
    let value = dwarf.attr_string(unit, attr.value())?;
    Ok(Some(
        String::from_utf8_lossy(&value.to_slice()?).into_owned(),
    ))
}

#[cfg(feature = "debug-info")]
fn attr_u64<R: gimli::Reader>(attr: Option<gimli::Attribute<R>>) -> Option<u64> {
    let attr = attr?;
    match attr.value() {
        gimli::AttributeValue::Addr(value) => Some(value),
        gimli::AttributeValue::Udata(value) => Some(value),
        gimli::AttributeValue::Data1(value) => Some(value as u64),
        gimli::AttributeValue::Data2(value) => Some(value as u64),
        gimli::AttributeValue::Data4(value) => Some(value as u64),
        gimli::AttributeValue::Data8(value) => Some(value),
        _ => None,
    }
}

#[cfg(feature = "debug-info")]
fn source_anchor_for<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    decl_file: Option<gimli::Attribute<R>>,
    decl_line: Option<u64>,
) -> Option<SourceAnchor> {
    let file = decl_file.and_then(|attr| match attr.value() {
        gimli::AttributeValue::FileIndex(index) => unit.line_program.as_ref().and_then(|program| {
            let header = program.header();
            header.file(index).and_then(|file| {
                dwarf
                    .attr_string(unit, file.path_name())
                    .ok()
                    .and_then(|value| {
                        value
                            .to_slice()
                            .ok()
                            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                    })
            })
        }),
        _ => None,
    });
    if file.is_none() && decl_line.is_none() {
        None
    } else {
        Some(SourceAnchor {
            file,
            line: decl_line,
        })
    }
}

fn find_external_dsym(path: &Path) -> Option<PathBuf> {
    let candidate = PathBuf::from(format!("{}.dSYM", path.display()));
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

fn resolve_pdb_path(binary_path: &Path, stored_path: &str) -> Option<PathBuf> {
    let leaf = Path::new(stored_path).file_name()?.to_owned();
    let sibling = binary_path.with_file_name(leaf);
    if sibling.exists() {
        Some(sibling)
    } else if Path::new(stored_path).exists() {
        Some(PathBuf::from(stored_path))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn macho_entry_and_function_starts_from_bin_ls_slice() {
        let path = Path::new("/tmp/revx-os-re/.revx/artifacts/88f0478b4887f5baaa38d36c766ce1d80aa265c02f82a13ae7c5f4291f0f9bb8");
        if !path.exists() {
            return;
        }
        let image = load_binary(path).expect("load");
        assert_eq!(image.architecture, Architecture::Arm64);
        assert_eq!(image.format, BinaryFormat::MachO);
        assert_eq!(image.entry, Some(0x100000960));
        assert!(
            image.debug_import.function_hints.len() >= 40,
            "expected LC_FUNCTION_STARTS seeds, got {}",
            image.debug_import.function_hints.len()
        );
        assert!(image.entry.is_some_and(|entry| {
            image
                .debug_import
                .function_hints
                .iter()
                .any(|hint| hint.address == Some(entry))
        }));
        assert!(
            image
                .segments
                .iter()
                .any(|segment| segment.name == "__TEXT" && segment.permissions.contains('x'))
        );
        assert!(
            !image
                .segments
                .iter()
                .any(|segment| segment.name == "__PAGEZERO" && segment.permissions.contains('x'))
        );
        let addressed = image
            .imports
            .iter()
            .filter(|import| import.address.is_some())
            .count();
        assert!(
            addressed >= 40,
            "expected Mach-O stub-bound imports, got {addressed}/{}",
            image.imports.len()
        );
        assert!(
            image
                .imports
                .iter()
                .any(|import| import.name.contains("strcoll") && import.address.is_some())
                || image
                    .imports
                    .iter()
                    .any(|import| import.name.contains("printf") && import.address.is_some())
        );
        let addr = |needle: &str| {
            image
                .imports
                .iter()
                .find(|import| {
                    let bare = import.name.trim_start_matches('_');
                    bare == needle
                })
                .and_then(|import| import.address)
        };
        assert_eq!(addr("setlocale"), Some(0x100004644));
        assert_eq!(addr("printf"), Some(0x1000045d4));
        assert_eq!(addr("strcoll"), Some(0x100004684));
        assert_eq!(addr("snprintf"), Some(0x100004664));
    }
}
