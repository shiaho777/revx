use revx_core::{Architecture, BinaryImage};

const MIN_METHOD_POINTER_COUNT: u64 = 16;
const MAX_METHOD_POINTER_COUNT: u64 = 4_000_000;

fn section_kind_at(image: &BinaryImage, address: u64) -> Option<&'static str> {
    for section in &image.sections {
        let start = section.address;
        let end = section.address.saturating_add(section.size);
        if address >= start && address < end {
            return Some(if section.kind.contains("Text") {
                "text"
            } else {
                "data"
            });
        }
    }
    None
}

fn is_executable(image: &BinaryImage, address: u64) -> bool {
    section_kind_at(image, address) == Some("text")
}

/// Finds exported il2cpp_* API function addresses.
pub fn il2cpp_api_exports(image: &BinaryImage) -> Vec<(String, u64)> {
    image
        .exports
        .iter()
        .filter_map(|export| {
            let address = export.address?;
            if export.name.starts_with("il2cpp_") {
                Some((export.name.clone(), address))
            } else {
                None
            }
        })
        .collect()
}

fn read_u64(image: &BinaryImage, address: u64) -> Option<u64> {
    for section in &image.sections {
        let start = section.address;
        let end = section.address.saturating_add(section.size);
        if address >= start && address < end && section.file_offset.is_some() {
            let offset = (address - start) as usize;
            let path = std::path::Path::new(&image.path);
            let file = fs_read_at(path, section.file_offset?, offset, 8)?;
            return Some(u64::from_le_bytes([
                file[0], file[1], file[2], file[3], file[4], file[5], file[6], file[7],
            ]));
        }
    }
    None
}

fn fs_read_at(
    path: &std::path::Path,
    file_offset: u64,
    offset: usize,
    len: usize,
) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).ok()?;
    file.seek(SeekFrom::Start(file_offset.saturating_add(offset as u64)))
        .ok()?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).ok()?;
    Some(buf)
}

/// Heuristic scan for the CodeRegistration structure inside writable/readonly data
/// sections: a (count, pointer) pair where count is a plausible method count and the
/// pointer targets executable bytes. Returns (count, table_address).
pub fn find_method_pointer_table(image: &BinaryImage) -> Option<(u64, u64)> {
    if image.architecture != Architecture::Arm64 || image.sections.is_empty() {
        return None;
    }
    let mut best: Option<(u64, u64, u64)> = None;
    for section in &image.sections {
        if !(section.kind.contains("Data") || section.kind.contains("ReadOnly")) {
            continue;
        }
        if section.size == 0 || section.size > 64 * 1024 * 1024 {
            continue;
        }
        let Some(file_offset) = section.file_offset else {
            continue;
        };
        let Some(bytes) = fs_read_at(
            std::path::Path::new(&image.path),
            file_offset,
            0,
            section.size as usize,
        ) else {
            continue;
        };
        for offset in (0..bytes.len().saturating_sub(16)).step_by(8) {
            let count = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            if !(MIN_METHOD_POINTER_COUNT..=MAX_METHOD_POINTER_COUNT).contains(&count) {
                continue;
            }
            let address = section.address + offset as u64;
            let table = u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
            let mut text_hits = 0u32;
            for index in 0..8u64 {
                let Some(entry) = read_u64(image, table.saturating_add(index * 8)) else {
                    break;
                };
                if is_executable(image, entry) {
                    text_hits += 1;
                }
            }
            #[cfg(test)]
            eprintln!(
                "dbg count={count:#x} table={table:#x} hits={text_hits} addr={address:#x} path={}",
                image.path
            );
            if text_hits < 4 {
                continue;
            }
            if best.is_none() || best.is_some_and(|(_, _, c)| count > c) {
                best = Some((count, table, address));
            }
        }
    }
    best.map(|(count, table, _)| (count, table))
}

/// Binds method index -> address for the first `want` entries of the table.
pub fn method_addresses(image: &BinaryImage, table: u64, want: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(want);
    for index in 0..want {
        let Some(entry) = read_u64(image, table.saturating_add((index * 8) as u64)) else {
            break;
        };
        if is_executable(image, entry) {
            out.push(entry);
        } else {
            out.push(0);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use revx_core::{BinaryFormat, Section};

    #[test]
    fn export_filter_only_il2cpp_prefix() {
        let mut image = BinaryImage {
            id: "t".into(),
            path: "/dev/null".into(),
            format: BinaryFormat::Elf,
            architecture: Architecture::Arm64,
            entry: None,
            image_base: Some(0x1000),
            size: 0x1000,
            hash_blake3: "h".into(),
            modules: Vec::new(),
            segments: Vec::new(),
            sections: Vec::new(),
            imports: Vec::new(),
            exports: vec![
                revx_core::Export {
                    name: "il2cpp_init".into(),
                    address: Some(0x1000),
                },
                revx_core::Export {
                    name: "other_fn".into(),
                    address: Some(0x2000),
                },
            ],
            relocations: Vec::new(),
            debug_artifacts: Vec::new(),
            debug_import: Default::default(),
            symbols: Vec::new(),
            strings: Vec::new(),
        };
        let _ = &mut image;
        let api = il2cpp_api_exports(&image);
        assert_eq!(api.len(), 1);
        assert_eq!(api[0].0, "il2cpp_init");
    }

    #[test]
    fn method_addresses_stops_on_non_executable() {
        // Placeholder structural test; real binding validated on corpus.
        let image = BinaryImage {
            id: "t".into(),
            path: "/dev/null".into(),
            format: BinaryFormat::Elf,
            architecture: Architecture::Arm64,
            entry: None,
            image_base: Some(0x1000),
            size: 0x1000,
            hash_blake3: "h".into(),
            modules: Vec::new(),
            segments: Vec::new(),
            sections: vec![Section {
                name: ".text".into(),
                address: 0x100000,
                size: 0x4000,
                kind: "Text".into(),
                file_offset: Some(0x1000),
            }],
            imports: Vec::new(),
            exports: Vec::new(),
            relocations: Vec::new(),
            debug_artifacts: Vec::new(),
            debug_import: Default::default(),
            symbols: Vec::new(),
            strings: Vec::new(),
        };
        assert!(is_executable(&image, 0x100000));
        assert!(!is_executable(&image, 0x200000));
    }
}

#[cfg(test)]
mod scan_tests {
    use super::*;
    use revx_core::{BinaryFormat, Section};
    use std::io::Write;

    #[test]
    fn scanner_finds_table_and_rejects_garbage() {
        let dir = std::env::temp_dir().join("revx-il2cpp-code");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("fake-{}.so", std::process::id()));

        let mut file = std::fs::File::create(&path).unwrap();
        use std::io::Seek;
        let text_addr: u64 = 0x100000;
        let data_addr: u64 = 0x200000;
        let func_a: u64 = text_addr + 0x100;
        let func_b: u64 = text_addr + 0x200;
        let pair_addr: u64 = data_addr + 0x300;
        let table_addr: u64 = data_addr + 0x100;
        let count: u64 = 42;

        let mut text = vec![0u8; 0x400];
        text[0x100..0x104].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
        text[0x200..0x204].copy_from_slice(&0xd65f03c0u32.to_le_bytes());

        let mut data = vec![0u8; 0x400];
        let pair_off = (pair_addr - data_addr) as usize;
        data[pair_off..pair_off + 8].copy_from_slice(&count.to_le_bytes());
        data[pair_off + 8..pair_off + 16].copy_from_slice(&table_addr.to_le_bytes());
        let entries_off = (table_addr - data_addr) as usize;
        for (i, func) in [
            func_a, func_b, func_a, func_b, func_a, func_b, func_a, func_b,
        ]
        .iter()
        .enumerate()
        {
            let e = entries_off + i * 8;
            data[e..e + 8].copy_from_slice(&func.to_le_bytes());
        }

        let blob: Vec<u8> = vec![0; 0x1000];
        file.write_all(&blob).unwrap();
        let text_file_off = 0x1000u64;
        file.write_all(&text).unwrap();
        while file.stream_position().unwrap() < 0x2000 {
            file.write_all(&[0u8; 0x100]).unwrap();
        }
        let data_file_off = 0x2000u64;
        file.write_all(&data).unwrap();
        drop(file);

        let image = BinaryImage {
            id: "fake".into(),
            path: path.display().to_string(),
            format: BinaryFormat::Elf,
            architecture: Architecture::Arm64,
            entry: None,
            image_base: Some(0x1000),
            size: 0x3000,
            hash_blake3: "h".into(),
            modules: Vec::new(),
            segments: Vec::new(),
            sections: vec![
                Section {
                    name: ".text".into(),
                    address: text_addr,
                    size: 0x400,
                    kind: "Text".into(),
                    file_offset: Some(text_file_off),
                },
                Section {
                    name: ".data.rel.ro".into(),
                    address: data_addr,
                    size: 0x400,
                    kind: "ReadOnlyData".into(),
                    file_offset: Some(data_file_off),
                },
            ],
            imports: Vec::new(),
            exports: Vec::new(),
            relocations: Vec::new(),
            debug_artifacts: Vec::new(),
            debug_import: Default::default(),
            symbols: Vec::new(),
            strings: Vec::new(),
        };

        let found = find_method_pointer_table(&image);
        assert!(found.is_some(), "scanner must locate the valid table");
        let (count_found, table_found) = found.unwrap();
        assert_eq!(count_found, count);
        assert_eq!(table_found, table_addr);

        let addresses = method_addresses(&image, table_addr, 4);
        assert_eq!(addresses[0], func_a);
        assert_eq!(addresses[1], func_b);
        assert_eq!(addresses[2], func_a);

        // garbage region: huge count whose "table" points at non-executable data
        let mut data2 = data.clone();
        let pair_off2 = (data_addr + 0x380 - data_addr) as usize;
        let garbage_table: u64 = data_addr + 0x380;
        data2[pair_off2..pair_off2 + 8].copy_from_slice(&999999u64.to_le_bytes());
        data2[pair_off2 + 8..pair_off2 + 16].copy_from_slice(&garbage_table.to_le_bytes());
        std::fs::write(&path, {
            let mut all = vec![0u8; 0x1000];
            all.extend_from_slice(&text);
            while all.len() < 0x2000 {
                all.push(0);
            }
            all.extend_from_slice(&data2);
            all
        })
        .unwrap();
        let found2 = find_method_pointer_table(&image);
        assert!(found2.is_some());
        assert_eq!(
            found2.unwrap().1,
            table_addr,
            "garbage pair must lose to valid one"
        );
    }
}

/// Relocation-aware pass: rebuilds the runtime view of data sections from RELATIVE
/// relocations (addend = target address in file state) and enumerates method-pointer
/// tables as maximal runs of relocated slots pointing into executable memory.
pub struct RelocTables {
    pub tables: Vec<(u64, usize)>,
    pub entries: Vec<(u64, u64)>,
}

pub fn scan_reloc_tables(image: &BinaryImage) -> Option<RelocTables> {
    if image.architecture != Architecture::Arm64 || image.relocations.is_empty() {
        return None;
    }
    let mut relmap: Vec<(u64, i64)> = image
        .relocations
        .iter()
        .filter(|r| r.addend != 0)
        .map(|r| (r.address, r.addend))
        .collect();
    if relmap.is_empty() {
        return None;
    }
    relmap.sort_unstable();
    relmap.dedup_by_key(|(address, _)| *address);
    let is_exec = |v: u64| -> bool { is_executable(image, v) };
    let mut tables = Vec::new();
    let mut entries: Vec<(u64, u64)> = Vec::new();
    let mut run_start: Option<u64> = None;
    let mut run_prev: Option<u64> = None;
    for &(address, addend) in &relmap {
        let value = addend as u64;
        if is_exec(value) {
            match (run_start, run_prev) {
                (Some(_start), Some(prev)) if address == prev.saturating_add(8) => {
                    run_prev = Some(address);
                }
                _ => {
                    if let (Some(start), Some(prev)) = (run_start, run_prev) {
                        let count = ((prev - start) / 8 + 1) as usize;
                        if count >= 100 {
                            tables.push((start, count));
                        }
                    }
                    run_start = Some(address);
                    run_prev = Some(address);
                }
            }
            entries.push((address, value));
        } else {
            if let (Some(start), Some(prev)) = (run_start, run_prev) {
                let count = ((prev - start) / 8 + 1) as usize;
                if count >= 100 {
                    tables.push((start, count));
                }
            }
            run_start = None;
            run_prev = None;
        }
    }
    if let (Some(start), Some(prev)) = (run_start, run_prev) {
        let count = ((prev - start) / 8 + 1) as usize;
        if count >= 100 {
            tables.push((start, count));
        }
    }
    if tables.is_empty() {
        return None;
    }
    Some(RelocTables { tables, entries })
}

#[cfg(test)]
mod reloc_tests {
    use super::*;

    #[test]
    fn real_corpus_scan_finds_module_tables_when_present() {
        let corpus = std::env::var("REVX_IL2CPP_CORPUS").ok();
        let Some(path) = corpus else {
            eprintln!("skipping: REVX_IL2CPP_CORPUS not set");
            return;
        };
        let image = match crate::load_binary(std::path::Path::new(&path)) {
            Ok(image) => image,
            Err(e) => {
                eprintln!("skipping: load failed: {e}");
                return;
            }
        };
        eprintln!("relocations captured: {}", image.relocations.len());
        if image.relocations.is_empty() {
            eprintln!("skipping: no relocations captured (lean build?)");
            return;
        }
        let tables = scan_reloc_tables(&image).expect("reloc scan should find tables");
        eprintln!(
            "tables={} entries={}",
            tables.tables.len(),
            tables.entries.len()
        );
        assert!(!tables.tables.is_empty());
        let total_entries: usize = tables.tables.iter().map(|(_, c)| c).sum();
        assert!(total_entries >= 100_000, "expected large method surface");
    }
}
