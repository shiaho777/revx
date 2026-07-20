use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::fmt;

pub const COMPOUND_FILE_MAGIC: &[u8; 8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";

const FREE_SECTOR: u32 = 0xffff_ffff;
const END_OF_CHAIN: u32 = 0xffff_fffe;
const FAT_SECTOR: u32 = 0xffff_fffd;
const DIFAT_SECTOR: u32 = 0xffff_fffc;
const NO_STREAM: u32 = 0xffff_ffff;
const HEADER_SIZE: usize = 512;
const DIRECTORY_ENTRY_SIZE: usize = 128;
const DIFAT_HEADER_ENTRIES: usize = 109;
const MAX_CHAIN_SECTORS: usize = 1_000_000;

#[derive(Debug, Clone)]
pub struct CompoundFileError {
    message: String,
}

impl CompoundFileError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CompoundFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CompoundFileError {}

pub type CompoundFileResult<T> = Result<T, CompoundFileError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundFileHeader {
    pub minor_version: u16,
    pub major_version: u16,
    pub byte_order: u16,
    pub sector_shift: u16,
    pub mini_sector_shift: u16,
    pub sector_size: usize,
    pub mini_sector_size: usize,
    pub directory_sector_count: u32,
    pub fat_sector_count: u32,
    pub first_directory_sector: Option<u32>,
    pub mini_stream_cutoff_size: u32,
    pub first_mini_fat_sector: Option<u32>,
    pub mini_fat_sector_count: u32,
    pub first_difat_sector: Option<u32>,
    pub difat_sector_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompoundEntryType {
    Unknown,
    Storage,
    Stream,
    RootStorage,
}

impl CompoundEntryType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Storage => "storage",
            Self::Stream => "stream",
            Self::RootStorage => "root_storage",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundDirectoryEntry {
    pub index: usize,
    pub name: String,
    pub entry_type: CompoundEntryType,
    pub color: u8,
    pub left_sibling: Option<u32>,
    pub right_sibling: Option<u32>,
    pub child: Option<u32>,
    pub clsid_hex: String,
    pub state_bits: u32,
    pub creation_time: Option<u64>,
    pub modified_time: Option<u64>,
    pub start_sector: Option<u32>,
    pub stream_size: u64,
    pub path: Option<String>,
    pub parent_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundStream {
    pub index: usize,
    pub path: String,
    pub name: String,
    pub size: u64,
    pub start_sector: Option<u32>,
    pub storage_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundStorage {
    pub index: usize,
    pub path: String,
    pub name: String,
    pub child_count: usize,
}

#[derive(Debug, Clone)]
pub struct CompoundFile<'a> {
    bytes: &'a [u8],
    header: CompoundFileHeader,
    fat: Vec<u32>,
    mini_fat: Vec<u32>,
    directory: Vec<CompoundDirectoryEntry>,
    root_stream: Vec<u8>,
    fat_sector_ids: Vec<u32>,
    difat_sector_ids: Vec<u32>,
    warnings: Vec<String>,
}

impl<'a> CompoundFile<'a> {
    pub fn parse(bytes: &'a [u8]) -> CompoundFileResult<Self> {
        if !is_compound_file(bytes) {
            return Err(CompoundFileError::new("missing Compound File header magic"));
        }
        if bytes.len() < HEADER_SIZE {
            return Err(CompoundFileError::new("truncated Compound File header"));
        }

        let header = parse_header(bytes)?;
        if header.byte_order != 0xfffe {
            return Err(CompoundFileError::new(format!(
                "unsupported Compound File byte order 0x{:04x}",
                header.byte_order
            )));
        }
        if !matches!(header.sector_shift, 9 | 12) {
            return Err(CompoundFileError::new(format!(
                "unsupported Compound File sector shift {}",
                header.sector_shift
            )));
        }

        let mut warnings = Vec::new();
        let (fat_sector_ids, difat_sector_ids) = collect_difat(bytes, &header, &mut warnings)?;
        let fat = collect_fat(bytes, &header, &fat_sector_ids, &mut warnings)?;
        let directory_bytes = read_regular_chain(
            bytes,
            &header,
            &fat,
            header.first_directory_sector,
            None,
            &mut warnings,
        )?;
        let mut directory = parse_directory_entries(&directory_bytes, &mut warnings);
        assign_directory_paths(&mut directory, &mut warnings);

        let root_stream = directory
            .first()
            .filter(|entry| entry.entry_type == CompoundEntryType::RootStorage)
            .and_then(|entry| {
                read_regular_chain(
                    bytes,
                    &header,
                    &fat,
                    entry.start_sector,
                    Some(entry.stream_size),
                    &mut warnings,
                )
                .ok()
            })
            .unwrap_or_default();
        let mini_fat = collect_mini_fat(bytes, &header, &fat, &mut warnings)?;

        Ok(Self {
            bytes,
            header,
            fat,
            mini_fat,
            directory,
            root_stream,
            fat_sector_ids,
            difat_sector_ids,
            warnings,
        })
    }

    pub fn header(&self) -> &CompoundFileHeader {
        &self.header
    }

    pub fn directory(&self) -> &[CompoundDirectoryEntry] {
        &self.directory
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn streams(&self) -> Vec<CompoundStream> {
        self.directory
            .iter()
            .filter(|entry| entry.entry_type == CompoundEntryType::Stream)
            .filter_map(|entry| {
                let path = entry.path.clone()?;
                Some(CompoundStream {
                    index: entry.index,
                    path: path.clone(),
                    name: entry.name.clone(),
                    size: entry.stream_size,
                    start_sector: entry.start_sector,
                    storage_path: path
                        .rsplit_once('/')
                        .map(|(storage, _)| (!storage.is_empty()).then_some(storage.to_string()))
                        .flatten(),
                })
            })
            .collect()
    }

    pub fn storages(&self) -> Vec<CompoundStorage> {
        self.directory
            .iter()
            .filter(|entry| entry.entry_type == CompoundEntryType::Storage)
            .filter_map(|entry| {
                let path = entry.path.clone()?;
                Some(CompoundStorage {
                    index: entry.index,
                    path,
                    name: entry.name.clone(),
                    child_count: entry
                        .child
                        .map(|child| collect_child_indices(&self.directory, child).len())
                        .unwrap_or(0),
                })
            })
            .collect()
    }

    pub fn read_stream_by_index(&self, index: usize) -> CompoundFileResult<Vec<u8>> {
        let entry = self.directory.get(index).ok_or_else(|| {
            CompoundFileError::new(format!("stream index {index} is out of range"))
        })?;
        if entry.entry_type != CompoundEntryType::Stream {
            return Err(CompoundFileError::new(format!(
                "directory entry {index} is not a stream"
            )));
        }
        self.read_stream_entry(entry)
    }

    pub fn read_stream_by_path(&self, path: &str) -> CompoundFileResult<Vec<u8>> {
        let entry = self
            .directory
            .iter()
            .find(|entry| {
                entry.entry_type == CompoundEntryType::Stream && entry.path.as_deref() == Some(path)
            })
            .ok_or_else(|| CompoundFileError::new(format!("stream path {path} was not found")))?;
        self.read_stream_entry(entry)
    }

    pub fn physical_size(&self) -> u64 {
        let mut max_sector = None::<u32>;
        for sector in self
            .fat_sector_ids
            .iter()
            .chain(self.difat_sector_ids.iter())
            .copied()
        {
            update_max_sector(&mut max_sector, sector);
        }
        for entry in &self.directory {
            if matches!(
                entry.entry_type,
                CompoundEntryType::Stream | CompoundEntryType::RootStorage
            ) {
                for sector in self.chain_sector_ids(entry.start_sector) {
                    update_max_sector(&mut max_sector, sector);
                }
            }
        }
        for sector in self.chain_sector_ids(self.header.first_directory_sector) {
            update_max_sector(&mut max_sector, sector);
        }
        for sector in self.chain_sector_ids(self.header.first_mini_fat_sector) {
            update_max_sector(&mut max_sector, sector);
        }
        max_sector
            .and_then(|sector| {
                (sector as u64)
                    .checked_add(2)?
                    .checked_mul(self.header.sector_size as u64)
            })
            .unwrap_or(HEADER_SIZE as u64)
            .min(self.bytes.len() as u64)
    }

    fn read_stream_entry(&self, entry: &CompoundDirectoryEntry) -> CompoundFileResult<Vec<u8>> {
        if entry.stream_size == 0 {
            return Ok(Vec::new());
        }
        if entry.stream_size < self.header.mini_stream_cutoff_size as u64 {
            self.read_mini_stream(entry.start_sector, entry.stream_size)
        } else {
            let mut warnings = Vec::new();
            read_regular_chain(
                self.bytes,
                &self.header,
                &self.fat,
                entry.start_sector,
                Some(entry.stream_size),
                &mut warnings,
            )
        }
    }

    fn read_mini_stream(
        &self,
        start_sector: Option<u32>,
        size: u64,
    ) -> CompoundFileResult<Vec<u8>> {
        let Some(mut sector) = start_sector else {
            return Ok(Vec::new());
        };
        let mut bytes = Vec::new();
        let mut visited = HashSet::new();
        while sector != END_OF_CHAIN && sector != FREE_SECTOR {
            if !visited.insert(sector) {
                return Err(CompoundFileError::new(
                    "cycle in Compound File mini FAT chain",
                ));
            }
            let offset = sector as usize * self.header.mini_sector_size;
            let end = offset
                .checked_add(self.header.mini_sector_size)
                .ok_or_else(|| CompoundFileError::new("mini sector range overflows"))?;
            if end > self.root_stream.len() {
                return Err(CompoundFileError::new(format!(
                    "mini sector {sector} exceeds root mini stream size {}",
                    self.root_stream.len()
                )));
            }
            bytes.extend_from_slice(&self.root_stream[offset..end]);
            if bytes.len() as u64 >= size {
                bytes.truncate(size as usize);
                return Ok(bytes);
            }
            sector = *self
                .mini_fat
                .get(sector as usize)
                .ok_or_else(|| CompoundFileError::new("mini FAT chain references missing entry"))?;
        }
        bytes.truncate(size as usize);
        Ok(bytes)
    }

    fn chain_sector_ids(&self, start: Option<u32>) -> Vec<u32> {
        let Some(mut sector) = start else {
            return Vec::new();
        };
        let mut sectors = Vec::new();
        let mut visited = HashSet::new();
        while sector != END_OF_CHAIN && sector != FREE_SECTOR {
            if !visited.insert(sector) {
                break;
            }
            sectors.push(sector);
            let Some(next) = self.fat.get(sector as usize).copied() else {
                break;
            };
            if matches!(next, FAT_SECTOR | DIFAT_SECTOR) {
                break;
            }
            sector = next;
            if sectors.len() >= MAX_CHAIN_SECTORS {
                break;
            }
        }
        sectors
    }
}

pub fn is_compound_file(bytes: &[u8]) -> bool {
    bytes.starts_with(COMPOUND_FILE_MAGIC)
}

fn parse_header(bytes: &[u8]) -> CompoundFileResult<CompoundFileHeader> {
    let sector_shift = read_le_u16(bytes, 30)?;
    let mini_sector_shift = read_le_u16(bytes, 32)?;
    let sector_size = 1usize
        .checked_shl(sector_shift as u32)
        .ok_or_else(|| CompoundFileError::new("Compound File sector size overflows"))?;
    let mini_sector_size = 1usize
        .checked_shl(mini_sector_shift as u32)
        .ok_or_else(|| CompoundFileError::new("Compound File mini sector size overflows"))?;
    Ok(CompoundFileHeader {
        minor_version: read_le_u16(bytes, 24)?,
        major_version: read_le_u16(bytes, 26)?,
        byte_order: read_le_u16(bytes, 28)?,
        sector_shift,
        mini_sector_shift,
        sector_size,
        mini_sector_size,
        directory_sector_count: read_le_u32(bytes, 40)?,
        fat_sector_count: read_le_u32(bytes, 44)?,
        first_directory_sector: normalize_sector(read_le_u32(bytes, 48)?),
        mini_stream_cutoff_size: read_le_u32(bytes, 56)?,
        first_mini_fat_sector: normalize_sector(read_le_u32(bytes, 60)?),
        mini_fat_sector_count: read_le_u32(bytes, 64)?,
        first_difat_sector: normalize_sector(read_le_u32(bytes, 68)?),
        difat_sector_count: read_le_u32(bytes, 72)?,
    })
}

fn collect_difat(
    bytes: &[u8],
    header: &CompoundFileHeader,
    warnings: &mut Vec<String>,
) -> CompoundFileResult<(Vec<u32>, Vec<u32>)> {
    let mut fat_sector_ids = Vec::new();
    for index in 0..DIFAT_HEADER_ENTRIES {
        let offset = 76 + index * 4;
        let sector = read_le_u32(bytes, offset)?;
        if is_regular_sector_id(sector) {
            fat_sector_ids.push(sector);
        }
    }

    let mut difat_sector_ids = Vec::new();
    let mut next = header.first_difat_sector;
    let entries_per_difat = header.sector_size / 4 - 1;
    for _ in 0..header.difat_sector_count {
        let Some(sector) = next else {
            break;
        };
        difat_sector_ids.push(sector);
        let offset = sector_offset(header, sector)?;
        let sector_bytes = bytes
            .get(offset..offset + header.sector_size)
            .ok_or_else(|| {
                CompoundFileError::new(format!("DIFAT sector {sector} exceeds file size"))
            })?;
        for index in 0..entries_per_difat {
            let sector = read_le_u32(sector_bytes, index * 4)?;
            if is_regular_sector_id(sector) {
                fat_sector_ids.push(sector);
            }
        }
        next = normalize_sector(read_le_u32(sector_bytes, entries_per_difat * 4)?);
    }

    if fat_sector_ids.len() < header.fat_sector_count as usize {
        warnings.push(format!(
            "Compound File header declares {} FAT sectors but DIFAT lists {}",
            header.fat_sector_count,
            fat_sector_ids.len()
        ));
    }
    fat_sector_ids.truncate(header.fat_sector_count as usize);
    Ok((fat_sector_ids, difat_sector_ids))
}

fn collect_fat(
    bytes: &[u8],
    header: &CompoundFileHeader,
    fat_sector_ids: &[u32],
    warnings: &mut Vec<String>,
) -> CompoundFileResult<Vec<u32>> {
    let mut fat = Vec::new();
    for &sector in fat_sector_ids {
        let offset = sector_offset(header, sector)?;
        let Some(sector_bytes) = bytes.get(offset..offset + header.sector_size) else {
            warnings.push(format!("FAT sector {sector} exceeds file size"));
            continue;
        };
        for chunk in sector_bytes.chunks_exact(4) {
            fat.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
    }
    Ok(fat)
}

fn collect_mini_fat(
    bytes: &[u8],
    header: &CompoundFileHeader,
    fat: &[u32],
    warnings: &mut Vec<String>,
) -> CompoundFileResult<Vec<u32>> {
    let mini_fat_bytes = read_regular_chain(
        bytes,
        header,
        fat,
        header.first_mini_fat_sector,
        Some(header.mini_fat_sector_count as u64 * header.sector_size as u64),
        warnings,
    )?;
    Ok(mini_fat_bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect())
}

fn read_regular_chain(
    bytes: &[u8],
    header: &CompoundFileHeader,
    fat: &[u32],
    start: Option<u32>,
    size: Option<u64>,
    warnings: &mut Vec<String>,
) -> CompoundFileResult<Vec<u8>> {
    let Some(mut sector) = start else {
        return Ok(Vec::new());
    };
    let mut result = Vec::new();
    let mut visited = HashSet::new();
    while sector != END_OF_CHAIN && sector != FREE_SECTOR {
        if !visited.insert(sector) {
            return Err(CompoundFileError::new("cycle in Compound File FAT chain"));
        }
        let offset = sector_offset(header, sector)?;
        let Some(sector_bytes) = bytes.get(offset..offset + header.sector_size) else {
            return Err(CompoundFileError::new(format!(
                "sector {sector} exceeds file size"
            )));
        };
        result.extend_from_slice(sector_bytes);
        if size.is_some_and(|size| result.len() as u64 >= size) {
            result.truncate(size.unwrap() as usize);
            return Ok(result);
        }
        let Some(next) = fat.get(sector as usize).copied() else {
            warnings.push(format!(
                "FAT chain references missing sector entry {sector}"
            ));
            break;
        };
        if matches!(next, FAT_SECTOR | DIFAT_SECTOR) {
            warnings.push(format!(
                "FAT chain for sector {sector} points to reserved sector marker"
            ));
            break;
        }
        sector = next;
        if visited.len() >= MAX_CHAIN_SECTORS {
            warnings.push(format!(
                "FAT chain reached sector limit {MAX_CHAIN_SECTORS}"
            ));
            break;
        }
    }
    if let Some(size) = size {
        result.truncate(size as usize);
    }
    Ok(result)
}

fn parse_directory_entries(
    directory_bytes: &[u8],
    warnings: &mut Vec<String>,
) -> Vec<CompoundDirectoryEntry> {
    let mut entries = Vec::new();
    for (index, entry) in directory_bytes
        .chunks_exact(DIRECTORY_ENTRY_SIZE)
        .enumerate()
    {
        let object_type = entry[66];
        let entry_type = match object_type {
            1 => CompoundEntryType::Storage,
            2 => CompoundEntryType::Stream,
            5 => CompoundEntryType::RootStorage,
            _ => CompoundEntryType::Unknown,
        };
        if entry_type == CompoundEntryType::Unknown {
            continue;
        }
        let name = decode_directory_name(entry).unwrap_or_else(|| format!("entry_{index}"));
        let start_sector = normalize_sector(read_le_u32(entry, 116).unwrap_or(FREE_SECTOR));
        entries.push(CompoundDirectoryEntry {
            index,
            name,
            entry_type,
            color: entry[67],
            left_sibling: normalize_stream_id(read_le_u32(entry, 68).unwrap_or(NO_STREAM)),
            right_sibling: normalize_stream_id(read_le_u32(entry, 72).unwrap_or(NO_STREAM)),
            child: normalize_stream_id(read_le_u32(entry, 76).unwrap_or(NO_STREAM)),
            clsid_hex: hex_bytes(&entry[80..96]),
            state_bits: read_le_u32(entry, 96).unwrap_or(0),
            creation_time: read_le_u64(entry, 100).filter(|value| *value != 0),
            modified_time: read_le_u64(entry, 108).filter(|value| *value != 0),
            start_sector,
            stream_size: read_le_u64(entry, 120).unwrap_or(0),
            path: None,
            parent_index: None,
        });
    }
    if entries.is_empty() {
        warnings.push("Compound File directory stream contained no entries".to_string());
    }
    entries
}

fn assign_directory_paths(entries: &mut [CompoundDirectoryEntry], warnings: &mut Vec<String>) {
    if entries.is_empty() {
        return;
    }
    entries[0].path = Some("/".to_string());
    if entries[0].entry_type != CompoundEntryType::RootStorage {
        warnings.push("Compound File first directory entry is not Root Storage".to_string());
    }
    let Some(child) = entries[0].child else {
        return;
    };
    let mut visited = BTreeSet::new();
    assign_child_paths(entries, child, "", Some(0), &mut visited);
}

fn assign_child_paths(
    entries: &mut [CompoundDirectoryEntry],
    child: u32,
    parent_path: &str,
    parent_index: Option<usize>,
    visited: &mut BTreeSet<usize>,
) {
    for index in collect_child_indices(entries, child) {
        if index >= entries.len() || !visited.insert(index) {
            continue;
        }
        let name = entries[index].name.clone();
        let path = if parent_path.is_empty() {
            name.clone()
        } else {
            format!("{parent_path}/{name}")
        };
        entries[index].path = Some(path.clone());
        entries[index].parent_index = parent_index;
        if matches!(
            entries[index].entry_type,
            CompoundEntryType::Storage | CompoundEntryType::RootStorage
        ) {
            if let Some(grandchild) = entries[index].child {
                assign_child_paths(entries, grandchild, &path, Some(index), visited);
            }
        }
    }
}

fn collect_child_indices(entries: &[CompoundDirectoryEntry], root: u32) -> Vec<usize> {
    let mut result = Vec::new();
    let mut visited = BTreeSet::new();
    collect_child_indices_inner(entries, root, &mut visited, &mut result);
    result
}

fn collect_child_indices_inner(
    entries: &[CompoundDirectoryEntry],
    index: u32,
    visited: &mut BTreeSet<usize>,
    result: &mut Vec<usize>,
) {
    let index = index as usize;
    if index >= entries.len() || !visited.insert(index) {
        return;
    }
    if let Some(left) = entries[index].left_sibling {
        collect_child_indices_inner(entries, left, visited, result);
    }
    result.push(index);
    if let Some(right) = entries[index].right_sibling {
        collect_child_indices_inner(entries, right, visited, result);
    }
}

fn decode_directory_name(entry: &[u8]) -> Option<String> {
    let name_len = read_le_u16(entry, 64).ok()? as usize;
    if name_len < 2 || name_len > 64 {
        return None;
    }
    let raw = entry.get(..name_len.saturating_sub(2))?;
    let mut units = Vec::new();
    for chunk in raw.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16(&units).ok()
}

fn sector_offset(header: &CompoundFileHeader, sector: u32) -> CompoundFileResult<usize> {
    (sector as usize)
        .checked_add(1)
        .and_then(|value| value.checked_mul(header.sector_size))
        .ok_or_else(|| CompoundFileError::new("Compound File sector offset overflows"))
}

fn read_le_u16(bytes: &[u8], offset: usize) -> CompoundFileResult<u16> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| CompoundFileError::new("truncated little-endian u16"))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_le_u32(bytes: &[u8], offset: usize) -> CompoundFileResult<u32> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| CompoundFileError::new("truncated little-endian u32"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn normalize_sector(value: u32) -> Option<u32> {
    is_regular_sector_id(value).then_some(value)
}

fn normalize_stream_id(value: u32) -> Option<u32> {
    (value != NO_STREAM).then_some(value)
}

fn is_regular_sector_id(value: u32) -> bool {
    !matches!(
        value,
        FREE_SECTOR | END_OF_CHAIN | FAT_SECTOR | DIFAT_SECTOR
    )
}

fn update_max_sector(max_sector: &mut Option<u32>, sector: u32) {
    if max_sector.is_none_or(|value| sector > value) {
        *max_sector = Some(sector);
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
