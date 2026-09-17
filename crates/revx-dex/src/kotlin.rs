//! Kotlin @Metadata parsing: recovers the d2 string table from class
//! annotations, which R8 cannot strip (the Kotlin runtime needs it for
//! reflection), and maps obfuscated classes back toward their original
//! names.

use crate::DexFile;

fn u32_at(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn uleb128(data: &[u8], off: usize) -> Option<(u32, usize)> {
    let mut result = 0u32;
    let mut shift = 0;
    let mut pos = off;
    loop {
        let b = *data.get(pos)?;
        result |= ((b & 0x7f) as u32) << shift;
        pos += 1;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 35 {
            return None;
        }
    }
    Some((result, pos))
}

fn string_at(dex: &DexFile, idx: u32) -> String {
    dex.strings.get(idx as usize).cloned().unwrap_or_default()
}

fn parse_encoded_value(dex: &DexFile, data: &[u8], off: usize) -> Option<(EncodedValue, usize)> {
    let head = *data.get(off)?;
    let value_type = head & 0x1f;
    let arg = (head >> 5) as usize;
    let mut pos = off + 1;
    let value = match value_type {
        0x17 => {
            let mut idx = 0u32;
            for i in 0..=arg {
                idx |= (*data.get(pos + i)? as u32) << (i * 8);
            }
            pos += arg + 1;
            EncodedValue::String(string_at(dex, idx))
        }
        0x18 => {
            pos += arg + 1;
            EncodedValue::Type
        }
        0x1c => {
            let (size, p) = uleb128(data, pos)?;
            pos = p;
            let mut items = Vec::with_capacity(size as usize);
            for _ in 0..size {
                let (v, p) = parse_encoded_value(dex, data, pos)?;
                pos = p;
                items.push(v);
            }
            EncodedValue::Array(items)
        }
        0x00 | 0x02 | 0x03 | 0x04 => {
            pos += arg + 1;
            EncodedValue::Int
        }
        _ => {
            pos += arg + 1;
            EncodedValue::Other
        }
    };
    Some((value, pos))
}

enum EncodedValue {
    String(String),
    Type,
    Array(Vec<EncodedValue>),
    Int,
    Other,
}

pub struct KotlinClassMetadata {
    pub class: String,
    pub d2: Vec<String>,
}

fn read_annotation(
    dex: &DexFile,
    data: &[u8],
    off: usize,
) -> Option<(u32, Vec<(u32, EncodedValue)>)> {
    let (type_idx, pos) = uleb128(data, off)?;
    let (size, mut pos) = uleb128(data, pos)?;
    let mut elements = Vec::with_capacity(size as usize);
    for _ in 0..size {
        let (name_idx, p) = uleb128(data, pos)?;
        pos = p;
        let (value, p) = parse_encoded_value(dex, data, pos)?;
        pos = p;
        elements.push((name_idx, value));
    }
    Some((type_idx, elements))
}

pub fn extract_kotlin_metadata(dex: &DexFile) -> Vec<KotlinClassMetadata> {
    let data = &dex.data;
    let mut out = Vec::new();
    for class in &dex.classes {
        let ann_off = class.annotations_off;
        if ann_off == 0 {
            continue;
        }
        let Some(class_set_off) = u32_at(data, ann_off as usize) else {
            continue;
        };
        if class_set_off == 0 {
            continue;
        }
        let Some(set_size) = u32_at(data, class_set_off as usize) else {
            continue;
        };
        for i in 0..set_size.min(16) {
            let Some(item_off) = u32_at(data, class_set_off as usize + 4 + i as usize * 4) else {
                continue;
            };
            let item = item_off as usize;
            let Some(_visibility) = data.get(item) else {
                continue;
            };
            let Some((type_idx, elements)) = read_annotation(dex, data, item + 1) else {
                continue;
            };
            let type_name = string_at(dex, type_idx);
            if type_name != "Lkotlin/Metadata;" {
                continue;
            }
            let mut d2 = Vec::new();
            for (name_idx, value) in &elements {
                if string_at(dex, *name_idx) == "d2"
                    && let EncodedValue::Array(items) = value
                {
                    for item in items {
                        if let EncodedValue::String(s) = item {
                            d2.push(s.clone());
                        }
                    }
                }
            }
            if !d2.is_empty() {
                out.push(KotlinClassMetadata {
                    class: class.class.clone(),
                    d2,
                });
            }
            break;
        }
    }
    out
}

pub struct RecoveredName {
    pub obfuscated: String,
    pub real: String,
    pub members: Vec<String>,
}

pub fn recover_names(metadata: &[KotlinClassMetadata]) -> Vec<RecoveredName> {
    let mut out = Vec::new();
    for m in metadata {
        let class_candidates: Vec<&String> =
            m.d2.iter()
                .filter(|s| {
                    s.len() > 3
                        && s.contains('/')
                        && !s.contains(' ')
                        && !s.contains('(')
                        && s.chars()
                            .next()
                            .is_some_and(|c| c.is_ascii_lowercase() || c == 'k')
                        && s.split('/').count() >= 2
                        && s.split('/').next_back().is_some_and(|last| {
                            last.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                        })
                })
                .collect();
        let real = class_candidates
            .last()
            .map(|s| s.as_str())
            .unwrap_or_default()
            .to_string();
        let members: Vec<String> =
            m.d2.iter()
                .filter(|s| {
                    !s.contains('/')
                        && !s.contains(' ')
                        && s.chars()
                            .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
                        && s.len() > 1
                })
                .cloned()
                .collect();
        if !real.is_empty() {
            out.push(RecoveredName {
                obfuscated: m.class.clone(),
                real,
                members,
            });
        }
    }
    out
}
