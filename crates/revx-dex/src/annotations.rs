//! Annotation directory walking: extracts Signature (generics) strings from
//! class, field, and method annotations, and the Kotlin @Metadata d2 table.

use crate::{ClassDef, DexFile};
use std::collections::HashMap;

fn uleb(data: &[u8], off: usize) -> Option<(u32, usize)> {
    let mut result = 0u32;
    let mut shift = 0u32;
    let mut pos = off;
    loop {
        let b = *data.get(pos)?;
        pos += 1;
        result |= ((b & 0x7f) as u32) << shift;
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

fn skip_value(data: &[u8], pos: usize) -> Option<usize> {
    let head = *data.get(pos)?;
    let ty = head & 0x1f;
    let arg = (head >> 5) as usize;
    let mut p = pos + 1;
    match ty {
        0x1e | 0x1f => {}
        0x1c => {
            let (n, np) = uleb(data, p)?;
            p = np;
            for _ in 0..n.min(64) {
                p = skip_value(data, p)?;
            }
        }
        0x1d => {
            let (_, np) = uleb(data, p)?;
            p = np;
            let (n, np) = uleb(data, p)?;
            p = np;
            for _ in 0..n.min(64) {
                let (_, np) = uleb(data, p)?;
                p = np;
                p = skip_value(data, p)?;
            }
        }
        _ => {
            p += arg + 1;
        }
    }
    Some(p)
}

fn u32_at(dex: &DexFile, off: usize) -> Option<u32> {
    let b = dex.data.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn string_value_in_annotation(
    dex: &DexFile,
    item: usize,
    ann_type: &str,
    elem_name: &str,
) -> Option<String> {
    let data = &dex.data;
    let pos = item + 1;
    let (type_idx, mut p) = uleb(data, pos)?;
    let tname = dex.types.get(type_idx as usize)?;
    if tname != ann_type {
        return None;
    }
    let (n, np) = uleb(data, p)?;
    p = np;
    for _ in 0..n.min(32) {
        let (name_idx, np) = uleb(data, p)?;
        p = np;
        let head = *data.get(p)?;
        let ty = head & 0x1f;
        let arg = (head >> 5) as usize;
        if ty == 0x17 {
            let mut idx = 0u32;
            for k in 0..arg + 1 {
                let b = *data.get(p + 1 + k)?;
                idx |= (b as u32) << (k * 8);
            }
            let ename = dex.strings.get(name_idx as usize)?;
            if ename == elem_name {
                return dex.strings.get(idx as usize).cloned();
            }
            p = p + 1 + arg + 1;
        } else {
            p = skip_value(data, p)?;
        }
    }
    None
}

fn annotation_set_string(
    dex: &DexFile,
    set_off: u32,
    ann_type: &str,
    elem: &str,
) -> Option<String> {
    let size = u32_at(dex, set_off as usize)?;
    for i in 0..size.min(64) {
        let item = u32_at(dex, set_off as usize + 4 + i as usize * 4)?;
        if item == 0 {
            continue;
        }
        if let Some(s) = string_value_in_annotation(dex, item as usize, ann_type, elem) {
            return Some(s);
        }
    }
    None
}

#[derive(Default)]
pub struct ClassAnnotations {
    pub class_signature: Option<String>,
    pub field_signatures: HashMap<u32, String>,
    pub method_signatures: HashMap<u32, String>,
}

pub fn scan_class_annotations(dex: &DexFile, class: &ClassDef) -> ClassAnnotations {
    let mut out = ClassAnnotations::default();
    if class.annotations_off == 0 {
        return out;
    }
    let dir = class.annotations_off as usize;
    let Some(class_set) = u32_at(dex, dir) else {
        return out;
    };
    if class_set != 0 {
        out.class_signature =
            annotation_set_string(dex, class_set, "Ljava/lang/Signature;", "value");
    }
    let Some(fields_size) = u32_at(dex, dir + 4) else {
        return out;
    };
    let methods_size = u32_at(dex, dir + 8).unwrap_or(0);
    for i in 0..fields_size.min(512) {
        let base = dir + 16 + i as usize * 8;
        let fidx = u32_at(dex, base).unwrap_or(0);
        let aoff = u32_at(dex, base + 4).unwrap_or(0);
        if aoff != 0
            && let Some(s) = annotation_set_string(dex, aoff, "Ljava/lang/Signature;", "value")
        {
            out.field_signatures.insert(fidx, s);
        }
    }
    let mbase = dir + 16 + fields_size as usize * 8;
    for i in 0..methods_size.min(2048) {
        let base = mbase + i as usize * 8;
        let midx = u32_at(dex, base).unwrap_or(0);
        let aoff = u32_at(dex, base + 4).unwrap_or(0);
        if aoff != 0
            && let Some(s) = annotation_set_string(dex, aoff, "Ljava/lang/Signature;", "value")
        {
            out.method_signatures.insert(midx, s);
        }
    }
    out
}

pub fn kotlin_d2_strings(dex: &DexFile, class: &ClassDef) -> Vec<String> {
    if class.annotations_off == 0 {
        return Vec::new();
    }
    let Some(class_set) = u32_at(dex, class.annotations_off as usize) else {
        return Vec::new();
    };
    if class_set == 0 {
        return Vec::new();
    }
    let size = u32_at(dex, class_set as usize).unwrap_or(0);
    for i in 0..size.min(16) {
        let item = u32_at(dex, class_set as usize + 4 + i as usize * 4).unwrap_or(0);
        if item == 0 {
            continue;
        }
        let data = &dex.data;
        let pos = item as usize + 1;
        let Some((type_idx, mut p)) = uleb(data, pos) else {
            continue;
        };
        if !dex
            .types
            .get(type_idx as usize)
            .is_some_and(|t| t == "Lkotlin/Metadata;")
        {
            continue;
        }
        let Some((n, np)) = uleb(data, p) else {
            continue;
        };
        p = np;
        for _ in 0..n.min(32) {
            let Some((name_idx, np)) = uleb(data, p) else {
                break;
            };
            p = np;
            let Some(head) = data.get(p).copied() else {
                break;
            };
            let ty = head & 0x1f;
            let _arg = (head >> 5) as usize;
            if ty == 0x1c
                && dex
                    .strings
                    .get(name_idx as usize)
                    .is_some_and(|s| s == "d2")
            {
                let Some((_, ap)) = uleb(data, p + 1) else {
                    return Vec::new();
                };
                let mut strs = Vec::new();
                let mut q = ap;
                for _ in 0..128 {
                    let Some(h) = data.get(q).copied() else {
                        break;
                    };
                    if h & 0x1f == 0x17 {
                        let a = (h >> 5) as usize;
                        let mut idx = 0u32;
                        let mut ok = true;
                        for k in 0..a + 1 {
                            match data.get(q + 1 + k) {
                                Some(b) => idx |= (*b as u32) << (k * 8),
                                None => {
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        if ok && let Some(s) = dex.strings.get(idx as usize) {
                            strs.push(s.clone());
                        }
                        q = q + 1 + a + 1;
                    } else if let Some(nq) = skip_value(data, q) {
                        q = nq;
                    } else {
                        break;
                    }
                    if strs.len() > 256 {
                        break;
                    }
                }
                return strs;
            }
            match skip_value(data, p) {
                Some(np2) => p = np2,
                None => break,
            }
        }
    }
    Vec::new()
}
