use revx_core::{
    DebugFunctionHint, DebugImportStatus, DebugImportSummary, DebugVariableHint, TypeDef,
    TypeSource, Variable, VariableRole, VariableStorage,
};
use std::fs;
use std::path::Path;

const METADATA_SANITY: u32 = 0xFAB11BAF;
const IL2CPP_EVIDENCE: &str = "il2cpp:global-metadata";

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
struct MetadataHeader {
    version: i32,
    string_literal_offset: i32,
    string_literal_count: i32,
    string_offset: i32,
    string_count: i32,
    type_definitions_offset: i32,
    type_definitions_count: i32,
    fields_offset: i32,
    fields_count: i32,
    methods_offset: i32,
    methods_count: i32,
    parameters_offset: i32,
    parameters_count: i32,
}

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn i32_at(&self, offset: usize) -> Option<i32> {
        let bytes = self.data.get(offset..offset.checked_add(4)?)?;
        Some(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn pair(&self, offset: usize) -> Option<(i32, i32)> {
        Some((self.i32_at(offset)?, self.i32_at(offset.checked_add(4)?)?))
    }

    fn cstring(&self, offset: i32) -> String {
        if offset < 0 {
            return String::new();
        }
        let start = offset as usize;
        let Some(rest) = self.data.get(start..) else {
            return String::new();
        };
        match rest.iter().position(|&b| b == 0) {
            Some(end) => String::from_utf8_lossy(&rest[..end]).into_owned(),
            None => String::new(),
        }
    }
}

fn read_header(data: &[u8]) -> Option<MetadataHeader> {
    if data.len() < 292 {
        return None;
    }
    let r = Reader { data };
    let sanity = r.i32_at(0)?;
    if sanity as u32 != METADATA_SANITY {
        return None;
    }
    let version = r.i32_at(4)?;
    if !(20..=31).contains(&version) {
        return None;
    }
    let (string_literal_offset, string_literal_count) = r.pair(0x50)?;
    let (string_offset, string_count) = r.pair(0x70)?;
    let (type_definitions_offset, type_definitions_size) = r.pair(0x58)?;
    let (fields_offset, fields_size) = r.pair(0x28)?;
    let (methods_offset, methods_size) = r.pair(0x60)?;
    let (parameters_offset, parameters_size) = r.pair(0x48)?;
    Some(MetadataHeader {
        version,
        string_literal_offset,
        string_literal_count,
        string_offset,
        string_count,
        type_definitions_offset,
        type_definitions_count: type_definitions_size,
        fields_offset,
        fields_count: fields_size,
        methods_offset,
        methods_count: methods_size,
        parameters_offset,
        parameters_count: parameters_size,
    })
}

const TYPE_DEF_STRIDE_V242: usize = 0x58;
const METHOD_DEF_STRIDE_V242: usize = 4 * 12;
const FIELD_DEF_STRIDE_V242: usize = 12;
const PARAM_DEF_STRIDE_V242: usize = 12;

fn u32_pair(r: &Reader, offset: usize) -> Option<(i32, i32)> {
    let a = r.i32_at(offset)?;
    let b = r.i32_at(offset.checked_add(4)?)?;
    Some((a, b))
}

fn parse(h: &MetadataHeader, data: &[u8]) -> Option<Il2cppMetadata> {
    let r = Reader { data };
    let type_stride = TYPE_DEF_STRIDE_V242;
    let mut types = Vec::new();
    let mut hints = Vec::new();
    let type_count = (h.type_definitions_count as usize) / type_stride;
    for type_index in 0..type_count {
        let base = h.type_definitions_offset as usize + type_index * type_stride;
        let Some((name_index, _namespace_index)) = u32_pair(&r, base) else {
            continue;
        };
        let type_name = r.cstring(h.string_offset + name_index);
        if type_name.is_empty() {
            continue;
        }
        types.push(TypeDef {
            id: format!("il2cpp:type:{type_index}"),
            name: type_name.clone(),
            kind: "il2cpp_class".to_string(),
            source: TypeSource::Debug,
            size: None,
            evidence_ids: vec![IL2CPP_EVIDENCE.to_string()],
        });
        let field_start_index = r.i32_at(base.checked_add(0x30)?).unwrap_or(0);
        let field_count = r.i32_at(base.checked_add(0x38)?).unwrap_or(0).max(0);
        for field_index in 0..field_count as usize {
            let field_base = h.fields_offset as usize
                + (field_start_index as usize + field_index) * FIELD_DEF_STRIDE_V242;
            let Some(field_name_index) = r.i32_at(field_base) else {
                continue;
            };
            let field_name = r.cstring(h.string_offset + field_name_index);
            if field_name.is_empty() {
                continue;
            }
            types.push(TypeDef {
                id: format!("il2cpp:field:{type_index}:{field_index}"),
                name: format!("{type_name}.{field_name}"),
                kind: "il2cpp_field".to_string(),
                source: TypeSource::Debug,
                size: None,
                evidence_ids: vec![IL2CPP_EVIDENCE.to_string()],
            });
        }
        let method_start_index = r.i32_at(base.checked_add(0x40)?).unwrap_or(0);
        let method_count = r.i32_at(base.checked_add(0x44)?).unwrap_or(0).max(0);
        for method_index in 0..method_count as usize {
            let method_base = h.methods_offset as usize
                + (method_start_index as usize + method_index) * METHOD_DEF_STRIDE_V242;
            let Some(name_index) = r.i32_at(method_base) else {
                continue;
            };
            let method_name = r.cstring(h.string_offset + name_index);
            if method_name.is_empty() {
                continue;
            }
            let (param_start, _token) = u32_pair(&r, method_base.checked_add(12)?)?;
            let _ = param_start;
            hints.push(DebugFunctionHint {
                address: None,
                name: format!("{type_name}.{method_name}"),
                return_type: None,
                calling_convention: Some("il2cpp".to_string()),
                arguments: Vec::new(),
                locals: Vec::new(),
                source_anchor: None,
                evidence_ids: vec![format!("{IL2CPP_EVIDENCE}:method")],
            });
        }
    }
    let _ = (
        h.parameters_offset,
        h.parameters_count,
        PARAM_DEF_STRIDE_V242,
    );
    Some(Il2cppMetadata {
        types,
        hints,
        variables: Vec::new(),
    })
}

pub struct Il2cppMetadata {
    pub types: Vec<TypeDef>,
    pub hints: Vec<DebugFunctionHint>,
    pub variables: Vec<DebugVariableHint>,
}

pub fn load_metadata_file(path: &Path) -> Option<Il2cppMetadata> {
    let data = fs::read(path).ok()?;
    let header = read_header(&data)?;
    parse(&header, &data)
}

pub fn metadata_candidates(binary_path: &Path) -> Vec<std::path::PathBuf> {
    let env_path = std::env::var("REVX_IL2CPP_METADATA")
        .ok()
        .filter(|p| !p.is_empty());
    let mut out = Vec::new();
    if let Some(env_path) = env_path {
        out.push(std::path::PathBuf::from(env_path));
    }
    if let Some(parent) = binary_path.parent() {
        out.push(parent.join("global-metadata.dat"));
        out.push(parent.join("il2cpp_data/Metadata/global-metadata.dat"));
    }
    out
}

pub fn enrich(binary_path: &Path, debug_import: &mut DebugImportSummary) {
    for candidate in metadata_candidates(binary_path) {
        if let Some(metadata) = load_metadata_file(&candidate) {
            debug_import.status = DebugImportStatus::Parsed;
            debug_import.source_kind = Some("il2cpp".to_string());
            debug_import.artifact_path = Some(candidate.display().to_string());
            debug_import.imported_type_count += metadata.types.len();
            debug_import.imported_function_hint_count += metadata.hints.len();
            debug_import.imported_variable_hint_count += metadata.variables.len();
            debug_import.type_defs.extend(metadata.types);
            debug_import.function_hints.extend(metadata.hints);
            debug_import.variable_hints.extend(metadata.variables);
            debug_import.evidence_ids.push(IL2CPP_EVIDENCE.to_string());
            debug_import
                .notes
                .push(format!("il2cpp metadata from {}", candidate.display()));
            return;
        }
    }
}

#[allow(dead_code)]
fn placeholder_variable(name: String) -> Variable {
    Variable {
        name,
        role: VariableRole::Argument,
        storage: VariableStorage::Register,
        type_name: None,
        confidence: 1.0,
        location: String::new(),
        evidence_ids: vec![IL2CPP_EVIDENCE.to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_fake_metadata() -> Vec<u8> {
        let mut out = Vec::new();
        let put_i32 = |out: &mut Vec<u8>, v: i32| out.extend_from_slice(&v.to_le_bytes());
        out.extend_from_slice(&METADATA_SANITY.to_le_bytes());
        put_i32(&mut out, 24);
        while out.len() < 0x28 {
            out.push(0);
        }
        let fields_offset = 0x1000i32;
        let fields_size = 3 * 12i32;
        put_i32(&mut out, fields_offset);
        put_i32(&mut out, fields_size);
        while out.len() < 0x48 {
            out.push(0);
        }
        put_i32(&mut out, 0x2000i32);
        put_i32(&mut out, 6 * 12i32);
        while out.len() < 0x50 {
            out.push(0);
        }
        put_i32(&mut out, 0x3000i32);
        put_i32(&mut out, 12i32);
        while out.len() < 0x58 {
            out.push(0);
        }
        let types_offset = 0x4000i32;
        put_i32(&mut out, types_offset);
        put_i32(&mut out, 0x58i32 * 2i32);
        while out.len() < 0x60 {
            out.push(0);
        }
        let methods_offset = 0x5000i32;
        put_i32(&mut out, methods_offset);
        put_i32(&mut out, 4 * 12i32 * 2i32);
        while out.len() < 0x70 {
            out.push(0);
        }
        let strings_offset = 0x6000i32;
        put_i32(&mut out, strings_offset);
        put_i32(&mut out, 0x100i32);
        let mut string_blob: Vec<u8> = Vec::new();
        let push_str = |strings: &mut Vec<u8>, s: &str| {
            let index = strings.len() as i32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            index
        };
        let _name_idx = push_str(&mut string_blob, "Camera");
        while out.len() < fields_offset as usize {
            out.push(0);
        }
        for field_name_index in 0..3i32 {
            let idx = push_str(&mut string_blob, &format!("field{field_name_index}"));
            put_i32(&mut out, idx);
            put_i32(&mut out, 0);
            put_i32(&mut out, 0);
        }
        while out.len() < methods_offset as usize {
            out.push(0);
        }
        for method_name_index in 0..2i32 {
            let idx = push_str(&mut string_blob, &format!("Method{method_name_index}"));
            put_i32(&mut out, idx);
            put_i32(&mut out, 0);
            put_i32(&mut out, 0);
            put_i32(&mut out, 0);
            put_i32(&mut out, 0);
            put_i32(&mut out, 0);
            put_i32(&mut out, 0);
            put_i32(&mut out, 0);
            put_i32(&mut out, 0);
            put_i32(&mut out, 0);
            put_i32(&mut out, 0);
            put_i32(&mut out, 0);
        }
        while out.len() < types_offset as usize {
            out.push(0);
        }
        for type_record in 0..2i32 {
            let base = types_offset as usize + type_record as usize * TYPE_DEF_STRIDE_V242;
            let idx = push_str(&mut string_blob, &format!("Type{type_record}"));
            while out.len() < base + TYPE_DEF_STRIDE_V242 {
                out.push(0);
            }
            out[base..base + 4].copy_from_slice(&idx.to_le_bytes());
            out[base + 4..base + 8].copy_from_slice(&0i32.to_le_bytes());
            out[base + 0x30..base + 0x34].copy_from_slice(&(type_record * 3).to_le_bytes());
            out[base + 0x38..base + 0x3c].copy_from_slice(&3i32.to_le_bytes());
            out[base + 0x40..base + 0x44].copy_from_slice(&(type_record * 2).to_le_bytes());
            out[base + 0x44..base + 0x48].copy_from_slice(&2i32.to_le_bytes());
        }
        while out.len() < strings_offset as usize {
            out.push(0);
        }
        out.extend_from_slice(&string_blob);
        out
    }

    #[test]
    fn parses_synthentic_metadata_into_hints_and_types() {
        let data = build_fake_metadata();
        let header = read_header(&data).expect("header");
        let metadata = parse(&header, &data).expect("parse");
        assert_eq!(metadata.types.len(), 8);
        assert!(metadata.types.iter().any(|t| t.name == "Type0"));
        assert!(metadata.types.iter().any(|t| t.name == "Type1"));
        assert!(metadata.types.iter().any(|t| t.name == "Type0.field2"));
        assert_eq!(metadata.hints.len(), 4);
        assert!(metadata.hints.iter().any(|h| h.name == "Type0.Method0"));
        assert!(metadata.hints.iter().any(|h| h.name == "Type0.Method1"));
    }

    #[test]
    fn rejects_bad_sanity_and_version() {
        let mut data = build_fake_metadata();
        data[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        assert!(read_header(&data).is_none());
        let mut data2 = build_fake_metadata();
        data2[4..8].copy_from_slice(&99i32.to_le_bytes());
        assert!(read_header(&data2).is_none());
    }

    #[test]
    fn enrich_tolerates_missing_files() {
        let mut summary = DebugImportSummary::default();
        enrich(Path::new("/nonexistent/libfoo.so"), &mut summary);
        assert_eq!(summary.status, DebugImportStatus::NotFound);
        assert!(summary.function_hints.is_empty());
    }
}
