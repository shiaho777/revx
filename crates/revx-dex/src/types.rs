//! DEX type descriptor to Java type name conversion and value type tables.

use revx_analysis::ssa::SsaValueId;
use std::collections::HashMap;

pub type ValueTypes = HashMap<SsaValueId, String>;

pub fn java_type(descriptor: &str) -> String {
    let d = descriptor.trim();
    let mut dims = 0usize;
    let bytes = d.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() && bytes[i] == b'[' {
        dims += 1;
        i += 1;
    }
    let base = match &d[i..] {
        "V" => "void".to_string(),
        "Z" => "boolean".to_string(),
        "B" => "byte".to_string(),
        "S" => "short".to_string(),
        "C" => "char".to_string(),
        "I" => "int".to_string(),
        "J" => "long".to_string(),
        "F" => "float".to_string(),
        "D" => "double".to_string(),
        obj if obj.starts_with('L') => obj
            .trim_start_matches('L')
            .trim_end_matches(';')
            .replace('/', "."),
        other => other.to_string(),
    };
    let mut out = base;
    for _ in 0..dims {
        out.push_str("[]");
    }
    out
}

pub fn simple_name(java_type_name: &str) -> String {
    java_type_name
        .rsplit('.')
        .next()
        .unwrap_or(java_type_name)
        .to_string()
}

pub fn is_primitive(java_type_name: &str) -> bool {
    matches!(
        java_type_name,
        "void" | "boolean" | "byte" | "short" | "char" | "int" | "long" | "float" | "double"
    )
}
