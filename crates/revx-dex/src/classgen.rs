//! Java-style class-level rendering: class headers, fields, and method
//! signatures with access flags.

use crate::types::java_type;
use crate::{ClassDef, DexFile};

pub fn access_flags_to_java(flags: u32, is_field: bool) -> String {
    let mut parts = Vec::new();
    if flags & 0x0001 != 0 {
        parts.push("public");
    }
    if flags & 0x0002 != 0 {
        parts.push("private");
    }
    if flags & 0x0004 != 0 {
        parts.push("protected");
    }
    if flags & 0x0008 != 0 {
        parts.push("static");
    }
    if flags & 0x0010 != 0 {
        parts.push("final");
    }
    if !is_field && flags & 0x0020 != 0 {
        parts.push("synchronized");
    }
    if flags & 0x0040 != 0 {
        parts.push(if is_field { "volatile" } else { "bridge" });
    }
    if flags & 0x0080 != 0 {
        parts.push(if is_field { "transient" } else { "varargs" });
    }
    if !is_field && flags & 0x0100 != 0 {
        parts.push("native");
    }
    if !is_field && flags & 0x0400 != 0 {
        parts.push("abstract");
    }
    if !is_field && flags & 0x0800 != 0 {
        parts.push("strictfp");
    }
    if flags & 0x1000 != 0 {
        parts.push("synthetic");
    }
    if flags & 0x2000 != 0 {
        parts.push("enum");
    }
    parts.join(" ")
}

pub fn class_kind(flags: u32) -> &'static str {
    if flags & 0x0200 != 0 {
        return "interface";
    }
    if flags & 0x2000 != 0 {
        return "enum";
    }
    if flags & 0x4000 != 0 && flags & 0x0010 != 0 {
        return "annotation";
    }
    "class"
}

pub struct ClassHeader {
    pub package: String,
    pub declaration: String,
    pub fields: Vec<String>,
}

pub fn render_class_header(dex: &DexFile, class: &ClassDef) -> ClassHeader {
    let full = class.class.trim_start_matches('L').trim_end_matches(';');
    let (package, name) = match full.rfind('/') {
        Some(pos) => (full[..pos].replace('/', "."), full[pos + 1..].to_string()),
        None => (String::new(), full.to_string()),
    };
    let modifiers = access_flags_to_java(class.access_flags, false);
    let kind = class_kind(class.access_flags);
    let mut decl = String::new();
    if !modifiers.is_empty() {
        decl.push_str(&modifiers);
        decl.push(' ');
    }
    decl.push_str(kind);
    decl.push(' ');
    decl.push_str(&name);
    if let Some(sup) = &class.superclass {
        let sup_name = java_type(sup);
        if sup_name != "java.lang.Object" {
            decl.push_str(" extends ");
            decl.push_str(&sup_name);
        }
    }
    if !class.interfaces.is_empty() {
        let keyword = if kind == "interface" {
            "extends"
        } else {
            "implements"
        };
        decl.push_str(&format!(" {keyword} "));
        let ifaces: Vec<String> = class.interfaces.iter().map(|i| java_type(i)).collect();
        decl.push_str(&ifaces.join(", "));
    }
    let mut fields = Vec::new();
    if let Some(cd) = &class.class_data {
        for f in cd.static_fields.iter().chain(cd.instance_fields.iter()) {
            let Some(fd) = dex.fields.get(f.field_idx as usize) else {
                continue;
            };
            let fmods = access_flags_to_java(f.access_flags, true);
            let fty = java_type(&fd.ty);
            let prefix = if fmods.is_empty() {
                String::new()
            } else {
                format!("{fmods} ")
            };
            let static_kw = if f.access_flags & 0x0008 != 0 {
                "static "
            } else {
                ""
            };
            let combined = if fmods.contains("static") {
                format!("{prefix}{fty} {};", fd.name)
            } else {
                format!("{prefix}{static_kw}{fty} {};", fd.name)
            };
            fields.push(combined);
        }
    }
    ClassHeader {
        package,
        declaration: decl,
        fields,
    }
}

pub fn java_method_signature(
    dex: &DexFile,
    method_idx: u32,
    access_flags: u32,
    ann: &crate::annotations::ClassAnnotations,
) -> String {
    let Some(m) = dex.methods.get(method_idx as usize) else {
        return format!("method@{method_idx}");
    };
    if let Some(sig_str) = ann.method_signatures.get(&method_idx)
        && let Some(g) = crate::signature::parse_method_sig(sig_str)
    {
        let mods = access_flags_to_java(access_flags, false);
        let name = if m.name == "<init>" {
            m.class
                .trim_start_matches('L')
                .trim_end_matches(';')
                .rsplit('/')
                .next()
                .unwrap_or(&m.class)
                .to_string()
        } else {
            m.name.clone()
        };
        let params: Vec<String> = g
            .params
            .iter()
            .enumerate()
            .map(|(i, ty)| format!("{ty} p{i}"))
            .collect();
        let throws = if g.throws.is_empty() {
            String::new()
        } else {
            format!(" throws {}", g.throws.join(", "))
        };
        let prefix = if mods.is_empty() {
            String::new()
        } else {
            format!("{mods} ")
        };
        let tp = if g.type_params.is_empty() {
            String::new()
        } else {
            format!("{} ", g.type_params)
        };
        return format!(
            "{prefix}{tp}{} {name}({}){throws}",
            g.ret,
            params.join(", ")
        );
    }
    let Some(p) = dex.protos.get(m.proto as usize) else {
        return format!("{}->{}", m.class, m.name);
    };
    let mods = access_flags_to_java(access_flags, false);
    let ret = java_type(&p.return_type);
    let name = if m.name == "<init>" {
        let class = m.class.trim_start_matches('L').trim_end_matches(';');
        class.rsplit('/').next().unwrap_or(class).to_string()
    } else {
        m.name.clone()
    };
    let params: Vec<String> = p
        .parameters
        .iter()
        .enumerate()
        .map(|(i, ty)| format!("{} p{i}", java_type(ty)))
        .collect();
    let prefix = if mods.is_empty() {
        String::new()
    } else {
        format!("{mods} ")
    };
    format!("{prefix}{ret} {name}({})", params.join(", "))
}

pub fn render_java_class(
    dex: &DexFile,
    class: &ClassDef,
    method_bodies: &[(u32, u32, String)],
) -> String {
    let header = render_class_header(dex, class);
    let mut out = String::new();
    if !header.package.is_empty() {
        out.push_str(&format!("package {};\n\n", header.package));
    }
    out.push_str(&format!("{} {{\n", header.declaration));
    if !header.fields.is_empty() {
        out.push('\n');
        for f in &header.fields {
            out.push_str(&format!("    {f}\n"));
        }
    }
    let ann = crate::annotations::scan_class_annotations(dex, class);
    let mut method_idx = 0;
    if let Some(cd) = &class.class_data {
        for m in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
            let sig = java_method_signature(dex, m.method_idx, m.access_flags, &ann);
            out.push('\n');
            out.push_str(&format!("    {sig} {{\n"));
            if method_idx < method_bodies.len() {
                for line in method_bodies[method_idx].2.lines() {
                    out.push_str(&format!("    {line}\n"));
                }
            }
            out.push_str("    }\n");
            method_idx += 1;
        }
    }
    out.push_str("}\n");
    out
}
