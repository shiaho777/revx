//! JNI cross-layer linkage: native method declarations in DEX and the
//! mangled symbol names the JNI linker resolves them to.

use crate::{ClassData, DexFile};
use std::collections::HashMap;

pub struct NativeMethod {
    pub class: String,
    pub method: String,
    pub signature: String,
    pub mangled: String,
    pub mangled_overload: Option<String>,
}

fn escape_jni(part: &str) -> String {
    let mut out = String::with_capacity(part.len() + 8);
    for c in part.chars() {
        match c {
            '_' => out.push_str("_1"),
            ';' => out.push_str("_2"),
            '[' => out.push_str("_3"),
            '.' => out.push_str("_4"),
            '/' => out.push('_'),
            c if !c.is_ascii_alphanumeric() && c != '$' => {
                out.push_str(&format!("_{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn mangle_args(sig_params: &[String]) -> String {
    let mut out = String::new();
    for p in sig_params {
        let mut depth = 0;
        let b = p.as_bytes();
        let mut i = 0;
        while i < b.len() && b[i] == b'[' {
            depth += 1;
            i += 1;
        }
        for _ in 0..depth {
            out.push_str("_3");
        }
        let base = &p[i..];
        match base {
            "V" => out.push('V'),
            "Z" => out.push('Z'),
            "B" => out.push('B'),
            "S" => out.push('S'),
            "C" => out.push('C'),
            "I" => out.push('I'),
            "J" => out.push('J'),
            "F" => out.push('F'),
            "D" => out.push('D'),
            obj => {
                let inner = obj.trim_start_matches('L').trim_end_matches(';');
                let escaped = inner.replace('_', "_1").replace('/', "_");
                out.push('L');
                out.push_str(&escaped);
                out.push_str("_2");
            }
        }
    }
    out
}

pub fn native_methods_in_class(
    dex: &DexFile,
    cd: &ClassData,
    class_desc: &str,
) -> Vec<NativeMethod> {
    let mut natives = Vec::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for m in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
        if m.access_flags & 0x0100 != 0 {
            let name = dex
                .methods
                .get(m.method_idx as usize)
                .map(|x| x.name.clone())
                .unwrap_or_default();
            *counts.entry(name).or_insert(0) += 1;
        }
    }
    for m in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
        if m.access_flags & 0x0100 == 0 {
            continue;
        }
        let Some(mi) = dex.methods.get(m.method_idx as usize) else {
            continue;
        };
        let (proto_params, proto_ret) = dex
            .protos
            .get(mi.proto as usize)
            .map(|p| (p.parameters.clone(), p.return_type.clone()))
            .unwrap_or_default();
        let sig = format!("({}){}", proto_params.join(""), proto_ret);
        let class_path = class_desc.trim_start_matches('L').trim_end_matches(';');
        let mangled = format!("Java_{}_{}", escape_jni(class_path), escape_jni(&mi.name));
        let mangled_overload = if counts.get(&mi.name).copied().unwrap_or(0) > 1 {
            Some(format!("{}__{}", mangled, mangle_args(&proto_params)))
        } else {
            None
        };
        natives.push(NativeMethod {
            class: class_desc.to_string(),
            method: mi.name.clone(),
            signature: sig,
            mangled,
            mangled_overload,
        });
    }
    natives
}

pub fn all_native_methods(dex: &DexFile) -> Vec<NativeMethod> {
    let mut out = Vec::new();
    for class in &dex.classes {
        let Some(cd) = &class.class_data else {
            continue;
        };
        out.extend(native_methods_in_class(dex, cd, &class.class));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mangles_simple_native() {
        assert_eq!(escape_jni("com/example/Foo"), "com_example_Foo");
        assert_eq!(escape_jni("com/example/Bar$Baz"), "com_example_Bar$Baz");
    }

    #[test]
    fn mangles_args() {
        assert_eq!(mangle_args(&[]), "");
        assert_eq!(mangle_args(&["I".to_string()]), "I");
        assert_eq!(
            mangle_args(&["Ljava/lang/String;".to_string()]),
            "Ljava_lang_String_2"
        );
        assert_eq!(mangle_args(&["[I".to_string()]), "_3I");
        assert_eq!(
            mangle_args(&["[Ljava/lang/Object;".to_string()]),
            "_3Ljava_lang_Object_2"
        );
    }

    #[test]
    fn builds_mangled_symbol() {
        let cases = vec![
            (
                "Lcom/example/Native;",
                "foo",
                Vec::<String>::new(),
                "Java_com_example_Native_foo",
            ),
            (
                "La/b/C;",
                "doIt",
                vec!["I".to_string()],
                "Java_a_b_C_doIt__I",
            ),
            (
                "Lx/y/Z_$inner;",
                "run",
                Vec::<String>::new(),
                "Java_x_y_Z_1$inner_run",
            ),
        ];
        for (class, method, params, expected) in cases {
            let class_path = class.trim_start_matches('L').trim_end_matches(';');
            let mangled = format!("Java_{}_{}", escape_jni(class_path), escape_jni(method));
            let full = if params.is_empty() {
                mangled
            } else {
                format!("{}__{}", mangled, mangle_args(&params))
            };
            assert_eq!(full, expected, "class={class} method={method}");
        }
    }
}
