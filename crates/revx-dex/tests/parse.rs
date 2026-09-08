use revx_dex::DexFile;
use revx_dex::insns::{decode_insn, disassemble_method};

fn put_u16(out: &mut [u8], off: usize, v: u16) {
    out[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(out: &mut [u8], off: usize, v: u32) {
    out[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn uleb(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn build_synthetic_dex() -> Vec<u8> {
    let strings: Vec<&str> = vec![
        "Lcom/example/Foo;",
        "bar",
        "()V",
        "V",
        "Ljava/lang/Object;",
        "Foo.java",
        "Ljava/lang/StringBuilder;",
        "append",
        "(Ljava/lang/String;)Ljava/lang/StringBuilder;",
        "<init>",
        "hello",
    ];
    let types: Vec<u32> = vec![0, 3, 4, 6, 3];
    let protos: Vec<(u32, u32, Vec<u32>)> = vec![(2, 1, vec![]), (8, 6, vec![0])];
    let methods: Vec<(u32, u32, u32)> = vec![(0, 0, 9), (0, 0, 1), (3, 1, 7)];

    let header_size = 0x70usize;
    let mut out = vec![0u8; header_size];
    let string_ids_off = out.len();
    out.resize(string_ids_off + strings.len() * 4, 0);
    let type_ids_off = out.len();
    out.resize(type_ids_off + types.len() * 4, 0);
    let proto_ids_off = out.len();
    out.resize(proto_ids_off + protos.len() * 12, 0);
    let field_ids_off = out.len();
    let method_ids_off = out.len();
    out.resize(method_ids_off + methods.len() * 8, 0);
    let class_defs_off = out.len();
    out.resize(class_defs_off + 32, 0);
    let data_start = out.len();

    for (i, s) in strings.iter().enumerate() {
        let off = out.len() as u32;
        put_u32(&mut out, string_ids_off + i * 4, off);
        uleb(&mut out, s.chars().count() as u32);
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }
    for (i, t) in types.iter().enumerate() {
        put_u32(&mut out, type_ids_off + i * 4, *t);
    }
    for (i, (shorty, ret, params)) in protos.iter().enumerate() {
        let base = proto_ids_off + i * 12;
        put_u32(&mut out, base, *shorty);
        put_u32(&mut out, base + 4, *ret);
        if params.is_empty() {
            put_u32(&mut out, base + 8, 0);
        } else {
            let poff = out.len() as u32;
            put_u32(&mut out, base + 8, poff);
            out.extend_from_slice(&(params.len() as u32).to_le_bytes());
            for p in params {
                out.extend_from_slice(&(*p as u16).to_le_bytes());
            }
        }
    }
    for (i, (class, proto, name)) in methods.iter().enumerate() {
        let base = method_ids_off + i * 8;
        put_u16(&mut out, base, *class as u16);
        put_u16(&mut out, base + 2, *proto as u16);
        put_u32(&mut out, base + 4, *name);
    }

    let write_code_item =
        |out: &mut Vec<u8>, registers: u16, ins: u16, outs: u16, insns: &[u16]| {
            let off = out.len() as u32;
            out.extend_from_slice(&registers.to_le_bytes());
            out.extend_from_slice(&ins.to_le_bytes());
            out.extend_from_slice(&outs.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(insns.len() as u32).to_le_bytes());
            for u in insns {
                out.extend_from_slice(&u.to_le_bytes());
            }
            off
        };

    let init_code: [u16; 4] = [0x1070, 0x0000, 0x0000, 0x000e];
    let init_item_off = write_code_item(&mut out, 1, 1, 1, &init_code);
    let bar_code: [u16; 7] = [0x001a, 0x000a, 0x206e, 0x0002, 0x0010, 0x000c, 0x000e];
    let bar_item_off = write_code_item(&mut out, 2, 1, 1, &bar_code);

    let class_data_off = out.len() as u32;
    uleb(&mut out, 0);
    uleb(&mut out, 0);
    uleb(&mut out, 2);
    uleb(&mut out, 0);
    uleb(&mut out, 0);
    uleb(&mut out, 0x9);
    uleb(&mut out, init_item_off);
    uleb(&mut out, 1);
    uleb(&mut out, 0x1);
    uleb(&mut out, bar_item_off);

    let cd = class_defs_off;
    put_u32(&mut out, cd, 0);
    put_u32(&mut out, cd + 4, 0x1);
    put_u32(&mut out, cd + 8, 4);
    put_u32(&mut out, cd + 12, 0);
    put_u32(&mut out, cd + 16, 5);
    put_u32(&mut out, cd + 20, 0);
    put_u32(&mut out, cd + 24, class_data_off);
    put_u32(&mut out, cd + 28, 0);

    out[0..4].copy_from_slice(&[0x64, 0x65, 0x78, 0x0a]);
    out[4..7].copy_from_slice(&[0x30, 0x33, 0x39]);
    out[7] = 0;
    let file_size = out.len() as u32;
    let data_size = (out.len() - data_start) as u32;
    put_u32(&mut out, 0x20, file_size);
    put_u32(&mut out, 0x24, header_size as u32);
    put_u32(&mut out, 0x28, 0x12345678);
    put_u32(&mut out, 0x38, strings.len() as u32);
    put_u32(&mut out, 0x3c, string_ids_off as u32);
    put_u32(&mut out, 0x40, types.len() as u32);
    put_u32(&mut out, 0x44, type_ids_off as u32);
    put_u32(&mut out, 0x48, protos.len() as u32);
    put_u32(&mut out, 0x4c, proto_ids_off as u32);
    put_u32(&mut out, 0x50, 0);
    put_u32(&mut out, 0x54, field_ids_off as u32);
    put_u32(&mut out, 0x58, methods.len() as u32);
    put_u32(&mut out, 0x5c, method_ids_off as u32);
    put_u32(&mut out, 0x60, 1);
    put_u32(&mut out, 0x64, class_defs_off as u32);
    put_u32(&mut out, 0x68, data_size);
    put_u32(&mut out, 0x6c, data_start as u32);

    out
}

#[test]
fn parses_synthetic_dex() {
    let data = build_synthetic_dex();
    let dex = DexFile::parse(data).expect("parse synthetic dex");
    assert_eq!(dex.strings.len(), 11);
    assert_eq!(dex.methods.len(), 3);
    assert_eq!(dex.classes.len(), 1);
    assert_eq!(dex.classes[0].class, "Lcom/example/Foo;");
    let data_cd = dex.classes[0].class_data.as_ref().expect("class data");
    assert_eq!(data_cd.direct_methods.len(), 2);
    let sig = dex.method_signature(data_cd.direct_methods[1].method_idx);
    assert!(sig.contains("bar"), "method sig: {sig}");
}

#[test]
fn disassembles_synthetic_method() {
    let data = build_synthetic_dex();
    let dex = DexFile::parse(data).expect("parse");
    let cd = dex.classes[0].class_data.as_ref().expect("class data");
    let bar = &cd.direct_methods[1];
    let code = dex.code_item(bar.code_off).expect("code item");
    let dis = disassemble_method(&dex, &code.insns);
    let text = dis.lines.join("\n");
    assert!(text.contains("const-string v0, \"hello\""), "{text}");
    assert!(text.contains("invoke-virtual {v0, v1}"), "{text}");
    assert!(text.contains("move-result-object v0"), "{text}");
    assert!(text.contains("return-void"), "{text}");
}

#[test]
fn decodes_all_formats_without_panic() {
    let data = build_synthetic_dex();
    let dex = DexFile::parse(data).expect("parse");
    for op in 0u16..=0xff {
        let units = [op | 0x1100, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006];
        let _ = decode_insn(&dex, &units, 0);
    }
}

#[test]
fn parses_real_classes_dex_when_corpus_set() {
    let Ok(path) = std::env::var("REVX_DEX_CORPUS") else {
        eprintln!("skipping: REVX_DEX_CORPUS not set");
        return;
    };
    let data = std::fs::read(&path).expect("read corpus");
    let dex = DexFile::parse(data).expect("parse real dex");
    assert!(!dex.classes.is_empty());
    let mut with_code = 0usize;
    let mut total_insns = 0usize;
    for class in &dex.classes {
        let Some(cd) = &class.class_data else {
            continue;
        };
        for m in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
            if m.code_off == 0 {
                continue;
            }
            let code = dex.code_item(m.code_off).expect("code item");
            with_code += 1;
            total_insns += code.insns.len();
            let _ = disassemble_method(&dex, &code.insns);
        }
    }
    eprintln!(
        "corpus: classes={} with_code={} total_insns={}",
        dex.classes.len(),
        with_code,
        total_insns
    );
    assert!(with_code > 0);
}
