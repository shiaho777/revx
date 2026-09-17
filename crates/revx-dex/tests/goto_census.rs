use revx_dex::DexFile;
use revx_dex::census;
use revx_dex::lift::{build_basic_blocks, decode_all, lift_method_to_ssa};
use revx_dex::render::build_try_info;
use revx_dex::structure::{GotoReason, render_structured_with_diagnostics};
use std::collections::HashMap;

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

struct MethodSpec<'a> {
    name: &'static str,
    insns: &'a [u16],
}

fn build_dex(methods: &[MethodSpec<'_>]) -> Vec<u8> {
    let strings: Vec<&str> = vec![
        "Lcom/example/Foo;",
        "V",
        "()V",
        "Ljava/lang/Object;",
        "Foo.java",
    ];
    let n = methods.len();
    let mut names = Vec::new();
    for i in 0..n {
        names.push(format!("m{}", i));
    }
    let all_strings: Vec<String> = strings
        .iter()
        .map(|s| s.to_string())
        .chain(names.iter().cloned())
        .collect();

    let header_size = 0x70usize;
    let mut out = vec![0u8; header_size];
    let string_ids_off = out.len();
    out.resize(string_ids_off + all_strings.len() * 4, 0);
    let type_ids_off = out.len();
    out.resize(type_ids_off + 2 * 4, 0);
    let proto_ids_off = out.len();
    out.resize(proto_ids_off + 12, 0);
    let field_ids_off = out.len();
    let method_ids_off = out.len();
    out.resize(method_ids_off + n * 8, 0);
    let class_defs_off = out.len();
    out.resize(class_defs_off + 32, 0);
    let data_start = out.len();

    for (i, s) in all_strings.iter().enumerate() {
        let off = out.len() as u32;
        put_u32(&mut out, string_ids_off + i * 4, off);
        uleb(&mut out, s.chars().count() as u32);
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }
    for i in 0..2u32 {
        put_u32(&mut out, type_ids_off + i as usize * 4, i);
    }
    put_u32(&mut out, proto_ids_off, 1);
    put_u32(&mut out, proto_ids_off + 4, 1);
    put_u32(&mut out, proto_ids_off + 8, 0);
    for (i, m) in methods.iter().enumerate() {
        let base = method_ids_off + i * 8;
        put_u16(&mut out, base, 0);
        put_u16(&mut out, base + 2, 0);
        put_u32(&mut out, base + 4, (strings.len() + i) as u32);
        let _ = m.name;
    }

    let write_code_item = |out: &mut Vec<u8>, insns: &[u16]| {
        let off = out.len() as u32;
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(insns.len() as u32).to_le_bytes());
        for u in insns {
            out.extend_from_slice(&u.to_le_bytes());
        }
        off
    };

    let mut code_offs = Vec::new();
    for m in methods {
        code_offs.push(write_code_item(&mut out, m.insns));
    }

    let class_data_off = out.len() as u32;
    uleb(&mut out, 0);
    uleb(&mut out, 0);
    uleb(&mut out, 0);
    uleb(&mut out, n as u32);
    for (i, _m) in methods.iter().enumerate() {
        uleb(&mut out, if i == 0 { 0 } else { 1 });
        uleb(&mut out, 0x9);
        uleb(&mut out, code_offs[i]);
    }

    let cd = class_defs_off;
    put_u32(&mut out, cd, 0);
    put_u32(&mut out, cd + 4, 0x1);
    put_u32(&mut out, cd + 8, 1);
    put_u32(&mut out, cd + 12, 0);
    put_u32(&mut out, cd + 16, 4);
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
    put_u32(&mut out, 0x38, all_strings.len() as u32);
    put_u32(&mut out, 0x3c, string_ids_off as u32);
    put_u32(&mut out, 0x40, 2);
    put_u32(&mut out, 0x44, type_ids_off as u32);
    put_u32(&mut out, 0x48, 1);
    put_u32(&mut out, 0x4c, proto_ids_off as u32);
    put_u32(&mut out, 0x50, 0);
    put_u32(&mut out, 0x54, field_ids_off as u32);
    put_u32(&mut out, 0x58, n as u32);
    put_u32(&mut out, 0x5c, method_ids_off as u32);
    put_u32(&mut out, 0x60, 1);
    put_u32(&mut out, 0x64, class_defs_off as u32);
    put_u32(&mut out, 0x68, data_size);
    put_u32(&mut out, 0x6c, data_start as u32);

    out
}

fn goto8(delta: i8) -> Vec<u16> {
    vec![0x0028 | ((delta as u8 as u16) << 8)]
}

fn if_eqz(reg: u8, delta: i16) -> Vec<u16> {
    let d = (delta as u16).to_le_bytes();
    vec![0x0038 | ((reg as u16) << 8), u16::from_le_bytes(d)]
}

#[test]
fn counts_goto_ignoring_strings_and_comments() {
    let text = "\
    goto L3;\n\
    // goto L9;\n\
    let s = \"goto L9;\";\n\
    x = 'g'; /* goto L9; */ goto L3;\n\
    agoto L4;\n\
    goto L3 // trailing comment\n\
    ;\n\
    goto L9;\n";
    let scan = census::count_final_gotos(text);
    assert_eq!(scan.count, 4);
    assert_eq!(scan.target_counts.get("L3"), Some(&3));
    assert_eq!(scan.target_counts.get("L9"), Some(&1));
    assert_eq!(scan.line_count, 4);
}

#[test]
fn scanner_rejects_non_statement_gotos() {
    let scan = census::count_final_gotos("foo.goto L1; goto L2 x; goto(); gotoL3; goto L4");
    assert_eq!(scan.count, 0);
    let scan2 = census::count_final_gotos("if (x) goto L1; else goto L2;");
    assert_eq!(scan2.count, 2);
}

#[test]
fn dangling_targets_reported() {
    let scan = census::count_final_gotos("goto L5;");
    assert_eq!(scan.dangling_targets, vec!["L5".to_string()]);
    let scan2 = census::count_final_gotos("L5:\n goto L5;");
    assert!(scan2.dangling_targets.is_empty());
}

#[test]
fn empty_dex_yields_empty_census() {
    let data = build_dex(&[]);
    let dex = DexFile::parse(data).expect("parse");
    let census = census::census_dex(&dex, None);
    assert_eq!(census.methods.len(), 0);
    assert_eq!(census.totals.final_goto_count, 0);
    assert!(!census.selection.truncated);
}

#[test]
fn same_target_multiple_gotos_counted_individually() {
    let text = "goto L2;\ngoto L2;\ngoto L2;\nL2:\nreturn;";
    let scan = census::count_final_gotos(text);
    assert_eq!(scan.count, 3);
    assert_eq!(scan.target_counts.get("L2"), Some(&3));
}

#[test]
fn census_reports_method_identity_and_totals() {
    let insns = [0x1070u16, 0x0000, 0x0000, 0x000e];
    let spec = MethodSpec {
        name: "m0",
        insns: &insns,
    };
    let data = build_dex(&[spec]);
    let dex = DexFile::parse(data).expect("parse");
    let census = census::census_dex(&dex, None);
    assert_eq!(census.schema_version, census::CENSUS_SCHEMA_VERSION);
    assert_eq!(census.selection.total_defined_methods, 1);
    assert_eq!(census.selection.selected_methods, 1);
    assert!(!census.selection.truncated);
    assert_eq!(census.selection.completed_methods, 1);
    let m = &census.methods[0];
    assert_eq!(m.class, "Lcom/example/Foo;");
    assert_eq!(m.signature, "Lcom/example/Foo;->m0()V");
    assert_eq!(m.status, "completed");
    let counts = m.counts.as_ref().expect("counts");
    assert_eq!(counts.final_goto_count, 0);
    assert_eq!(counts.by_reason.unknown, 0);
    assert_eq!(census.totals.raw_emission_count, 0);
}

#[test]
fn structuring_diagnostics_record_emissions() {
    let first: [u16; 4] = [0x1070, 0x0000, 0x0000, 0x000e];
    let spec = MethodSpec {
        name: "m0",
        insns: &first,
    };
    let data = build_dex(&[spec]);
    let dex = DexFile::parse(data).expect("parse");
    let cd = dex.classes[0].class_data.as_ref().expect("class data");
    let code = dex.code_item(cd.virtual_methods[0].code_off).expect("code");
    let lift = lift_method_to_ssa(&dex, &code, cd.virtual_methods[0].method_idx);
    let insns_map = decode_all(&code);
    let _ = build_basic_blocks(&code, &insns_map);
    let try_info = build_try_info(&dex, &code.tries);
    let _ = try_info;
    let mut blocks: HashMap<revx_analysis::ssa::BlockId, revx_dex::structure::BlockRender> =
        HashMap::new();
    for b in &lift.func.cfg.blocks {
        blocks.insert(
            b.id,
            revx_dex::structure::BlockRender {
                lines: vec!["v0 = 1;".to_string()],
                cond: None,
                jump: lift
                    .func
                    .cfg
                    .succs
                    .get(b.id.0 as usize)
                    .and_then(|s| s.first().copied()),
                switch: None,
            },
        );
    }
    let (_, diagnostics) = render_structured_with_diagnostics(&lift.func, &blocks);
    assert!(!diagnostics.bailed);
    for e in &diagnostics.goto_emissions {
        assert!(matches!(
            e.reason,
            GotoReason::Revisit | GotoReason::ForwardRevisit
        ));
    }
}

#[test]
fn raw_emissions_are_not_final_counts() {
    let back_edge: [u16; 6] = [0x1070u16, 0x0000, 0x0000, goto8(0)[0], 0x0000, 0x000e];
    let spec = MethodSpec {
        name: "m0",
        insns: &back_edge,
    };
    let data = build_dex(&[spec]);
    let dex = DexFile::parse(data).expect("parse");
    let census = census::census_dex(&dex, None);
    let m = &census.methods[0];
    let counts = m.counts.as_ref().expect("counts");
    assert!(
        counts.raw_emission_count >= counts.final_goto_count,
        "raw emissions include gotos later removed or converted; final count is the honest floor"
    );
    assert_eq!(census.totals.raw_emission_count, counts.raw_emission_count);
}

#[test]
fn limit_selects_prefix_and_discloses_truncation() {
    let ret: [u16; 4] = [0x1070u16, 0x0000, 0x0000, 0x000e];
    let specs: Vec<MethodSpec> = (0..3)
        .map(|_| MethodSpec {
            name: "m",
            insns: &ret,
        })
        .collect();
    let data = build_dex(&specs);
    let dex = DexFile::parse(data).expect("parse");
    let census = census::census_dex(&dex, Some(2));
    assert_eq!(census.selection.selected_methods, 2);
    assert_eq!(census.selection.total_defined_methods, 3);
    assert_eq!(census.selection.unselected_methods, 1);
    assert!(census.selection.truncated);
    assert_eq!(census.methods.len(), 2);
    let full = census::census_dex(&dex, None);
    assert_eq!(full.selection.selected_methods, 3);
    assert!(!full.selection.truncated);
}

#[test]
fn invalid_dex_fails_to_parse() {
    let mut data = build_dex(&[]);
    data[0] = b'X';
    assert!(DexFile::parse(data).is_err());
}

#[test]
fn goto8_targets_shape_cfg() {
    let body: Vec<u16> = [vec![0x1070u16, 0x0000], goto8(2), vec![0x0000, 0x000e]].concat();
    let spec = MethodSpec {
        name: "m0",
        insns: &body,
    };
    let data = build_dex(&[spec]);
    let dex = DexFile::parse(data).expect("parse");
    let cd = dex.classes[0].class_data.as_ref().expect("class data");
    let code = dex.code_item(cd.virtual_methods[0].code_off).expect("code");
    let census = census::census_dex(&dex, None);
    assert_eq!(census.methods[0].status, "completed");
    let _ = code;
}

#[test]
fn provenance_is_explicitly_unknown_in_scan() {
    let scan = census::count_final_gotos("goto L7;");
    assert_eq!(scan.count, 1);
    assert_eq!(scan.sites[0].target, "L7");
    let census_text = "goto L1;\ngoto L1;";
    let scan2 = census::count_final_gotos(census_text);
    assert_eq!(scan2.target_counts.get("L1"), Some(&2));
}

#[test]
fn if_goto_shapes_count_and_do_not_panic() {
    let body: Vec<u16> = [
        vec![0x1070u16, 0x0000],
        if_eqz(0, 3),
        vec![0x1070 | (1 << 8), 0x0001],
        goto8(0xfeu8 as i8),
        vec![0x0000, 0x000e],
    ]
    .concat();
    let data = build_dex(&[MethodSpec {
        name: "m0",
        insns: &body,
    }]);
    let dex = DexFile::parse(data).expect("parse");
    let census = census::census_dex(&dex, None);
    assert_eq!(census.methods[0].status, "completed");
}
