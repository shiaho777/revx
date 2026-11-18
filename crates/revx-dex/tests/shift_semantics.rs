use revx_analysis::ssa::{BinOpKind, Operand, SsaOp, constant_propagation};
use revx_dex::lift::lift_method_to_ssa;
use revx_dex::{CodeItem, DexFile};

fn empty_dex() -> DexFile {
    let mut bytes = vec![0; 0x70];
    bytes[..8].copy_from_slice(b"dex\n039\0");
    DexFile::parse(bytes).unwrap()
}

fn lift(insns: Vec<u16>) -> revx_dex::lift::LiftOutput {
    let dex = empty_dex();
    let code = CodeItem {
        registers_size: 4,
        ins_size: 0,
        outs_size: 0,
        tries_size: 0,
        debug_info_off: 0,
        insns,
        tries: vec![],
    };
    lift_method_to_ssa(&dex, &code, 0)
}

fn binop_kinds(output: &revx_dex::lift::LiftOutput) -> Vec<BinOpKind> {
    output
        .func
        .values
        .iter()
        .filter_map(|inst| match &inst.op {
            SsaOp::BinOp { kind, .. } => Some(*kind),
            _ => None,
        })
        .collect()
}

#[test]
fn dex_arithmetic_shift_maps_to_sar_and_logical_to_shr() {
    let output = lift(vec![0x0099, 0x0100, 0x009a, 0x0102, 0x000e]);
    assert_eq!(binop_kinds(&output), vec![BinOpKind::Sar, BinOpKind::Shr]);
}

fn single_binop_kind(insns: Vec<u16>) -> BinOpKind {
    let output = lift(insns);
    let kinds = binop_kinds(&output);
    assert_eq!(kinds.len(), 1, "expected one binop, got {kinds:?}");
    kinds[0]
}

#[test]
fn dex_shift_immediate_forms_follow_canonical_semantics() {
    assert_eq!(
        single_binop_kind(vec![0x00a4, 0x0100, 0x000e]),
        BinOpKind::Sar
    );
    assert_eq!(
        single_binop_kind(vec![0x00a5, 0x0100, 0x000e]),
        BinOpKind::Shr
    );
    assert_eq!(
        single_binop_kind(vec![0x00c4, 0x0100, 0x000e]),
        BinOpKind::Sar
    );
    assert_eq!(
        single_binop_kind(vec![0x00c5, 0x0100, 0x000e]),
        BinOpKind::Shr
    );
    assert_eq!(
        single_binop_kind(vec![0x00b9, 0x0100, 0x000e]),
        BinOpKind::Sar
    );
    assert_eq!(
        single_binop_kind(vec![0x00ba, 0x0100, 0x000e]),
        BinOpKind::Shr
    );
    assert_eq!(
        single_binop_kind(vec![0x00e1, 0x0100, 0x000e]),
        BinOpKind::Sar
    );
    assert_eq!(
        single_binop_kind(vec![0x00e2, 0x0100, 0x000e]),
        BinOpKind::Shr
    );
}

#[test]
fn dex_shift_decoder_uses_canonical_opcodes() {
    use revx_dex::lift::{Insn, decode_insn_structured};
    let cases: [(u16, BinOpKind); 10] = [
        (0x99, BinOpKind::Sar),
        (0x9a, BinOpKind::Shr),
        (0xa4, BinOpKind::Sar),
        (0xa5, BinOpKind::Shr),
        (0xb9, BinOpKind::Sar),
        (0xba, BinOpKind::Shr),
        (0xc4, BinOpKind::Sar),
        (0xc5, BinOpKind::Shr),
        (0xe1, BinOpKind::Sar),
        (0xe2, BinOpKind::Shr),
    ];
    for (op, expected) in cases {
        let units = [op, 0x0100, 0x0200, 0x000e];
        let (insn, _) = decode_insn_structured(&units, 0).expect("decode");
        let kind = match insn {
            Insn::Binary { kind, .. }
            | Insn::BinaryLit { kind, .. }
            | Insn::Binary2Addr { kind, .. } => kind,
            other => panic!("unexpected insn for {op:#x}: {other:?}"),
        };
        assert_eq!(kind, expected, "opcode {op:#x}");
    }
}

#[test]
fn shared_constant_folder_matches_dex_shift_semantics() {
    let output = lift(vec![0x0099, 0x0100, 0x009a, 0x0102, 0x000e]);
    let mut func = output.func.clone();
    for inst in &mut func.values {
        if let SsaOp::BinOp { kind, lhs, rhs } = &mut inst.op
            && matches!(kind, BinOpKind::Sar | BinOpKind::Shr)
        {
            *lhs = Operand::Constant(-8);
            *rhs = Operand::Constant(1);
        }
    }
    constant_propagation(&mut func);
    let folded: Vec<i64> = func
        .values
        .iter()
        .filter_map(|inst| match &inst.op {
            SsaOp::Copy {
                src: Operand::Constant(v),
            } => Some(*v),
            _ => None,
        })
        .collect();
    assert!(
        folded.contains(&-4),
        "arithmetic shift folded wrong: {folded:?}"
    );
    assert!(
        folded.contains(&9223372036854775804),
        "logical shift folded wrong: {folded:?}"
    );
}

#[test]
fn dex_shift_pseudocode_symbols_are_unchanged() {
    let dex = empty_dex();
    let code = CodeItem {
        registers_size: 4,
        ins_size: 0,
        outs_size: 0,
        tries_size: 0,
        debug_info_off: 0,
        insns: vec![0x0099, 0x0100, 0x009a, 0x0102, 0x000e],
        tries: vec![],
    };
    let result =
        revx_dex::region::structure_method(&dex, &code, 0, revx_dex::region::StructuringMode::Auto);
    assert!(
        result.pseudocode.contains(">>") && result.pseudocode.contains(">>>"),
        "pseudocode={}",
        result.pseudocode
    );
    let arithmetic_line = result
        .pseudocode
        .lines()
        .find(|line| line.contains(">>") && !line.contains(">>>"))
        .expect("arithmetic shift line");
    assert!(arithmetic_line.contains(">>"));
}
