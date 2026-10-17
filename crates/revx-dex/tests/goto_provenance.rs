use revx_analysis::ssa::{BlockId, CfgBlock, Operand, SsaInstruction, SsaOp, SsaValueId};
use revx_dex::census::{self, CENSUS_SCHEMA_VERSION, FinalGotoProvenance};
use revx_dex::exception::{ExceptionRegion, HandlerKind, HandlerRef};
use revx_dex::lift::{LiftOutput, lift_method_to_ssa};
use revx_dex::region::{StructuringMode, structure_lifted};
use revx_dex::{CodeItem, DexFile};

fn empty_dex() -> DexFile {
    let mut bytes = vec![0; 0x70];
    bytes[..8].copy_from_slice(b"dex\n039\0");
    DexFile::parse(bytes).unwrap()
}

fn fixture(ops: Vec<Vec<SsaOp>>) -> (DexFile, LiftOutput) {
    let dex = empty_dex();
    let code = CodeItem {
        registers_size: 0,
        ins_size: 0,
        outs_size: 0,
        tries_size: 0,
        debug_info_off: 0,
        insns: vec![0x000e],
        tries: vec![],
    };
    let mut out = lift_method_to_ssa(&dex, &code, 0);
    out.func.values.clear();
    out.func.cfg.blocks.clear();
    out.func.cfg.preds = vec![vec![]; ops.len()];
    out.func.cfg.succs = vec![vec![]; ops.len()];
    out.func.next_value = 0;
    for (index, ops) in ops.into_iter().enumerate() {
        let block = BlockId(index as u32);
        let mut insts = vec![];
        for op in ops {
            let id = SsaValueId(out.func.values.len() as u32);
            let successors = match &op {
                SsaOp::Branch {
                    true_block,
                    false_block,
                    ..
                } => vec![*true_block, *false_block],
                SsaOp::Jump { target } => vec![*target],
                _ => vec![],
            };
            for target in successors {
                out.func.cfg.succs[index].push(target);
                out.func.cfg.preds[target.0 as usize].push(block);
            }
            out.func.values.push(SsaInstruction {
                id,
                op,
                source_addr: index as u64,
                block,
            });
            insts.push(id);
            out.func.next_value = out.func.values.len() as u32;
        }
        out.func.cfg.blocks.push(CfgBlock {
            id: block,
            start_addr: index as u64,
            end_addr: index as u64 + 1,
            insts,
            phis: vec![],
        });
    }
    (dex, out)
}

fn branch(yes: u32, no: u32) -> SsaOp {
    SsaOp::Branch {
        cond: Operand::Symbol("choice".into()),
        true_block: BlockId(yes),
        false_block: BlockId(no),
    }
}

fn call(name: &str) -> SsaOp {
    SsaOp::Call {
        target: Operand::Symbol(format!("@s:LTrace;->{name}()V")),
        args: vec![],
    }
}

fn switch_op() -> SsaOp {
    SsaOp::Call {
        target: Operand::Symbol("__switch".into()),
        args: vec![Operand::Symbol("key".into())],
    }
}

fn connect(out: &mut LiftOutput, from: u32, to: u32) {
    let from = BlockId(from);
    let to = BlockId(to);
    if !out.func.cfg.succs[from.0 as usize].contains(&to) {
        out.func.cfg.succs[from.0 as usize].push(to);
    }
    if !out.func.cfg.preds[to.0 as usize].contains(&from) {
        out.func.cfg.preds[to.0 as usize].push(from);
    }
}

fn structured(dex: &DexFile, out: &LiftOutput) -> revx_dex::region::RegionResult {
    let info = revx_dex::render::build_try_info(dex, &[]);
    structure_lifted(dex, &info, out, StructuringMode::Auto).0
}

fn attributed(dex: &DexFile, out: &LiftOutput) -> census::FinalGotoScan {
    let result = structured(dex, out);
    let mut scan = census::count_final_gotos(&result.pseudocode);
    census::attribute_final_gotos(&mut scan, out);
    scan
}

fn two_exits_merge_outside() -> (DexFile, LiftOutput) {
    fixture(vec![
        vec![call("entry"), branch(1, 3)],
        vec![call("head"), branch(2, 3)],
        vec![call("body"), branch(1, 4)],
        vec![call("left"), SsaOp::Jump { target: BlockId(5) }],
        vec![call("right"), SsaOp::Jump { target: BlockId(5) }],
        vec![call("join"), SsaOp::Return { value: None }],
    ])
}

fn protected_multi() -> (DexFile, LiftOutput) {
    let (mut dex, mut out) = fixture(vec![
        vec![call("entry"), branch(1, 2)],
        vec![call("a"), branch(2, 3)],
        vec![call("b"), branch(1, 3)],
        vec![call("exit"), SsaOp::Return { value: None }],
    ]);
    dex.types.push("Ljava/lang/Exception;".into());
    out.exception_flow.regions.push(ExceptionRegion {
        try_index: 0,
        start: 1,
        insn_count: 1,
        end: Some(2),
        valid_range: true,
        protected_blocks: vec![BlockId(1)],
        handlers: vec![HandlerRef {
            kind: HandlerKind::Typed { type_idx: 0 },
            addr: 3,
            block: Some(BlockId(3)),
            ordinary_entry_reachable: false,
        }],
    });
    (dex, out)
}

fn switch_fallthrough() -> (DexFile, LiftOutput) {
    let (dex, mut out) = fixture(vec![
        vec![switch_op()],
        vec![call("a"), SsaOp::Jump { target: BlockId(2) }],
        vec![call("b"), SsaOp::Jump { target: BlockId(3) }],
        vec![call("join"), SsaOp::Return { value: None }],
    ]);
    connect(&mut out, 0, 1);
    connect(&mut out, 0, 2);
    out.switch_cases.insert(
        BlockId(0),
        vec![
            ("0".into(), BlockId(1)),
            ("1".into(), BlockId(2)),
            ("default".into(), BlockId(2)),
        ],
    );
    (dex, out)
}

fn handler_target_lift() -> LiftOutput {
    let (_dex, mut out) = fixture(vec![
        vec![call("body"), SsaOp::Return { value: None }],
        vec![
            SsaOp::Call {
                target: Operand::Symbol("__exception".into()),
                args: vec![],
            },
            SsaOp::Return { value: None },
        ],
    ]);
    out.exception_flow.regions.push(ExceptionRegion {
        try_index: 0,
        start: 0,
        insn_count: 1,
        end: Some(1),
        valid_range: true,
        protected_blocks: vec![BlockId(0)],
        handlers: vec![HandlerRef {
            kind: HandlerKind::Typed { type_idx: 0 },
            addr: 1,
            block: Some(BlockId(1)),
            ordinary_entry_reachable: false,
        }],
    });
    out
}

fn two_return_exits() -> (DexFile, LiftOutput) {
    fixture(vec![
        vec![call("head"), SsaOp::Jump { target: BlockId(1) }],
        vec![call("body"), branch(2, 3)],
        vec![call("more"), branch(0, 4)],
        vec![call("left"), SsaOp::Return { value: None }],
        vec![call("right"), SsaOp::Return { value: None }],
    ])
}

#[test]
fn census_schema_is_v7() {
    assert_eq!(CENSUS_SCHEMA_VERSION, 7);
}

#[test]
fn dangling_goto_stays_unknown() {
    let mut scan = census::count_final_gotos("goto L99;");
    let (_dex, out) = fixture(vec![vec![SsaOp::Return { value: None }]]);
    census::attribute_final_gotos(&mut scan, &out);
    assert_eq!(scan.count, 1);
    assert_eq!(scan.sites[0].provenance, FinalGotoProvenance::Unknown);
}

#[test]
fn two_exit_merge_gotos_are_unstructured() {
    let (dex, out) = two_exits_merge_outside();
    let scan = attributed(&dex, &out);
    assert!(scan.count > 0, "expected leftover gotos");
    assert!(
        scan.sites
            .iter()
            .all(|site| site.provenance == FinalGotoProvenance::Unstructured)
    );
}

#[test]
fn multi_entry_scc_gotos_are_irreducible_loop() {
    let (dex, out) = protected_multi();
    let scan = attributed(&dex, &out);
    assert!(scan.count > 0, "expected leftover gotos");
    assert!(
        scan.sites
            .iter()
            .all(|site| site.provenance == FinalGotoProvenance::IrreducibleLoop)
    );
}

#[test]
fn switch_case_target_gotos_are_switch() {
    let (_dex, out) = switch_fallthrough();
    let mut scan = census::count_final_gotos("goto L2;");
    census::attribute_final_gotos(&mut scan, &out);
    assert_eq!(scan.sites[0].provenance, FinalGotoProvenance::Switch);
}

#[test]
fn handler_block_target_is_handler() {
    let out = handler_target_lift();
    let mut scan = census::count_final_gotos("goto L1;");
    census::attribute_final_gotos(&mut scan, &out);
    assert_eq!(scan.sites[0].provenance, FinalGotoProvenance::Handler);
}

#[test]
fn structured_region_method_has_no_unknown_gotos() {
    let (dex, out) = two_return_exits();
    let result = structured(&dex, &out);
    assert!(result.used_region_path);
    let scan = attributed(&dex, &out);
    assert_eq!(scan.count, 0);
    assert!(
        scan.sites
            .iter()
            .all(|site| site.provenance != FinalGotoProvenance::Unknown)
    );
}

#[test]
fn reason_counts_sum_to_final_goto_count() {
    let (dex, out) = protected_multi();
    let scan = attributed(&dex, &out);
    let unknown = scan
        .sites
        .iter()
        .filter(|site| site.provenance == FinalGotoProvenance::Unknown)
        .count();
    assert_eq!(scan.count, scan.sites.len());
    assert!(scan.count > 0);
    assert_ne!(unknown, scan.count);
}
