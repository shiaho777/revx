use revx_analysis::ssa::{BlockId, Operand, SsaOp};
use revx_dex::DexFile;
use revx_dex::census::{self, CENSUS_SCHEMA_VERSION};
use revx_dex::exception::{ExceptionRegion, HandlerKind, HandlerRef};
use revx_dex::lift::lift_method_to_ssa;
use revx_dex::region::{RegionFallbackReason, StructuringMode, structure_lifted};
use std::time::{Duration, Instant};

fn ret_dex() -> Vec<u8> {
    let mut bytes = vec![0; 0x70];
    bytes[..8].copy_from_slice(b"dex\n039\0");
    bytes
}

#[derive(Clone, Copy, Debug)]
enum Expect {
    Region { min_splits: usize },
    Fallback(RegionFallbackReason),
}

struct Row {
    name: &'static str,
    expect: Expect,
}

fn classify(used: bool, splits: usize, reason: Option<RegionFallbackReason>) -> Expect {
    if used {
        Expect::Region { min_splits: splits }
    } else {
        Expect::Fallback(reason.expect("fallback reason"))
    }
}

fn matches(actual: Expect, expect: Expect) -> bool {
    match (actual, expect) {
        (Expect::Region { min_splits }, Expect::Region { min_splits: floor }) => {
            min_splits >= floor
        }
        (Expect::Fallback(left), Expect::Fallback(right)) => left == right,
        _ => false,
    }
}

#[test]
fn frozen_capability_matrix_matches_v1_acceptance() {
    let rows = [
        Row {
            name: "nested-natural-loops",
            expect: Expect::Region { min_splits: 0 },
        },
        Row {
            name: "multi-entry-loop",
            expect: Expect::Region { min_splits: 2 },
        },
        Row {
            name: "expansion-budget",
            expect: Expect::Fallback(RegionFallbackReason::Budget),
        },
        Row {
            name: "loop-exception-intersection",
            expect: Expect::Fallback(RegionFallbackReason::LoopExceptionIntersection),
        },
        Row {
            name: "try-crosses-loop",
            expect: Expect::Fallback(RegionFallbackReason::NestedOrCrossScope),
        },
        Row {
            name: "phi-irreducible",
            expect: Expect::Fallback(RegionFallbackReason::UnsupportedShape),
        },
    ];
    let started = Instant::now();
    for row in rows {
        let (used, splits, reason) = run_row(row.name);
        let actual = classify(used, splits, reason);
        assert!(
            matches(actual, row.expect),
            "{}: {actual:?} != {:?}",
            row.name,
            row.expect
        );
    }
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn census_schema_records_loop_normalization() {
    let dex = DexFile::parse(ret_dex()).unwrap();
    let census = census::census_dex(&dex, None);
    assert_eq!(census.schema_version, CENSUS_SCHEMA_VERSION);
    assert_eq!(CENSUS_SCHEMA_VERSION, 5);
    assert_eq!(census.totals.nodes_split, 0);
    assert_eq!(census.totals.loop_norm_methods, 0);
    assert_eq!(census.totals.unknown_methods, 0);
    assert_eq!(
        census.totals.final_goto_count,
        census.totals.by_reason.unknown
    );
}

fn run_row(name: &str) -> (bool, usize, Option<RegionFallbackReason>) {
    let (dex, out) = match name {
        "nested-natural-loops" => shape_nested(),
        "multi-entry-loop" => shape_multi(),
        "expansion-budget" => shape_wide(),
        "loop-exception-intersection" => shape_protected_multi(),
        "try-crosses-loop" => shape_cross_try(),
        "phi-irreducible" => shape_phi(),
        other => panic!("unknown row {other}"),
    };
    let info = revx_dex::render::build_try_info(&dex, &[]);
    let (auto, _) = structure_lifted(&dex, &info, &out, StructuringMode::Auto);
    let (legacy, _) = structure_lifted(&dex, &info, &out, StructuringMode::Legacy);
    if !auto.used_region_path {
        assert_eq!(auto.pseudocode, legacy.pseudocode, "{name}");
        assert_eq!(auto.nodes_split, 0, "{name}");
    }
    (
        auto.used_region_path,
        auto.nodes_split,
        auto.fallback_reason,
    )
}

fn call(name: &str) -> SsaOp {
    SsaOp::Call {
        target: Operand::Symbol(format!("@s:LTrace;->{name}()V")),
        args: vec![],
    }
}

fn branch(yes: u32, no: u32) -> SsaOp {
    SsaOp::Branch {
        cond: Operand::Symbol("choice".into()),
        true_block: BlockId(yes),
        false_block: BlockId(no),
    }
}

fn shape_nested() -> (DexFile, revx_dex::lift::LiftOutput) {
    build(vec![
        vec![call("outer"), branch(1, 3)],
        vec![call("inner"), branch(2, 0)],
        vec![call("body"), SsaOp::Jump { target: BlockId(1) }],
        vec![call("exit"), SsaOp::Return { value: None }],
    ])
}

fn shape_multi() -> (DexFile, revx_dex::lift::LiftOutput) {
    build(vec![
        vec![call("entry"), branch(1, 2)],
        vec![call("a"), branch(2, 3)],
        vec![call("b"), branch(1, 3)],
        vec![call("exit"), SsaOp::Return { value: None }],
    ])
}

fn shape_wide() -> (DexFile, revx_dex::lift::LiftOutput) {
    let n = revx_dex::loopnorm::DEFAULT_MAX_NEW_BLOCKS + 1;
    let exit = (n + 1) as u32;
    let mut ops = vec![vec![call("entry"), branch(1, 2)]];
    for i in 1..n {
        ops.push(vec![
            call("step"),
            SsaOp::Jump {
                target: BlockId((i + 1) as u32),
            },
        ]);
    }
    ops.push(vec![call("latch"), branch(1, exit)]);
    ops.push(vec![call("exit"), SsaOp::Return { value: None }]);
    build(ops)
}

fn shape_protected_multi() -> (DexFile, revx_dex::lift::LiftOutput) {
    let (mut dex, mut out) = shape_multi();
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

fn shape_cross_try() -> (DexFile, revx_dex::lift::LiftOutput) {
    let (mut dex, mut out) = build(vec![
        vec![call("head"), SsaOp::Jump { target: BlockId(1) }],
        vec![call("body"), branch(0, 2)],
        vec![call("exit"), SsaOp::Return { value: None }],
        vec![
            SsaOp::Call {
                target: Operand::Symbol("__exception".into()),
                args: vec![],
            },
            call("handler"),
            SsaOp::Jump { target: BlockId(2) },
        ],
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

fn shape_phi() -> (DexFile, revx_dex::lift::LiftOutput) {
    let (dex, mut out) = shape_multi();
    let v0 = out.func.cfg.blocks[0].insts[0];
    let v1 = out.func.cfg.blocks[1].insts[0];
    let v2 = out.func.cfg.blocks[2].insts[0];
    let id = revx_analysis::ssa::SsaValueId(out.func.values.len() as u32);
    out.func.values.push(revx_analysis::ssa::SsaInstruction {
        id,
        op: SsaOp::Phi {
            incoming: vec![(BlockId(0), v0), (BlockId(2), v2), (BlockId(1), v1)],
        },
        source_addr: 1,
        block: BlockId(1),
    });
    out.func.cfg.blocks[1].phis.push(id);
    (dex, out)
}

fn build(ops: Vec<Vec<SsaOp>>) -> (DexFile, revx_dex::lift::LiftOutput) {
    let dex = DexFile::parse(ret_dex()).unwrap();
    let code = revx_dex::CodeItem {
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
            let id = revx_analysis::ssa::SsaValueId(out.func.values.len() as u32);
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
            out.func.values.push(revx_analysis::ssa::SsaInstruction {
                id,
                op,
                source_addr: index as u64,
                block,
            });
            insts.push(id);
            out.func.next_value = out.func.values.len() as u32;
        }
        out.func.cfg.blocks.push(revx_analysis::ssa::CfgBlock {
            id: block,
            start_addr: index as u64,
            end_addr: index as u64 + 1,
            insts,
            phis: vec![],
        });
    }
    (dex, out)
}
