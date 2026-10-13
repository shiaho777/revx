use revx_analysis::ssa::{BlockId, CfgBlock, Operand, SsaInstruction, SsaOp, SsaValueId};
use revx_dex::exception::{ExceptionRegion, HandlerKind, HandlerRef};
use revx_dex::lift::{LiftOutput, lift_method_to_ssa};
use revx_dex::loopnorm::{
    LoopNormBudget, LoopNormRefusal, normalize_loops, normalize_loops_with_budget,
};
use revx_dex::region::{
    Region, RegionFallbackReason, StructuringMode, build_region_tree, structure_lifted,
};
use revx_dex::{CodeItem, DexFile};
use std::collections::{BTreeSet, VecDeque};

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

fn multi_entry() -> (DexFile, LiftOutput) {
    fixture(vec![
        vec![call("entry"), branch(1, 2)],
        vec![call("a"), branch(2, 3)],
        vec![call("b"), branch(1, 3)],
        vec![call("exit"), SsaOp::Return { value: None }],
    ])
}

fn nested() -> (DexFile, LiftOutput) {
    fixture(vec![
        vec![call("outer"), branch(1, 3)],
        vec![call("inner"), branch(2, 0)],
        vec![call("body"), SsaOp::Jump { target: BlockId(1) }],
        vec![call("exit"), SsaOp::Return { value: None }],
    ])
}

#[derive(Debug, PartialEq)]
enum Control {
    Next,
    Break,
    Continue,
    Return,
}

fn block_trace(out: &LiftOutput, block: BlockId, trace: &mut Vec<String>) -> Control {
    for id in &out.func.cfg.blocks[block.0 as usize].insts {
        match &out.func.values[id.0 as usize].op {
            SsaOp::Call {
                target: Operand::Symbol(name),
                ..
            } => trace.push(name.clone()),
            SsaOp::Return { .. } => {
                trace.push("return".into());
                return Control::Return;
            }
            _ => {}
        }
    }
    Control::Next
}

fn cfg_trace(out: &LiftOutput, mut choices: VecDeque<bool>) -> Vec<String> {
    let mut current = out.func.cfg.entry;
    let mut trace = vec![];
    for _ in 0..100 {
        if block_trace(out, current, &mut trace) == Control::Return {
            return trace;
        }
        let block = &out.func.cfg.blocks[current.0 as usize];
        current = match &out.func.values[block.insts.last().unwrap().0 as usize].op {
            SsaOp::Branch {
                true_block,
                false_block,
                ..
            } => {
                if choices.pop_front().expect("branch input") {
                    *true_block
                } else {
                    *false_block
                }
            }
            SsaOp::Jump { target } => *target,
            _ => panic!("missing terminator"),
        };
    }
    panic!("CFG fuel exhausted")
}

fn tree_trace(
    node: &Region,
    out: &LiftOutput,
    choices: &mut VecDeque<bool>,
    trace: &mut Vec<String>,
    fuel: &mut usize,
) -> Control {
    assert!(*fuel > 0);
    *fuel -= 1;
    match node {
        Region::Sequence(nodes) => {
            for node in nodes {
                let control = tree_trace(node, out, choices, trace, fuel);
                if control != Control::Next {
                    return control;
                }
            }
            Control::Next
        }
        Region::Block(block) => block_trace(out, *block, trace),
        Region::If { yes, no, .. } => tree_trace(
            if choices.pop_front().expect("branch input") {
                yes
            } else {
                no
            },
            out,
            choices,
            trace,
            fuel,
        ),
        Region::Loop { body, .. } => loop {
            match tree_trace(body, out, choices, trace, fuel) {
                Control::Break => break Control::Next,
                Control::Return => break Control::Return,
                Control::Continue => continue,
                Control::Next => {}
            }
        },
        Region::Break => Control::Break,
        Region::Continue => Control::Continue,
        Region::Switch { .. } | Region::TryCatch { .. } => panic!("unsupported node"),
    }
}

fn assert_traces(out: &LiftOutput, dex: &DexFile, cases: &[Vec<bool>]) {
    let norm = normalize_loops(out);
    let subject = norm.lift.as_ref().unwrap_or(out);
    let tree = build_region_tree(subject, dex).unwrap_or_else(|reason| {
        panic!("region tree failed: {reason:?}\nreport {:?}", norm.report)
    });
    for choices in cases {
        let expected = cfg_trace(out, choices.clone().into());
        let normalized = cfg_trace(subject, choices.clone().into());
        assert_eq!(
            normalized, expected,
            "normalized CFG drifted for {choices:?}"
        );
        let mut actual = vec![];
        let control = tree_trace(
            &tree.root,
            subject,
            &mut choices.clone().into(),
            &mut actual,
            &mut 1000,
        );
        assert_eq!(control, Control::Return, "trace {actual:?}");
        assert_eq!(actual, expected, "region trace drifted for {choices:?}");
    }
}

fn phi_preds(out: &LiftOutput, block: BlockId) -> BTreeSet<BlockId> {
    out.func.cfg.blocks[block.0 as usize]
        .phis
        .iter()
        .flat_map(|id| match &out.func.values[id.0 as usize].op {
            SsaOp::Phi { incoming } => incoming.iter().map(|(pred, _)| *pred).collect::<Vec<_>>(),
            _ => vec![],
        })
        .collect()
}

fn add_phi(out: &mut LiftOutput, block: BlockId, incoming: Vec<(BlockId, SsaValueId)>) {
    let id = SsaValueId(out.func.values.len() as u32);
    out.func.values.push(SsaInstruction {
        id,
        op: SsaOp::Phi { incoming },
        source_addr: block.0 as u64,
        block,
    });
    out.func.cfg.blocks[block.0 as usize].phis.push(id);
    out.func.next_value = out.func.values.len() as u32;
}

#[test]
fn nested_natural_loops_keep_inner_and_outer_side_effects() {
    let (dex, out) = nested();
    let norm = normalize_loops(&out);
    assert_eq!(norm.report.nodes_split, 0);
    assert!(norm.lift.is_none());
    assert_traces(
        &out,
        &dex,
        &[
            vec![false],
            vec![true, false, false],
            vec![true, true, false, false],
            vec![true, true, true, false, true, false, false],
        ],
    );
}

#[test]
fn multi_entry_loop_splits_under_budget_and_matches_cfg_traces() {
    let (dex, out) = multi_entry();
    let norm = normalize_loops(&out);
    assert!(norm.report.nodes_split >= 2, "{:?}", norm.report);
    assert_eq!(norm.report.multi_entry_after, 0);
    assert_eq!(norm.report.refusal, None);
    assert_traces(
        &out,
        &dex,
        &[
            vec![true, false],
            vec![false, false],
            vec![true, true, false],
            vec![false, true, false],
            vec![true, true, true, false],
            vec![false, true, true, true, false],
        ],
    );
    let info = revx_dex::render::build_try_info(&dex, &[]);
    let (structured, _) = structure_lifted(&dex, &info, &out, StructuringMode::Auto);
    assert!(
        structured.used_region_path,
        "{:?}",
        structured.fallback_reason
    );
    assert!(structured.nodes_split >= 2);
    assert!(structured.pseudocode.contains("while (true)"));
    assert_eq!(structured.pseudocode.matches("Trace.a()").count(), 2);
    assert_eq!(structured.pseudocode.matches("Trace.b()").count(), 2);
    let (legacy, _) = structure_lifted(&dex, &info, &out, StructuringMode::Legacy);
    assert!(!legacy.used_region_path);
    assert_eq!(legacy.nodes_split, 0);
}

#[test]
fn expansion_budget_refuses_without_mutating_and_reports_budget() {
    let (_dex, out) = multi_entry();
    let norm = normalize_loops_with_budget(&out, LoopNormBudget { max_new_blocks: 1 });
    assert!(norm.lift.is_none());
    assert_eq!(norm.report.nodes_split, 0);
    assert_eq!(norm.report.blocks_after, norm.report.blocks_before);
    assert_eq!(norm.report.multi_entry_after, 1);
    assert_eq!(norm.report.refusal, Some(LoopNormRefusal::ExpansionBudget));
}

#[test]
fn default_expansion_budget_falls_back_without_changing_legacy_text() {
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
    let (dex, out) = fixture(ops);
    let norm = normalize_loops(&out);
    assert!(norm.lift.is_none(), "{:?}", norm.report);
    assert_eq!(norm.report.nodes_split, 0);
    assert!(norm.report.multi_entry_after > 0, "{:?}", norm.report);
    assert_eq!(norm.report.refusal, Some(LoopNormRefusal::ExpansionBudget));
    let info = revx_dex::render::build_try_info(&dex, &[]);
    let (auto, _) = structure_lifted(&dex, &info, &out, StructuringMode::Auto);
    let (legacy, _) = structure_lifted(&dex, &info, &out, StructuringMode::Legacy);
    assert_eq!(auto.fallback_reason, Some(RegionFallbackReason::Budget));
    assert!(!auto.used_region_path);
    assert_eq!(auto.nodes_split, 0);
    assert_eq!(auto.pseudocode, legacy.pseudocode);
}

#[test]
fn protected_block_inside_multi_entry_scc_is_not_split() {
    let (mut dex, mut out) = multi_entry();
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
    let norm = normalize_loops(&out);
    assert!(norm.lift.is_none());
    assert_eq!(norm.report.nodes_split, 0);
    assert_eq!(
        norm.report.refusal,
        Some(LoopNormRefusal::ExceptionIntersection)
    );
    let info = revx_dex::render::build_try_info(&dex, &[]);
    let (auto, _) = structure_lifted(&dex, &info, &out, StructuringMode::Auto);
    let (legacy, _) = structure_lifted(&dex, &info, &out, StructuringMode::Legacy);
    assert_eq!(
        auto.fallback_reason,
        Some(RegionFallbackReason::LoopExceptionIntersection)
    );
    assert!(!auto.used_region_path);
    assert_eq!(auto.pseudocode, legacy.pseudocode);
}

#[test]
fn try_that_crosses_a_loop_back_edge_keeps_an_explicit_fallback() {
    let (mut dex, mut out) = fixture(vec![
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
    let norm = normalize_loops(&out);
    assert_eq!(norm.report.multi_entry_before, 0);
    let info = revx_dex::render::build_try_info(&dex, &[]);
    let (auto, _) = structure_lifted(&dex, &info, &out, StructuringMode::Auto);
    let (legacy, _) = structure_lifted(&dex, &info, &out, StructuringMode::Legacy);
    assert!(!auto.used_region_path);
    assert_eq!(
        auto.fallback_reason,
        Some(RegionFallbackReason::NestedOrCrossScope)
    );
    assert_eq!(auto.pseudocode, legacy.pseudocode);
}

#[test]
fn phi_incomings_follow_the_retargeted_predecessors() {
    let (_dex, mut out) = multi_entry();
    let v0 = out.func.cfg.blocks[0].insts[0];
    let v1 = out.func.cfg.blocks[1].insts[0];
    let v2 = out.func.cfg.blocks[2].insts[0];
    add_phi(
        &mut out,
        BlockId(1),
        vec![(BlockId(0), v0), (BlockId(2), v2)],
    );
    add_phi(
        &mut out,
        BlockId(2),
        vec![(BlockId(0), v0), (BlockId(1), v1)],
    );
    let norm = normalize_loops(&out);
    let lifted = norm.lift.expect("split");
    assert_eq!(norm.report.multi_entry_after, 0);
    for block in &lifted.func.cfg.blocks {
        if block.phis.is_empty() {
            continue;
        }
        let preds: BTreeSet<_> = lifted.func.cfg.preds[block.id.0 as usize]
            .iter()
            .copied()
            .collect();
        assert_eq!(phi_preds(&lifted, block.id), preds, "block {}", block.id.0);
        for phi in &block.phis {
            let SsaOp::Phi { incoming } = &lifted.func.values[phi.0 as usize].op else {
                panic!("phi slot is not a phi");
            };
            for (pred, value) in incoming {
                let owner = lifted.func.values[value.0 as usize].block;
                assert!(
                    owner == *pred
                        || lifted.func.cfg.blocks[pred.0 as usize]
                            .insts
                            .contains(value)
                        || lifted.func.cfg.blocks[pred.0 as usize].phis.contains(value),
                    "value {} from pred {} lives in {}",
                    value.0,
                    pred.0,
                    owner.0
                );
            }
        }
    }
    let copy_of_b = lifted
        .func
        .cfg
        .blocks
        .iter()
        .find(|block| block.start_addr == 2 && block.id != BlockId(2))
        .unwrap();
    let SsaOp::Phi { incoming } = &lifted.func.values[copy_of_b.phis[0].0 as usize].op else {
        panic!("missing copied phi");
    };
    let from_copy_a = incoming
        .iter()
        .find(|(pred, _)| {
            lifted.func.cfg.blocks[pred.0 as usize].start_addr == 1 && *pred != BlockId(1)
        })
        .expect("copy of a");
    assert_ne!(from_copy_a.1, v1);
    assert_eq!(
        lifted.func.values[from_copy_a.1.0 as usize].block,
        from_copy_a.0
    );
    let info = revx_dex::render::build_try_info(&_dex, &[]);
    let (auto, _) = structure_lifted(&_dex, &info, &out, StructuringMode::Auto);
    let (legacy, _) = structure_lifted(&_dex, &info, &out, StructuringMode::Legacy);
    assert_eq!(
        auto.fallback_reason,
        Some(RegionFallbackReason::UnsupportedShape)
    );
    assert_eq!(auto.pseudocode, legacy.pseudocode);
}
