use revx_analysis::ssa::{BlockId, CfgBlock, Operand, SsaInstruction, SsaOp, SsaValueId};
use revx_dex::exception::{ExceptionRegion, HandlerKind, HandlerRef};
use revx_dex::lift::{LiftOutput, lift_method_to_ssa};
use revx_dex::loopnorm::normalize_loops;
use revx_dex::philower::{PhiLowerBudget, destroy_phis_with_budget};
use revx_dex::region::{
    Region, RegionFallbackReason, StructuringMode, build_region_tree, structure_lifted,
};
use revx_dex::{CodeItem, DexFile};
use std::collections::VecDeque;

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

fn add_phi(
    out: &mut LiftOutput,
    block: BlockId,
    incoming: Vec<(BlockId, SsaValueId)>,
) -> SsaValueId {
    let id = SsaValueId(out.func.values.len() as u32);
    out.func.values.push(SsaInstruction {
        id,
        op: SsaOp::Phi { incoming },
        source_addr: block.0 as u64,
        block,
    });
    out.func.cfg.blocks[block.0 as usize].phis.push(id);
    out.func.next_value = out.func.values.len() as u32;
    id
}

fn diamond() -> (DexFile, LiftOutput) {
    fixture(vec![
        vec![call("entry"), branch(1, 2)],
        vec![call("left"), SsaOp::Jump { target: BlockId(3) }],
        vec![call("right"), SsaOp::Jump { target: BlockId(3) }],
        vec![call("join"), SsaOp::Return { value: None }],
    ])
}

fn diamond_with_phi() -> (DexFile, LiftOutput) {
    let (dex, mut out) = diamond();
    let left = out.func.cfg.blocks[1].insts[0];
    let right = out.func.cfg.blocks[2].insts[0];
    add_phi(
        &mut out,
        BlockId(3),
        vec![(BlockId(1), left), (BlockId(2), right)],
    );
    (dex, out)
}

fn loop_with_phi() -> (DexFile, LiftOutput) {
    let (dex, mut out) = fixture(vec![
        vec![call("init"), SsaOp::Jump { target: BlockId(1) }],
        vec![call("head"), branch(2, 3)],
        vec![call("body"), SsaOp::Jump { target: BlockId(1) }],
        vec![call("exit"), SsaOp::Return { value: None }],
    ]);
    let init = out.func.cfg.blocks[0].insts[0];
    let body = out.func.cfg.blocks[2].insts[0];
    add_phi(
        &mut out,
        BlockId(1),
        vec![(BlockId(0), init), (BlockId(2), body)],
    );
    (dex, out)
}

fn multi_entry_with_phi() -> (DexFile, LiftOutput) {
    let (dex, mut out) = fixture(vec![
        vec![call("entry"), branch(1, 2)],
        vec![call("a"), branch(2, 3)],
        vec![call("b"), branch(1, 3)],
        vec![call("exit"), SsaOp::Return { value: None }],
    ]);
    let v0 = out.func.cfg.blocks[0].insts[0];
    let v1 = out.func.cfg.blocks[1].insts[0];
    let v2 = out.func.cfg.blocks[2].insts[0];
    add_phi(
        &mut out,
        BlockId(1),
        vec![(BlockId(0), v0), (BlockId(2), v2), (BlockId(1), v1)],
    );
    (dex, out)
}

fn try_crosses_loop() -> (DexFile, LiftOutput) {
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
    (dex, out)
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
            } if name != "__copy" => trace.push(name.clone()),
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

fn structured(dex: &DexFile, out: &LiftOutput) -> revx_dex::region::RegionResult {
    let info = revx_dex::render::build_try_info(dex, &[]);
    structure_lifted(dex, &info, out, StructuringMode::Auto).0
}

fn legacy_text(dex: &DexFile, out: &LiftOutput) -> String {
    let info = revx_dex::render::build_try_info(dex, &[]);
    structure_lifted(dex, &info, out, StructuringMode::Legacy)
        .0
        .pseudocode
}

fn prepared(out: &LiftOutput) -> LiftOutput {
    let norm = normalize_loops(out);
    let base = norm.lift.as_ref().unwrap_or(out);
    let remaining =
        revx_dex::loopnorm::DEFAULT_MAX_NEW_BLOCKS.saturating_sub(norm.report.nodes_split);
    let lowered = destroy_phis_with_budget(
        base,
        PhiLowerBudget {
            max_new_blocks: remaining,
        },
    );
    lowered.lift.unwrap_or_else(|| base.clone())
}

fn assert_region_traces(dex: &DexFile, out: &LiftOutput, cases: &[Vec<bool>]) {
    let auto = structured(dex, out);
    assert!(auto.used_region_path, "{:?}", auto.fallback_reason);
    assert!(auto.phi_lowered);
    let subject = prepared(out);
    assert!(
        !subject
            .func
            .values
            .iter()
            .any(|inst| matches!(inst.op, SsaOp::Phi { .. }))
    );
    let tree = build_region_tree(&subject, dex)
        .unwrap_or_else(|reason| panic!("region tree failed after phi lowering: {reason:?}"));
    for choices in cases {
        let expected = cfg_trace(out, choices.clone().into());
        let lowered = cfg_trace(&subject, choices.clone().into());
        assert_eq!(lowered, expected, "lowered CFG drifted for {choices:?}");
        let mut actual = vec![];
        let control = tree_trace(
            &tree.root,
            &subject,
            &mut choices.clone().into(),
            &mut actual,
            &mut 1000,
        );
        assert_eq!(control, Control::Return, "trace {actual:?}");
        assert_eq!(actual, expected, "region trace drifted for {choices:?}");
    }
}

#[test]
fn diamond_join_phi_structures_and_matches_traces() {
    let (dex, out) = diamond_with_phi();
    assert_region_traces(&dex, &out, &[vec![true], vec![false]]);
    let auto = structured(&dex, &out);
    assert!(auto.pseudocode.contains("if ("));
    assert!(auto.pseudocode.contains("Trace.join()"));
}

#[test]
fn loop_carried_phi_structures_and_matches_traces() {
    let (dex, out) = loop_with_phi();
    assert_region_traces(
        &dex,
        &out,
        &[vec![false], vec![true, false], vec![true, true, false]],
    );
    let auto = structured(&dex, &out);
    assert!(auto.pseudocode.contains("while (true)"));
}

#[test]
fn used_join_phi_emits_edge_copies() {
    let (dex, mut out) = diamond();
    let left = out.func.cfg.blocks[1].insts[0];
    let right = out.func.cfg.blocks[2].insts[0];
    let phi = add_phi(
        &mut out,
        BlockId(3),
        vec![(BlockId(1), left), (BlockId(2), right)],
    );
    let join = out.func.cfg.blocks[3].insts[0];
    if let SsaOp::Call { args, .. } = &mut out.func.values[join.0 as usize].op {
        args.push(Operand::Value(phi));
    }
    let auto = structured(&dex, &out);
    assert!(auto.used_region_path, "{:?}", auto.fallback_reason);
    assert!(auto.phi_lowered);
    assert!(auto.pseudocode.contains(&format!("v{} = v", phi.0)));
    assert!(auto.pseudocode.contains(&format!("Trace.join(v{})", phi.0)));
}

#[test]
fn multi_entry_loop_with_phi_uses_the_region_path() {
    let (dex, out) = multi_entry_with_phi();
    let auto = structured(&dex, &out);
    let legacy = legacy_text(&dex, &out);
    assert!(auto.used_region_path, "{:?}", auto.fallback_reason);
    assert!(auto.nodes_split >= 2);
    assert!(auto.phi_lowered);
    assert!(auto.pseudocode.contains("while (true)"));
    assert_ne!(auto.pseudocode, legacy);
    assert_region_traces(
        &dex,
        &out,
        &[
            vec![true, false],
            vec![false, false],
            vec![true, true, false],
            vec![false, true, false],
        ],
    );
}

#[test]
fn try_across_back_edge_still_falls_back_with_identical_legacy_text() {
    let (dex, out) = try_crosses_loop();
    let auto = structured(&dex, &out);
    let legacy = legacy_text(&dex, &out);
    assert!(!auto.used_region_path);
    assert_eq!(
        auto.fallback_reason,
        Some(RegionFallbackReason::NestedOrCrossScope)
    );
    assert_eq!(auto.pseudocode, legacy);
    assert!(!auto.phi_lowered);
}

#[test]
fn expansion_budget_row_is_unchanged() {
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
    let auto = structured(&dex, &out);
    let legacy = legacy_text(&dex, &out);
    assert_eq!(auto.fallback_reason, Some(RegionFallbackReason::Budget));
    assert!(!auto.used_region_path);
    assert_eq!(auto.nodes_split, 0);
    assert_eq!(auto.pseudocode, legacy);
}

fn critical_join() -> (DexFile, LiftOutput) {
    let (dex, mut out) = fixture(vec![
        vec![call("entry"), branch(1, 2)],
        vec![call("then"), SsaOp::Jump { target: BlockId(2) }],
        vec![call("join"), SsaOp::Return { value: None }],
    ]);
    let entry = out.func.cfg.blocks[0].insts[0];
    let then = out.func.cfg.blocks[1].insts[0];
    add_phi(
        &mut out,
        BlockId(2),
        vec![(BlockId(0), entry), (BlockId(1), then)],
    );
    (dex, out)
}

#[test]
fn critical_edge_phi_structures_under_budget() {
    let (dex, out) = critical_join();
    let auto = structured(&dex, &out);
    assert!(auto.used_region_path, "{:?}", auto.fallback_reason);
    assert!(auto.phi_lowered);
    assert_region_traces(&dex, &out, &[vec![true], vec![false]]);
}

#[test]
fn critical_edge_without_split_budget_refuses_and_leaves_phis() {
    let (_dex, out) = critical_join();
    let lowered = destroy_phis_with_budget(&out, PhiLowerBudget { max_new_blocks: 0 });
    assert!(lowered.lift.is_none());
    assert_eq!(
        lowered.report.refusal,
        Some(revx_dex::philower::PhiLowerRefusal::ExpansionBudget)
    );
    assert!(
        out.func
            .values
            .iter()
            .any(|inst| matches!(inst.op, SsaOp::Phi { .. }))
    );
}
