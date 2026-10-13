use revx_analysis::ssa::{BlockId, CfgBlock, Operand, SsaInstruction, SsaOp, SsaValueId};
use revx_dex::exception::{ExceptionRegion, HandlerKind, HandlerRef};
use revx_dex::lift::{LiftOutput, lift_method_to_ssa};
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

fn two_return_exits() -> (DexFile, LiftOutput) {
    fixture(vec![
        vec![call("head"), SsaOp::Jump { target: BlockId(1) }],
        vec![call("body"), branch(2, 3)],
        vec![call("more"), branch(0, 4)],
        vec![call("left"), SsaOp::Return { value: None }],
        vec![call("right"), SsaOp::Return { value: None }],
    ])
}

fn switch_rejoin() -> (DexFile, LiftOutput) {
    let (dex, mut out) = fixture(vec![
        vec![switch_op()],
        vec![call("a"), SsaOp::Jump { target: BlockId(3) }],
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

fn switch_in_loop() -> (DexFile, LiftOutput) {
    let (dex, mut out) = fixture(vec![
        vec![call("head"), SsaOp::Jump { target: BlockId(1) }],
        vec![switch_op()],
        vec![call("body"), SsaOp::Jump { target: BlockId(0) }],
        vec![call("exit"), SsaOp::Return { value: None }],
    ]);
    connect(&mut out, 1, 0);
    connect(&mut out, 1, 2);
    connect(&mut out, 1, 3);
    out.switch_cases.insert(
        BlockId(1),
        vec![
            ("0".into(), BlockId(0)),
            ("1".into(), BlockId(2)),
            ("default".into(), BlockId(3)),
        ],
    );
    (dex, out)
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

fn overlapping_try() -> (DexFile, LiftOutput) {
    let (mut dex, mut out) = fixture(vec![
        vec![call("a"), SsaOp::Jump { target: BlockId(1) }],
        vec![call("b"), SsaOp::Jump { target: BlockId(2) }],
        vec![call("c"), SsaOp::Return { value: None }],
        vec![
            SsaOp::Call {
                target: Operand::Symbol("__exception".into()),
                args: vec![],
            },
            SsaOp::Return { value: None },
        ],
        vec![
            SsaOp::Call {
                target: Operand::Symbol("__exception".into()),
                args: vec![],
            },
            SsaOp::Return { value: None },
        ],
    ]);
    dex.types.push("Ljava/lang/Exception;".into());
    out.exception_flow.regions.push(ExceptionRegion {
        try_index: 0,
        start: 0,
        insn_count: 2,
        end: Some(2),
        valid_range: true,
        protected_blocks: vec![BlockId(0), BlockId(1)],
        handlers: vec![HandlerRef {
            kind: HandlerKind::Typed { type_idx: 0 },
            addr: 3,
            block: Some(BlockId(3)),
            ordinary_entry_reachable: false,
        }],
    });
    out.exception_flow.regions.push(ExceptionRegion {
        try_index: 1,
        start: 1,
        insn_count: 1,
        end: Some(2),
        valid_range: true,
        protected_blocks: vec![BlockId(1)],
        handlers: vec![HandlerRef {
            kind: HandlerKind::Typed { type_idx: 0 },
            addr: 4,
            block: Some(BlockId(4)),
            ordinary_entry_reachable: false,
        }],
    });
    (dex, out)
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

#[derive(Clone, Debug)]
enum Step {
    Cond(bool),
    Case(&'static str),
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
            } if name != "__exception" && name != "__switch" && name != "__copy" => {
                trace.push(name.clone());
            }
            SsaOp::Return { .. } => {
                trace.push("return".into());
                return Control::Return;
            }
            _ => {}
        }
    }
    Control::Next
}

fn cfg_trace(out: &LiftOutput, mut steps: VecDeque<Step>) -> Vec<String> {
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
            } => match steps.pop_front().expect("branch input") {
                Step::Cond(true) => *true_block,
                Step::Cond(false) => *false_block,
                other => panic!("expected cond, got {other:?}"),
            },
            SsaOp::Jump { target } => *target,
            SsaOp::Call {
                target: Operand::Symbol(name),
                ..
            } if name == "__switch" => {
                let key = match steps.pop_front().expect("switch input") {
                    Step::Case(key) => key,
                    other => panic!("expected case, got {other:?}"),
                };
                let cases = out.switch_cases.get(&current).expect("switch cases");
                cases
                    .iter()
                    .find(|(k, _)| k == key)
                    .or_else(|| cases.iter().find(|(k, _)| k == "default"))
                    .map(|(_, target)| *target)
                    .expect("case target")
            }
            _ => panic!("missing terminator"),
        };
    }
    panic!("CFG fuel exhausted")
}

fn tree_trace(
    node: &Region,
    out: &LiftOutput,
    steps: &mut VecDeque<Step>,
    trace: &mut Vec<String>,
    fuel: &mut usize,
) -> Control {
    assert!(*fuel > 0);
    *fuel -= 1;
    match node {
        Region::Sequence(nodes) => {
            for node in nodes {
                let control = tree_trace(node, out, steps, trace, fuel);
                if control != Control::Next {
                    return control;
                }
            }
            Control::Next
        }
        Region::Block(block) => block_trace(out, *block, trace),
        Region::If { yes, no, .. } => tree_trace(
            match steps.pop_front().expect("branch input") {
                Step::Cond(true) => yes,
                Step::Cond(false) => no,
                other => panic!("expected cond, got {other:?}"),
            },
            out,
            steps,
            trace,
            fuel,
        ),
        Region::Loop { body, .. } => loop {
            match tree_trace(body, out, steps, trace, fuel) {
                Control::Break => break Control::Next,
                Control::Return => break Control::Return,
                Control::Continue => continue,
                Control::Next => {}
            }
        },
        Region::Break => Control::Break,
        Region::Continue => Control::Continue,
        Region::Switch { cases, .. } => {
            let key = match steps.pop_front().expect("switch input") {
                Step::Case(key) => key,
                other => panic!("expected case, got {other:?}"),
            };
            let body = cases
                .iter()
                .find(|(keys, _)| keys.iter().any(|k| k == key))
                .or_else(|| {
                    cases
                        .iter()
                        .find(|(keys, _)| keys.iter().any(|k| k == "default"))
                })
                .map(|(_, body)| body)
                .expect("case body");
            tree_trace(body, out, steps, trace, fuel)
        }
        Region::TryCatch { body, .. } => tree_trace(body, out, steps, trace, fuel),
    }
}

fn assert_traces(dex: &DexFile, out: &LiftOutput, runs: &[Vec<Step>]) {
    let tree = build_region_tree(out, dex).unwrap_or_else(|reason| {
        panic!("region tree failed: {reason:?}");
    });
    for run in runs {
        let expected = cfg_trace(out, run.clone().into());
        let mut actual = vec![];
        let control = tree_trace(
            &tree.root,
            out,
            &mut run.clone().into(),
            &mut actual,
            &mut 1000,
        );
        assert_eq!(control, Control::Return, "trace {actual:?}");
        assert_eq!(actual, expected, "region trace drifted for {run:?}");
    }
}

#[test]
fn loop_with_two_return_exits_structures_and_matches_traces() {
    let (dex, out) = two_return_exits();
    let auto = structured(&dex, &out);
    let legacy = legacy_text(&dex, &out);
    assert!(
        auto.used_region_path,
        "fallback {:?}\n{}",
        auto.fallback_reason, auto.pseudocode
    );
    assert!(auto.pseudocode.contains("while (true)"));
    assert!(auto.pseudocode.contains("Trace.left()"));
    assert!(auto.pseudocode.contains("Trace.right()"));
    assert_ne!(auto.pseudocode, legacy);
    assert_traces(
        &dex,
        &out,
        &[
            vec![Step::Cond(false)],
            vec![Step::Cond(true), Step::Cond(false)],
            vec![Step::Cond(true), Step::Cond(true), Step::Cond(false)],
        ],
    );
}

#[test]
fn switch_arms_rejoin_after_the_switch() {
    let (dex, out) = switch_rejoin();
    let auto = structured(&dex, &out);
    let legacy = legacy_text(&dex, &out);
    assert!(
        auto.used_region_path,
        "fallback {:?}\n{}",
        auto.fallback_reason, auto.pseudocode
    );
    assert!(auto.pseudocode.contains("switch (key)"));
    assert!(auto.pseudocode.contains("case 0:"));
    assert!(auto.pseudocode.contains("case 1:"));
    assert!(auto.pseudocode.contains("default:"));
    assert_eq!(auto.pseudocode.matches("Trace.join()").count(), 1);
    assert_ne!(auto.pseudocode, legacy);
    assert_traces(
        &dex,
        &out,
        &[
            vec![Step::Case("0")],
            vec![Step::Case("1")],
            vec![Step::Case("default")],
        ],
    );
}

#[test]
fn switch_inside_loop_structures_and_matches_traces() {
    let (dex, out) = switch_in_loop();
    let auto = structured(&dex, &out);
    let legacy = legacy_text(&dex, &out);
    assert!(
        auto.used_region_path,
        "fallback {:?}\n{}",
        auto.fallback_reason, auto.pseudocode
    );
    assert!(auto.pseudocode.contains("while (true)"));
    assert!(auto.pseudocode.contains("switch (key)"));
    assert_ne!(auto.pseudocode, legacy);
    assert_traces(
        &dex,
        &out,
        &[
            vec![Step::Case("default")],
            vec![Step::Case("1"), Step::Case("default")],
            vec![Step::Case("0"), Step::Case("1"), Step::Case("default")],
        ],
    );
}

#[test]
fn two_loop_exits_that_merge_outside_still_fall_back() {
    let (dex, out) = two_exits_merge_outside();
    let auto = structured(&dex, &out);
    let legacy = legacy_text(&dex, &out);
    assert!(!auto.used_region_path);
    assert_eq!(
        auto.fallback_reason,
        Some(RegionFallbackReason::UnsupportedShape)
    );
    assert_eq!(auto.pseudocode, legacy);
}

#[test]
fn overlapping_tries_still_fall_back_with_identical_legacy_text() {
    let (dex, out) = overlapping_try();
    let auto = structured(&dex, &out);
    let legacy = legacy_text(&dex, &out);
    assert!(!auto.used_region_path);
    assert_eq!(
        auto.fallback_reason,
        Some(RegionFallbackReason::NestedOrCrossScope)
    );
    assert_eq!(auto.pseudocode, legacy);
}
