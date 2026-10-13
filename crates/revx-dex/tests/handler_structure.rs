use revx_analysis::ssa::{BlockId, CfgBlock, Operand, SsaInstruction, SsaOp, SsaValueId};
use revx_dex::exception::{ExceptionRegion, HandlerKind, HandlerRef};
use revx_dex::lift::{LiftOutput, lift_method_to_ssa};
use revx_dex::region::{
    Region, RegionFallbackReason, StructuringMode, build_region_tree, structure_lifted,
    structure_method,
};
use revx_dex::{CatchHandler, CodeItem, DexFile, TryItem};
use std::collections::VecDeque;

fn empty_dex() -> DexFile {
    let mut bytes = vec![0; 0x70];
    bytes[..8].copy_from_slice(b"dex\n039\0");
    let mut dex = DexFile::parse(bytes).unwrap();
    dex.types.push("Ljava/lang/Exception;".into());
    dex
}

fn dex_code(insns: &[u16], tries: Vec<TryItem>) -> CodeItem {
    CodeItem {
        registers_size: 2,
        ins_size: 0,
        outs_size: 0,
        tries_size: tries.len() as u16,
        debug_info_off: 0,
        insns: insns.to_vec(),
        tries,
    }
}

fn try_item(start: u32, count: u16, typed: &[(u32, u32)], catch_all: Option<u32>) -> TryItem {
    TryItem {
        start_addr: start,
        insn_count: count,
        handlers: typed
            .iter()
            .map(|&(type_idx, addr)| CatchHandler { type_idx, addr })
            .collect(),
        catch_all_addr: catch_all,
    }
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

fn try_in_loop() -> (DexFile, LiftOutput) {
    let (dex, mut out) = fixture(vec![
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

fn overlapping_tries() -> CodeItem {
    dex_code(
        &[0x0000, 0x0000, 0x000e, 0x000d, 0x000e, 0x000d, 0x000e],
        vec![
            try_item(0, 3, &[(0, 3)], None),
            try_item(1, 1, &[(0, 5)], None),
        ],
    )
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
            } if name != "__exception" && name != "__copy" => trace.push(name.clone()),
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
        Region::TryCatch { body, .. } => tree_trace(body, out, choices, trace, fuel),
        Region::Switch { .. } => panic!("unsupported node"),
    }
}

#[test]
fn try_inside_loop_structures_and_matches_ordinary_traces() {
    let (dex, out) = try_in_loop();
    let auto = structured(&dex, &out);
    assert!(auto.used_region_path, "{:?}", auto.fallback_reason);
    assert_eq!(auto.structured_try_count, 1);
    assert!(auto.pseudocode.contains("try {"));
    assert!(auto.pseudocode.contains("while (true)"));
    let tree = build_region_tree(&out, &dex)
        .unwrap_or_else(|reason| panic!("region tree failed: {reason:?}\n{}", auto.pseudocode));
    for choices in [vec![false], vec![true, false], vec![true, true, false]] {
        let expected = cfg_trace(&out, choices.clone().into());
        let mut actual = vec![];
        let control = tree_trace(
            &tree.root,
            &out,
            &mut choices.clone().into(),
            &mut actual,
            &mut 1000,
        );
        assert_eq!(control, Control::Return, "trace {actual:?}");
        assert_eq!(actual, expected, "region trace drifted for {choices:?}");
    }
}

#[test]
fn shared_handler_is_owned_per_try() {
    let dex = empty_dex();
    let code = dex_code(
        &[0x0000, 0x0000, 0x000e, 0x000d, 0x000e],
        vec![
            try_item(0, 1, &[(0, 3)], None),
            try_item(1, 2, &[(0, 3)], None),
        ],
    );
    let res = structure_method(&dex, &code, 0, StructuringMode::Auto);
    assert!(
        res.used_region_path,
        "fallback {:?}\n{}",
        res.fallback_reason, res.pseudocode
    );
    assert_eq!(res.structured_try_count, 2);
    assert_eq!(
        res.pseudocode.matches("catch (java.lang.Exception").count(),
        2
    );
}

#[test]
fn ordinary_reachable_handler_stays_exception_entry_only() {
    let dex = empty_dex();
    let code = dex_code(
        &[0x0000, 0x000d, 0x000e],
        vec![try_item(0, 1, &[(0, 1)], None)],
    );
    let res = structure_method(&dex, &code, 0, StructuringMode::Auto);
    assert!(
        res.used_region_path,
        "fallback {:?}\n{}",
        res.fallback_reason, res.pseudocode
    );
    assert_eq!(res.structured_try_count, 1);
    assert!(res.pseudocode.contains("try {"));
    assert!(res.pseudocode.contains("catch (java.lang.Exception"));
}

#[test]
fn overlapping_tries_still_fall_back_with_identical_legacy_text() {
    let dex = empty_dex();
    let code = overlapping_tries();
    let output = lift_method_to_ssa(&dex, &code, 0);
    let info = revx_dex::render::build_try_info(&dex, &code.tries);
    let (auto, _) = structure_lifted(&dex, &info, &output, StructuringMode::Auto);
    let (legacy, _) = structure_lifted(&dex, &info, &output, StructuringMode::Legacy);
    assert!(!auto.used_region_path);
    assert_eq!(
        auto.fallback_reason,
        Some(RegionFallbackReason::NestedOrCrossScope)
    );
    assert_eq!(auto.pseudocode, legacy.pseudocode);
}

#[test]
fn try_in_loop_legacy_text_is_unchanged_when_requested() {
    let (dex, out) = try_in_loop();
    let auto = structured(&dex, &out);
    let legacy = legacy_text(&dex, &out);
    assert!(auto.used_region_path);
    assert_ne!(auto.pseudocode, legacy);
}
