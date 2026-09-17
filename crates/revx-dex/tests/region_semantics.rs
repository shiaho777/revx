use revx_analysis::ssa::{BlockId, CfgBlock, Operand, SsaInstruction, SsaOp, SsaValueId};
use revx_dex::lift::{LiftOutput, lift_method_to_ssa};
use revx_dex::region::{Region, build_region_tree, render_region_tree};
use revx_dex::{CodeItem, DexFile};
use std::collections::VecDeque;

fn fixture(ops: Vec<Vec<SsaOp>>) -> (DexFile, LiftOutput) {
    let mut bytes = vec![0; 0x70];
    bytes[..8].copy_from_slice(b"dex\n039\0");
    let dex = DexFile::parse(bytes).unwrap();
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
                target: Operand::Symbol(s),
                ..
            } => trace.push(s.clone()),
            SsaOp::Return { .. } => {
                trace.push("return".into());
                return Control::Return;
            }
            _ => {}
        }
    }
    Control::Next
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
                _ => {}
            }
        },
        Region::Break => Control::Break,
        Region::Continue => Control::Continue,
        _ => panic!("unsupported test interpreter node"),
    }
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

fn compare(out: &LiftOutput, dex: &DexFile, choices: Vec<bool>) -> String {
    let tree = build_region_tree(out, dex).unwrap();
    let expected = cfg_trace(out, choices.clone().into());
    let mut actual = vec![];
    assert_eq!(
        tree_trace(&tree.root, out, &mut choices.into(), &mut actual, &mut 1000),
        Control::Return
    );
    assert_eq!(actual, expected);
    assert_eq!(tree.owned_blocks.len(), out.func.cfg.blocks.len());
    let text = render_region_tree(&tree, out, dex).unwrap();
    assert_eq!(
        text,
        render_region_tree(&build_region_tree(out, dex).unwrap(), out, dex).unwrap()
    );
    text
}

#[test]
fn diamond_execution_preserves_branch_call_order_and_join() {
    let (dex, out) = fixture(vec![
        vec![call("start"), branch(1, 2)],
        vec![call("yes"), SsaOp::Jump { target: BlockId(3) }],
        vec![call("no"), SsaOp::Jump { target: BlockId(3) }],
        vec![call("join"), SsaOp::Return { value: None }],
    ]);
    for choice in [true, false] {
        let text = compare(&out, &dex, vec![choice]);
        assert_eq!(text.matches("Trace.join()").count(), 1);
        assert!(text.contains("if (choice)"));
    }
}

#[test]
fn bounded_loop_execution_preserves_break_continue_and_side_effects() {
    let (dex, out) = fixture(vec![
        vec![call("head"), branch(1, 2)],
        vec![call("body"), SsaOp::Jump { target: BlockId(0) }],
        vec![call("exit"), SsaOp::Return { value: None }],
    ]);
    for iterations in 0..8 {
        let mut choices = vec![true; iterations];
        choices.push(false);
        let text = compare(&out, &dex, choices);
        assert!(text.contains("while (true)"));
        assert!(text.contains("break;"));
        assert!(text.contains("continue;"));
        assert_eq!(text.matches("Trace.body()").count(), 1);
    }
}

#[test]
fn exception_dispatch_preserves_priority_binding_and_outside_calls() {
    use revx_dex::exception::{ExceptionRegion, HandlerKind, HandlerRef};
    let binding = || SsaOp::Call {
        target: Operand::Symbol("__exception".into()),
        args: vec![],
    };
    let (mut dex, mut out) = fixture(vec![
        vec![call("outside"), SsaOp::Jump { target: BlockId(1) }],
        vec![call("protected"), SsaOp::Jump { target: BlockId(4) }],
        vec![binding(), call("typed"), SsaOp::Jump { target: BlockId(4) }],
        vec![
            binding(),
            call("catchall"),
            SsaOp::Jump { target: BlockId(4) },
        ],
        vec![call("join"), SsaOp::Return { value: None }],
    ]);
    dex.types.push("LException;".into());
    out.exception_flow.regions.push(ExceptionRegion {
        try_index: 0,
        start: 1,
        insn_count: 1,
        end: Some(2),
        valid_range: true,
        protected_blocks: vec![BlockId(1)],
        handlers: vec![
            HandlerRef {
                kind: HandlerKind::Typed { type_idx: 0 },
                addr: 2,
                block: Some(BlockId(2)),
                ordinary_entry_reachable: false,
            },
            HandlerRef {
                kind: HandlerKind::CatchAll,
                addr: 3,
                block: Some(BlockId(3)),
                ordinary_entry_reachable: false,
            },
        ],
    });
    fn matches(kind: &HandlerKind, exception: u32) -> bool {
        match kind {
            HandlerKind::Typed { type_idx } => *type_idx == exception,
            HandlerKind::CatchAll => true,
        }
    }
    fn execute(
        node: &Region,
        out: &LiftOutput,
        injection: Option<(BlockId, u32)>,
        trace: &mut Vec<String>,
    ) -> Result<bool, u32> {
        match node {
            Region::Sequence(nodes) => {
                for node in nodes {
                    if execute(node, out, injection, trace)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Region::Block(block) => {
                let control = block_trace(out, *block, trace);
                if let Some((source, kind)) = injection
                    && source == *block
                {
                    return Err(kind);
                }
                Ok(control == Control::Return)
            }
            Region::TryCatch { body, catches, .. } => match execute(body, out, injection, trace) {
                Err(exception) => {
                    let catch = catches
                        .iter()
                        .find(|c| matches(&c.kind, exception))
                        .expect("matching catch");
                    execute(&catch.body, out, injection, trace)
                }
                result => result,
            },
            _ => panic!("unexpected exception fixture node"),
        }
    }
    let tree = build_region_tree(&out, &dex).unwrap();
    for injection in [
        None,
        Some((BlockId(1), 0)),
        Some((BlockId(1), 1)),
        Some((BlockId(0), 0)),
    ] {
        let mut expected = vec![];
        let mut current = BlockId(0);
        let mut escaped = None;
        loop {
            let control = block_trace(&out, current, &mut expected);
            if let Some((source, kind)) = injection
                && source == current
            {
                let handler = out
                    .exception_flow
                    .regions
                    .iter()
                    .find(|r| r.protected_blocks.contains(&current))
                    .and_then(|r| r.handlers.iter().find(|h| matches(&h.kind, kind)));
                if let Some(handler) = handler {
                    current = handler.block.unwrap();
                    continue;
                }
                escaped = Some(kind);
                break;
            }
            if control == Control::Return {
                break;
            }
            current = out.func.cfg.succs[current.0 as usize][0];
        }
        let mut actual = vec![];
        let result = execute(&tree.root, &out, injection, &mut actual);
        assert_eq!(result.err(), escaped);
        assert_eq!(actual, expected);
    }
    let text = render_region_tree(&tree, &out, &dex).unwrap();
    assert!(text.find("Trace.outside()").unwrap() < text.find("try {").unwrap());
    assert_eq!(text.matches("Trace.typed()").count(), 1);
    assert_eq!(text.matches("Trace.catchall()").count(), 1);
    assert_eq!(text.matches("Trace.join()").count(), 1);
    for handler in &out.exception_flow.regions[0].handlers {
        let id = out.func.cfg.blocks[handler.block.unwrap().0 as usize].insts[0];
        assert!(text.contains(&format!(" v{})", id.0)));
    }
}

#[test]
fn oversized_cfg_has_explicit_budget_fallback() {
    let (dex, out) = fixture(
        (0..257)
            .map(|_| vec![SsaOp::Return { value: None }])
            .collect(),
    );
    assert_eq!(
        build_region_tree(&out, &dex).unwrap_err(),
        revx_dex::region::RegionFallbackReason::Budget
    );
}
