use revx_analysis::ssa::{
    BlockId, Cfg, CfgBlock, Operand, SsaFunction, SsaOp, render_ssa_pseudocode_named_layered,
};
use std::collections::HashMap;

fn fixture(n: usize, edges: &[(u32, u32)], ops: Vec<Vec<SsaOp>>) -> SsaFunction {
    let mut cfg = Cfg {
        blocks: (0..n)
            .map(|i| CfgBlock {
                id: BlockId(i as u32),
                start_addr: i as u64,
                end_addr: i as u64 + 1,
                insts: vec![],
                phis: vec![],
            })
            .collect(),
        preds: vec![Vec::new(); n],
        succs: vec![Vec::new(); n],
        entry: BlockId(0),
    };
    for &(from, to) in edges {
        cfg.succs[from as usize].push(BlockId(to));
        cfg.preds[to as usize].push(BlockId(from));
    }
    let mut func = SsaFunction::new(cfg);
    for (index, block_ops) in ops.into_iter().enumerate() {
        let block = BlockId(index as u32);
        for op in block_ops {
            func.define("_", block, op, index as u64);
        }
    }
    func
}

fn call(name: &str) -> SsaOp {
    SsaOp::Call {
        target: Operand::Symbol(name.to_string()),
        args: vec![],
    }
}

fn branch(yes: u32, no: u32) -> SsaOp {
    SsaOp::Branch {
        cond: Operand::Symbol("flag".into()),
        true_block: BlockId(yes),
        false_block: BlockId(no),
    }
}

fn jump(target: u32) -> SsaOp {
    SsaOp::Jump {
        target: BlockId(target),
    }
}

fn ret() -> SsaOp {
    SsaOp::Return { value: None }
}

fn render(func: &SsaFunction, name: &str) -> String {
    render_ssa_pseudocode_named_layered(func, name, &[], &HashMap::new(), &HashMap::new())
}

#[test]
fn named_layered_diamond_emits_if_else_without_goto() {
    let func = fixture(
        4,
        &[(0, 1), (0, 2), (1, 3), (2, 3)],
        vec![
            vec![branch(1, 2)],
            vec![call("then_work"), jump(3)],
            vec![call("else_work"), jump(3)],
            vec![call("join_work"), ret()],
        ],
    );
    let text = render(&func, "diamond");
    assert!(text.contains("if (flag) {"), "expected braced if:\n{text}");
    assert!(text.contains("} else {"), "expected else arm:\n{text}");
    assert!(text.contains("then_work("), "expected then call:\n{text}");
    assert!(text.contains("else_work("), "expected else call:\n{text}");
    assert_eq!(
        text.matches("join_work(").count(),
        1,
        "join call once:\n{text}"
    );
    assert!(
        !text.contains("goto bb") && !text.contains("goto fail") && !text.contains("goto cleanup"),
        "diamond still has goto:\n{text}"
    );
}

#[test]
fn named_layered_while_emits_loop_without_goto() {
    let func = fixture(
        3,
        &[(0, 1), (0, 2), (1, 0)],
        vec![vec![branch(1, 2)], vec![call("work"), jump(0)], vec![ret()]],
    );
    let text = render(&func, "loop_fn");
    assert!(text.contains("while ("), "expected while:\n{text}");
    assert!(text.contains("work("), "expected loop body:\n{text}");
    assert!(
        !text.contains("goto bb") && !text.contains("goto fail") && !text.contains("goto cleanup"),
        "while still has goto:\n{text}"
    );
}

#[test]
fn named_layered_early_exit_keeps_main_and_cleanup() {
    let func = fixture(
        4,
        &[(0, 3), (0, 1), (1, 2), (2, 3)],
        vec![
            vec![branch(3, 1)],
            vec![call("main_a"), branch(3, 2)],
            vec![call("main_b"), jump(3)],
            vec![call("cleanup"), ret()],
        ],
    );
    let text = render(&func, "guarded");
    assert!(text.contains("if ("), "expected if guard:\n{text}");
    assert!(
        text.contains("main_a("),
        "expected first main call:\n{text}"
    );
    assert!(
        text.contains("main_b("),
        "expected nested main call:\n{text}"
    );
    assert_eq!(text.matches("cleanup(").count(), 1, "cleanup once:\n{text}");
    assert!(
        !text.contains("goto bb") && !text.contains("goto fail") && !text.contains("goto cleanup"),
        "early-exit still has goto:\n{text}"
    );
}

#[test]
fn named_layered_oversize_stays_linear() {
    let n = 97usize;
    let ops = (0..n).map(|_| vec![ret()]).collect();
    let func = fixture(n, &[], ops);
    let text = render(&func, "oversize");
    assert!(
        text.contains("// bb1 @"),
        "expected linear block labels:\n{text}"
    );
}
