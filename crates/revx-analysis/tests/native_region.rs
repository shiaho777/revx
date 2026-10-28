use revx_analysis::ssa::{
    BlockId, Cfg, CfgBlock, Operand, SsaFunction, SsaOp, render_ssa_pseudocode_named_layered,
    render_ssa_pseudocode_named_layered_with_strings,
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
fn named_layered_open_arm_nests_before_join() {
    let func = fixture(
        5,
        &[(0, 1), (0, 2), (1, 4), (2, 3), (2, 4), (3, 4)],
        vec![
            vec![branch(1, 2)],
            vec![call("side"), jump(4)],
            vec![branch(3, 4)],
            vec![call("body"), jump(4)],
            vec![call("join_work"), ret()],
        ],
    );
    let text = render(&func, "open_arm");
    let body_at = text.find("body(").expect(&text);
    let join_at = text.find("join_work(").expect(&text);
    assert!(body_at < join_at, "body landed after join:\n{text}");
    assert!(text.contains("side("), "expected short arm:\n{text}");
    assert_eq!(text.matches("join_work(").count(), 1, "join once:\n{text}");
    assert!(
        !text.contains("goto bb") && !text.contains("// bb"),
        "open arm still linear:\n{text}"
    );
}

#[test]
fn named_layered_shared_body_stays_single() {
    let func = fixture(
        5,
        &[(0, 2), (0, 1), (1, 2), (1, 4), (2, 3), (4, 3)],
        vec![
            vec![branch(2, 1)],
            vec![call("side"), branch(2, 4)],
            vec![call("body"), jump(3)],
            vec![call("join_work"), ret()],
            vec![call("skip"), jump(3)],
        ],
    );
    let text = render(&func, "shared");
    assert_eq!(text.matches("body(").count(), 1, "body duplicated:\n{text}");
    assert_eq!(text.matches("side(").count(), 1, "side duplicated:\n{text}");
    assert_eq!(text.matches("skip(").count(), 1, "skip duplicated:\n{text}");
    assert_eq!(
        text.matches("join_work(").count(),
        1,
        "join duplicated:\n{text}"
    );
    assert!(
        text.matches("goto bb").count() <= 4,
        "too many gotos:\n{text}"
    );
}

#[test]
fn named_layered_repeated_null_guards_keep_body() {
    let func = fixture(
        6,
        &[(0, 4), (0, 1), (1, 4), (1, 2), (2, 4), (2, 3), (3, 5)],
        vec![
            vec![branch(4, 1)],
            vec![branch(4, 2)],
            vec![branch(4, 3)],
            vec![call("body"), jump(5)],
            vec![call("log_err"), ret()],
            vec![call("join_work"), ret()],
        ],
    );
    let text = render(&func, "guards");
    assert_eq!(text.matches("body(").count(), 1, "body duplicated:\n{text}");
    assert_eq!(
        text.matches("log_err(").count(),
        1,
        "log duplicated:\n{text}"
    );
    assert!(
        !text.contains("{\n    }"),
        "empty guard dropped a check:\n{text}"
    );
    assert!(
        text.matches("goto ").count() <= 1,
        "same-target guards stayed split:\n{text}"
    );
    let body_at = text.find("body(").expect(&text);
    let join_at = text.find("join_work(").expect(&text);
    assert!(body_at < join_at, "body after join:\n{text}");
}

#[test]
fn named_layered_self_loop_puts_work_inside_while() {
    let func = fixture(
        2,
        &[(0, 0), (0, 1)],
        vec![vec![call("work"), branch(0, 1)], vec![call("done"), ret()]],
    );
    let text = render(&func, "spin");
    let while_at = text.find("while (").expect(&text);
    let work_at = text.find("work(").expect(&text);
    let done_at = text.find("done(").expect(&text);
    assert!(
        while_at < work_at && work_at < done_at,
        "self-loop body escaped the while:\n{text}"
    );
    assert!(!text.contains("{\n    }"), "empty while:\n{text}");
}

#[test]
fn named_layered_self_loop_arm_is_the_while_body() {
    let func = fixture(
        3,
        &[(0, 2), (0, 1), (1, 1), (1, 2)],
        vec![
            vec![branch(2, 1)],
            vec![call("work"), branch(1, 2)],
            vec![call("done"), ret()],
        ],
    );
    let text = render(&func, "loop_arm");
    let while_at = text.find("while (").expect(&text);
    let work_at = text.find("work(").expect(&text);
    let done_at = text.find("done(").expect(&text);
    assert!(
        while_at < work_at && work_at < text.find("}").unwrap_or(work_at),
        "work is outside the while:\n{text}"
    );
    assert!(done_at > work_at, "done before the loop body:\n{text}");
    assert_eq!(text.matches("while (").count(), 1, "extra while:\n{text}");
    assert!(!text.contains("{\n    }"), "empty while:\n{text}");
}

#[test]
fn named_layered_branch_only_block_is_not_an_empty_if() {
    let func = fixture(
        6,
        &[(0, 1), (0, 2), (1, 3), (1, 4), (2, 5), (3, 5), (4, 5)],
        vec![
            vec![branch(1, 2)],
            vec![branch(3, 4)],
            vec![call("side"), jump(5)],
            vec![call("yes"), jump(5)],
            vec![call("no"), jump(5)],
            vec![call("done"), ret()],
        ],
    );
    let text = render(&func, "nested_cond");
    assert!(!text.contains("{\n    }"), "empty if:\n{text}");
    assert_eq!(text.matches("yes(").count(), 1, "yes duplicated:\n{text}");
    assert_eq!(text.matches("no(").count(), 1, "no duplicated:\n{text}");
    assert_eq!(text.matches("side(").count(), 1, "side duplicated:\n{text}");
    let yes_at = text.find("yes(").expect(&text);
    let side_at = text.find("side(").expect(&text);
    assert!(yes_at != side_at, "{text}");
}

#[test]
fn named_layered_sign_bit_does_not_reach_the_call() {
    let func = fixture(
        7,
        &[(0, 2), (0, 1), (1, 4), (1, 3), (3, 5), (2, 5), (5, 6)],
        vec![
            vec![branch(2, 1)],
            vec![branch(4, 3)],
            vec![call("nulls"), jump(5)],
            vec![call("alloc"), jump(5)],
            vec![call("err"), ret()],
            vec![call("use_buf"), jump(6)],
            vec![call("done"), ret()],
        ],
    );
    let text = render(&func, "signbit");
    let err_at = text.find("err(").expect(&text);
    let ret_after_err = text[err_at..].find("return").expect(&text);
    let use_after_err = text[err_at..].find("use_buf(");
    assert!(
        use_after_err.is_none() || use_after_err.unwrap() > ret_after_err,
        "sign-bit path reaches use_buf before returning:\n{text}"
    );
    assert!(text.contains("alloc("), "{text}");
    assert!(text.contains("nulls("), "{text}");
    assert!(!text.contains("{\n    }"), "empty if:\n{text}");
}

#[test]
fn named_layered_shared_log_keeps_the_setup_message() {
    let mut func = fixture(
        6,
        &[(0, 1), (0, 2), (2, 1), (2, 3), (1, 4), (4, 5), (3, 5)],
        vec![
            vec![branch(1, 2)],
            vec![jump(4)],
            vec![branch(1, 3)],
            vec![call("work"), jump(5)],
            vec![
                call("__android_log_print"),
                SsaOp::Copy {
                    src: Operand::Symbol("xzr".into()),
                },
                jump(5),
            ],
            vec![ret()],
        ],
    );
    let setup = BlockId(1);
    func.define(
        "x1",
        setup,
        SsaOp::Copy {
            src: Operand::Constant(0x2d9d),
        },
        0x531c,
    );
    func.define(
        "x2",
        setup,
        SsaOp::Copy {
            src: Operand::Constant(0x3355),
        },
        0x5324,
    );
    let mut strings = HashMap::new();
    strings.insert(0x2d9d, "NativeCrypto".to_string());
    strings.insert(0x3355, "Invalid parameters".to_string());
    let text = render_ssa_pseudocode_named_layered_with_strings(
        &func,
        "logmsg",
        &[],
        &HashMap::new(),
        &HashMap::new(),
        &strings,
    );
    assert!(text.matches("Invalid parameters").count() >= 2, "{text}");
    assert!(text.contains("NativeCrypto"), "{text}");
    assert!(!text.contains("goto "), "{text}");
}

#[test]
fn named_layered_log_arm_returns_instead_of_falling_through() {
    let func = fixture(
        5,
        &[(0, 1), (0, 3), (1, 2), (2, 4), (3, 2), (3, 4)],
        vec![
            vec![branch(1, 3)],
            vec![jump(2)],
            vec![
                call("__android_log_print"),
                SsaOp::Copy {
                    src: Operand::Symbol("xzr".into()),
                },
                jump(4),
            ],
            vec![call("work"), jump(4)],
            vec![ret()],
        ],
    );
    let text = render(&func, "logfail");
    let log_at = text.find("__android_log_print").expect(&text);
    let ret_at = text[log_at..].find("return 0").expect(&text);
    let work_at = text.find("work(").expect(&text);
    assert!(log_at + ret_at < work_at, "{text}");
    assert!(!text.contains("goto "), "{text}");
}

#[test]
fn named_layered_null_arm_rejoins_at_the_call() {
    let func = fixture(
        7,
        &[(0, 2), (0, 1), (1, 4), (1, 3), (2, 5), (3, 5), (5, 6)],
        vec![
            vec![branch(2, 1)],
            vec![branch(4, 3)],
            vec![],
            vec![call("alloc"), jump(5)],
            vec![call("err"), ret()],
            vec![call("use_buf"), jump(6)],
            vec![call("tail"), ret()],
        ],
    );
    let text = render(&func, "nulljoin");
    assert!(text.contains("alloc("), "{text}");
    assert!(text.contains("err("), "{text}");
    assert_eq!(text.matches("use_buf(").count(), 1, "{text}");
    let err_at = text.find("err(").expect(&text);
    let ret_at = text[err_at..].find("return").expect(&text);
    let use_rel = text[err_at..].find("use_buf(").expect(&text);
    assert!(ret_at < use_rel, "sign-bit falls into the call:\n{text}");
    let use_at = err_at + use_rel;
    assert!(
        text[..use_at].contains("alloc("),
        "alloc path misses the call:\n{text}"
    );
    assert!(text[err_at..use_at].contains('}'), "{text}");
    assert!(!text.contains("{\n    }"), "empty if:\n{text}");
    assert!(
        !text.contains("goto "),
        "null rejoin introduced a goto:\n{text}"
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
