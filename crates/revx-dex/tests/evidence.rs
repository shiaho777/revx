use revx_analysis::ssa::{BlockId, Operand, SsaOp};
use revx_dex::DexFile;
use revx_dex::evidence::{
    self, CoverageStatus, DEFAULT_VIEW_LINES, DexMethodRecord, EvidenceConfidence, ResidualUnknown,
};
use revx_dex::lift::lift_method_to_ssa;
use revx_dex::region::{StructuringMode, structure_lifted};

fn ret_dex() -> Vec<u8> {
    let mut bytes = vec![0; 0x70];
    bytes[..8].copy_from_slice(b"dex\n039\0");
    bytes
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

fn multi_entry() -> (DexFile, revx_dex::lift::LiftOutput) {
    build(vec![
        vec![call("entry"), branch(1, 2)],
        vec![call("a"), branch(2, 3)],
        vec![call("b"), branch(1, 3)],
        vec![call("exit"), SsaOp::Return { value: None }],
    ])
}

fn phi_irreducible() -> (DexFile, revx_dex::lift::LiftOutput) {
    let (dex, mut out) = multi_entry();
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

fn observe(
    dex: &DexFile,
    out: &revx_dex::lift::LiftOutput,
    complete: bool,
    offset: usize,
    limit: usize,
) -> (DexMethodRecord, Option<ResidualUnknown>) {
    let info = revx_dex::render::build_try_info(dex, &[]);
    let (result, _) = structure_lifted(dex, &info, out, StructuringMode::Auto);
    evidence::observe_region(
        "LTrace;",
        "LTrace;->run()V",
        0,
        &result,
        offset,
        limit,
        complete,
    )
}

#[test]
fn region_path_is_complete_observation() {
    let (dex, out) = multi_entry();
    let (record, unknown) = observe(&dex, &out, true, 0, DEFAULT_VIEW_LINES);
    assert!(record.used_region_path);
    assert_eq!(record.evidence.confidence, EvidenceConfidence::Observed);
    assert_eq!(record.evidence.coverage.status, CoverageStatus::Complete);
    assert!(record.evidence.unknown_ids.is_empty());
    assert!(unknown.is_none());
    assert!(record.evidence.evidence_id.starts_with("ev_"));
    assert_eq!(record.evidence.evidence_id.len(), 3 + 64);
    let text = record.pseudocode.as_deref().expect("complete text");
    assert!(text.contains("while (true)"));
    assert_eq!(record.view.evidence_id, record.evidence.evidence_id);
    assert_eq!(record.view.offset, 0);
}

#[test]
fn fallback_is_partial_with_open_unknown() {
    let (dex, out) = phi_irreducible();
    let info = revx_dex::render::build_try_info(&dex, &[]);
    let (auto, _) = structure_lifted(&dex, &info, &out, StructuringMode::Auto);
    let (legacy, _) = structure_lifted(&dex, &info, &out, StructuringMode::Legacy);
    assert!(!auto.used_region_path);
    assert_eq!(auto.pseudocode, legacy.pseudocode);
    let (record, unknown) = evidence::observe_region(
        "LTrace;",
        "LTrace;->run()V",
        0,
        &auto,
        0,
        DEFAULT_VIEW_LINES,
        true,
    );
    assert_eq!(record.evidence.coverage.status, CoverageStatus::Partial);
    assert_eq!(
        record.fallback_reason.as_deref(),
        Some("unsupported_control_flow")
    );
    let unknown = unknown.expect("unknown");
    assert!(unknown.unknown_id.starts_with("unk_"));
    assert_eq!(unknown.unknown_id.len(), 4 + 64);
    assert_eq!(unknown.status, "open");
    assert_eq!(unknown.domain, "dex.structuring");
    assert_eq!(unknown.reason, "unsupported_control_flow");
    assert_eq!(unknown.evidence_id, record.evidence.evidence_id);
    assert_eq!(
        record.evidence.unknown_ids,
        vec![unknown.unknown_id.clone()]
    );
    assert_eq!(record.pseudocode.as_deref(), Some(auto.pseudocode.as_str()));
}

#[test]
fn evidence_ids_are_stable() {
    let (dex, out) = multi_entry();
    let (a, _) = observe(&dex, &out, false, 0, 4);
    let (b, _) = observe(&dex, &out, true, 0, 80);
    assert_eq!(a.evidence.evidence_id, b.evidence.evidence_id);
    assert!(a.pseudocode.is_none());
    assert!(b.pseudocode.is_some());
}

#[test]
fn view_pages_concatenate_to_full_text() {
    let (dex, out) = multi_entry();
    let (full, _) = observe(&dex, &out, true, 0, 10_000);
    let text = full.pseudocode.clone().expect("text");
    let total = text.lines().count();
    assert!(total > 2);
    let mut offset = 0;
    let mut parts = Vec::new();
    while offset < total {
        let (page, _) = observe(&dex, &out, false, offset, 2);
        assert_eq!(page.view.offset, offset);
        assert_eq!(page.view.total, total);
        parts.push(page.view.text.clone());
        match page.view.next_offset {
            Some(next) => {
                assert!(next > offset);
                offset = next;
            }
            None => break,
        }
    }
    assert_eq!(parts.join("\n"), text);
}

#[test]
fn summary_omits_full_pseudocode() {
    let (dex, out) = phi_irreducible();
    let (record, _) = observe(&dex, &out, false, 0, 2);
    assert!(record.pseudocode.is_none());
    assert!(!record.view.text.is_empty());
    assert!(record.view.truncated);
}
