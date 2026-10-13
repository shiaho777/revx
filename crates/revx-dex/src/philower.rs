use crate::lift::LiftOutput;
use crate::loopnorm::{
    DEFAULT_MAX_NEW_BLOCKS, add_edge, edges_consistent, exception_blocks, retarget_edge,
};
use revx_analysis::ssa::{
    BlockId, Cfg, CfgBlock, Operand, SsaFunction, SsaInstruction, SsaOp, SsaValueId,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhiLowerBudget {
    pub max_new_blocks: usize,
}

impl Default for PhiLowerBudget {
    fn default() -> Self {
        Self {
            max_new_blocks: DEFAULT_MAX_NEW_BLOCKS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhiLowerRefusal {
    ExpansionBudget,
    ExceptionIntersection,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhiLowerReport {
    pub nodes_split: usize,
    pub phis_destroyed: usize,
    pub refusal: Option<PhiLowerRefusal>,
}

pub struct PhiLowerOutcome {
    pub lift: Option<LiftOutput>,
    pub report: PhiLowerReport,
}

pub fn destroy_phis(output: &LiftOutput) -> PhiLowerOutcome {
    destroy_phis_with_budget(output, PhiLowerBudget::default())
}

pub fn destroy_phis_with_budget(output: &LiftOutput, budget: PhiLowerBudget) -> PhiLowerOutcome {
    let phis = phi_count(output);
    if phis == 0 {
        return PhiLowerOutcome {
            lift: None,
            report: PhiLowerReport {
                nodes_split: 0,
                phis_destroyed: 0,
                refusal: None,
            },
        };
    }
    let mut lift = output.clone();
    match lower(&mut lift, budget.max_new_blocks) {
        Ok(nodes_split) => {
            lift.func.dom_tree = revx_analysis::ssa::DominatorTree::compute(&lift.func.cfg);
            PhiLowerOutcome {
                lift: Some(lift),
                report: PhiLowerReport {
                    nodes_split,
                    phis_destroyed: phis,
                    refusal: None,
                },
            }
        }
        Err(refusal) => PhiLowerOutcome {
            lift: None,
            report: PhiLowerReport {
                nodes_split: 0,
                phis_destroyed: 0,
                refusal: Some(refusal),
            },
        },
    }
}

fn phi_count(output: &LiftOutput) -> usize {
    output
        .func
        .cfg
        .blocks
        .iter()
        .map(|block| block.phis.len())
        .sum()
}

fn lower(output: &mut LiftOutput, remaining: usize) -> Result<usize, PhiLowerRefusal> {
    let protected = exception_blocks(&output.exception_flow);
    let work = collect_phis(output);
    let mut critical: BTreeSet<(BlockId, BlockId)> = BTreeSet::new();
    let mut copies: Vec<(BlockId, BlockId, SsaValueId, SsaValueId)> = Vec::new();
    for (dest, phi, incoming) in &work {
        let preds: HashSet<BlockId> = output.func.cfg.preds[dest.0 as usize]
            .iter()
            .copied()
            .collect();
        for (pred, value) in incoming {
            if value.0 == u32::MAX || !preds.contains(pred) {
                continue;
            }
            copies.push((*pred, *dest, *phi, *value));
            if is_critical(&output.func.cfg, *pred, *dest) {
                critical.insert((*pred, *dest));
            }
        }
    }
    if critical
        .iter()
        .any(|(from, to)| protected.contains(from) || protected.contains(to))
    {
        return Err(PhiLowerRefusal::ExceptionIntersection);
    }
    if critical.len() > remaining || output.func.cfg.blocks.len() + critical.len() > 256 {
        return Err(PhiLowerRefusal::ExpansionBudget);
    }
    let mut split_map = BTreeMap::new();
    for (from, to) in &critical {
        let split = split_edge(output, *from, *to);
        split_map.insert((*from, *to), split);
    }
    let mut by_place: BTreeMap<BlockId, Vec<(SsaValueId, SsaValueId)>> = BTreeMap::new();
    for (pred, dest, phi, value) in copies {
        let place = split_map.get(&(pred, dest)).copied().unwrap_or(pred);
        by_place.entry(place).or_default().push((phi, value));
    }
    for (place, assigns) in by_place {
        insert_parallel_copies(&mut output.func, place, assigns);
    }
    for (dest, phi, incoming) in work {
        output.func.cfg.blocks[dest.0 as usize]
            .phis
            .retain(|id| *id != phi);
        if let Some(inst) = output.func.values.get_mut(phi.0 as usize) {
            let src = incoming
                .iter()
                .find(|(_, value)| value.0 != u32::MAX)
                .map(|(_, value)| Operand::Value(*value))
                .unwrap_or(Operand::Constant(0));
            inst.op = SsaOp::Copy { src };
        }
    }
    if !edges_consistent(&output.func.cfg) {
        return Err(PhiLowerRefusal::Unsupported);
    }
    Ok(critical.len())
}

type PhiWork = Vec<(BlockId, SsaValueId, Vec<(BlockId, SsaValueId)>)>;

fn collect_phis(output: &LiftOutput) -> PhiWork {
    let mut work = Vec::new();
    for block in &output.func.cfg.blocks {
        for phi in &block.phis {
            let incoming = match &output.func.values[phi.0 as usize].op {
                SsaOp::Phi { incoming } => incoming.clone(),
                _ => continue,
            };
            work.push((block.id, *phi, incoming));
        }
    }
    work
}

fn is_critical(cfg: &Cfg, from: BlockId, to: BlockId) -> bool {
    cfg.succs
        .get(from.0 as usize)
        .is_some_and(|succs| succs.len() > 1)
        && cfg
            .preds
            .get(to.0 as usize)
            .is_some_and(|preds| preds.len() > 1)
}

fn split_edge(output: &mut LiftOutput, from: BlockId, to: BlockId) -> BlockId {
    let new_id = BlockId(output.func.cfg.blocks.len() as u32);
    let addr = output.func.cfg.blocks[from.0 as usize].start_addr;
    let jump = push_value(&mut output.func, SsaOp::Jump { target: to }, new_id, addr);
    output.func.cfg.blocks.push(CfgBlock {
        id: new_id,
        start_addr: addr,
        end_addr: addr,
        insts: vec![jump],
        phis: vec![],
    });
    output.func.cfg.preds.push(Vec::new());
    output.func.cfg.succs.push(Vec::new());
    retarget_edge(output, from, to, new_id);
    add_edge(&mut output.func.cfg, new_id, to);
    new_id
}

fn insert_parallel_copies(
    func: &mut SsaFunction,
    block: BlockId,
    mut pending: Vec<(SsaValueId, SsaValueId)>,
) {
    pending.retain(|(dest, src)| dest != src);
    pending.sort_by_key(|(dest, src)| (dest.0, src.0));
    pending.dedup();
    while !pending.is_empty() {
        if let Some(index) = pending
            .iter()
            .position(|(dest, _)| pending.iter().all(|(_, src)| src != dest))
        {
            let (dest, src) = pending.remove(index);
            insert_store(func, block, dest, src);
            continue;
        }
        let (dest, src) = pending.remove(0);
        let temp = insert_value_copy(func, block, dest);
        for (_, value) in pending.iter_mut() {
            if *value == dest {
                *value = temp;
            }
        }
        pending.push((dest, src));
    }
}

fn insert_store(func: &mut SsaFunction, block: BlockId, dest: SsaValueId, src: SsaValueId) {
    insert_before_terminator(
        func,
        block,
        SsaOp::Store {
            addr: Operand::Symbol(format!("v{}", dest.0)),
            value: Operand::Value(src),
        },
    );
}

fn insert_value_copy(func: &mut SsaFunction, block: BlockId, src: SsaValueId) -> SsaValueId {
    insert_before_terminator(
        func,
        block,
        SsaOp::Copy {
            src: Operand::Value(src),
        },
    )
}

fn insert_before_terminator(func: &mut SsaFunction, block: BlockId, op: SsaOp) -> SsaValueId {
    let addr = func.cfg.blocks[block.0 as usize].start_addr;
    let insert_at = {
        let insts = &func.cfg.blocks[block.0 as usize].insts;
        match insts.last() {
            Some(last) if is_terminator(&func.values[last.0 as usize].op) => insts.len() - 1,
            _ => insts.len(),
        }
    };
    let id = push_value(func, op, block, addr);
    func.cfg.blocks[block.0 as usize]
        .insts
        .insert(insert_at, id);
    id
}

fn push_value(func: &mut SsaFunction, op: SsaOp, block: BlockId, addr: u64) -> SsaValueId {
    let id = SsaValueId(func.values.len() as u32);
    func.values.push(SsaInstruction {
        id,
        op,
        source_addr: addr,
        block,
    });
    func.next_value = func.values.len() as u32;
    id
}

fn is_terminator(op: &SsaOp) -> bool {
    matches!(
        op,
        SsaOp::Jump { .. } | SsaOp::Branch { .. } | SsaOp::Return { .. }
    )
}
