use crate::exception::ExceptionFlow;
use crate::lift::LiftOutput;
use revx_analysis::ssa::{BlockId, Cfg, Operand, SsaFunction, SsaInstruction, SsaOp, SsaValueId};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

pub const DEFAULT_MAX_NEW_BLOCKS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoopNormBudget {
    pub max_new_blocks: usize,
}

impl Default for LoopNormBudget {
    fn default() -> Self {
        Self {
            max_new_blocks: DEFAULT_MAX_NEW_BLOCKS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopNormRefusal {
    ExpansionBudget,
    ExceptionIntersection,
    PhiShape,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoopNormReport {
    pub blocks_before: usize,
    pub blocks_after: usize,
    pub multi_entry_before: usize,
    pub multi_entry_after: usize,
    pub nodes_split: usize,
    pub refusal: Option<LoopNormRefusal>,
}

pub struct LoopNormOutcome {
    pub lift: Option<LiftOutput>,
    pub report: LoopNormReport,
}

pub fn normalize_loops(output: &LiftOutput) -> LoopNormOutcome {
    normalize_loops_with_budget(output, LoopNormBudget::default())
}

pub fn normalize_loops_with_budget(output: &LiftOutput, budget: LoopNormBudget) -> LoopNormOutcome {
    let before = output.func.cfg.blocks.len();
    let multi_before = multi_entry_count(&output.func.cfg);
    let mut report = LoopNormReport {
        blocks_before: before,
        blocks_after: before,
        multi_entry_before: multi_before,
        multi_entry_after: multi_before,
        nodes_split: 0,
        refusal: None,
    };
    if multi_before == 0 || before > 256 {
        return LoopNormOutcome { lift: None, report };
    }
    let mut lift = output.clone();
    let protected = exception_blocks(&output.exception_flow);
    let mut remaining = budget.max_new_blocks;
    let mut saw_exception = false;
    let mut saw_budget = false;
    loop {
        let mut candidates = Vec::new();
        for scc in cyclic_sccs(&lift.func.cfg) {
            if let Some(target) = peel_target(&scc, &lift.func.cfg) {
                candidates.push((target, scc));
            }
        }
        candidates.sort_by_key(|(target, _)| target.0);
        let mut peeled = false;
        for (target, scc) in candidates {
            if scc.iter().any(|block| protected.contains(block)) {
                saw_exception = true;
                continue;
            }
            if scc.len() > remaining || lift.func.cfg.blocks.len() + scc.len() > 256 {
                saw_budget = true;
                continue;
            }
            let snapshot = lift.clone();
            if !peel(&mut lift, &scc, target) {
                lift = snapshot;
                report.refusal = Some(LoopNormRefusal::PhiShape);
                peeled = false;
                break;
            }
            remaining -= scc.len();
            report.nodes_split += scc.len();
            peeled = true;
            break;
        }
        if !peeled {
            break;
        }
    }
    report.blocks_after = lift.func.cfg.blocks.len();
    report.multi_entry_after = multi_entry_count(&lift.func.cfg);
    if report.refusal.is_none() && report.multi_entry_after > 0 {
        report.refusal = if saw_exception {
            Some(LoopNormRefusal::ExceptionIntersection)
        } else if saw_budget {
            Some(LoopNormRefusal::ExpansionBudget)
        } else {
            None
        };
    }
    if report.nodes_split == 0 {
        report.blocks_after = before;
        return LoopNormOutcome { lift: None, report };
    }
    lift.func.dom_tree = revx_analysis::ssa::DominatorTree::compute(&lift.func.cfg);
    LoopNormOutcome {
        lift: Some(lift),
        report,
    }
}

pub(crate) fn exception_blocks(flow: &ExceptionFlow) -> BTreeSet<BlockId> {
    let mut blocks = BTreeSet::new();
    for region in &flow.regions {
        blocks.extend(region.protected_blocks.iter().copied());
        for handler in &region.handlers {
            if let Some(block) = handler.block {
                blocks.insert(block);
            }
        }
    }
    for shared in &flow.shared_handlers {
        if let Some(block) = shared.block {
            blocks.insert(block);
        }
    }
    blocks
}

fn multi_entry_count(cfg: &Cfg) -> usize {
    cyclic_sccs(cfg)
        .into_iter()
        .filter(|scc| entries(scc, cfg).len() > 1)
        .count()
}

fn cyclic_sccs(cfg: &Cfg) -> Vec<BTreeSet<BlockId>> {
    tarjan(cfg)
        .into_iter()
        .filter(|scc| {
            scc.len() > 1
                || scc.iter().any(|b| {
                    cfg.succs
                        .get(b.0 as usize)
                        .is_some_and(|succs| succs.contains(b))
                })
        })
        .collect()
}

fn entries(scc: &BTreeSet<BlockId>, cfg: &Cfg) -> Vec<BlockId> {
    let mut found: Vec<BlockId> = scc
        .iter()
        .copied()
        .filter(|block| {
            cfg.preds
                .get(block.0 as usize)
                .is_some_and(|preds| preds.iter().any(|pred| !scc.contains(pred)))
        })
        .collect();
    if scc.contains(&cfg.entry) && !found.contains(&cfg.entry) {
        found.push(cfg.entry);
    }
    found.sort();
    found
}

fn peel_target(scc: &BTreeSet<BlockId>, cfg: &Cfg) -> Option<BlockId> {
    let entries = entries(scc, cfg);
    if entries.len() <= 1 {
        return None;
    }
    let order = bfs(cfg);
    let pos = |block: BlockId| {
        order
            .iter()
            .position(|item| *item == block)
            .unwrap_or(usize::MAX)
    };
    let keeper = entries.iter().copied().min_by_key(|block| pos(*block))?;
    entries
        .into_iter()
        .filter(|block| {
            *block != keeper
                && cfg
                    .preds
                    .get(block.0 as usize)
                    .is_some_and(|preds| preds.iter().any(|pred| !scc.contains(pred)))
        })
        .min_by_key(|block| pos(*block))
}

fn bfs(cfg: &Cfg) -> Vec<BlockId> {
    let mut seen = vec![false; cfg.blocks.len()];
    let mut order = Vec::new();
    let mut queue = VecDeque::new();
    if (cfg.entry.0 as usize) < cfg.blocks.len() {
        seen[cfg.entry.0 as usize] = true;
        queue.push_back(cfg.entry);
    }
    while let Some(block) = queue.pop_front() {
        order.push(block);
        for succ in cfg.succs.get(block.0 as usize).into_iter().flatten() {
            let index = succ.0 as usize;
            if index < seen.len() && !seen[index] {
                seen[index] = true;
                queue.push_back(*succ);
            }
        }
    }
    order
}

struct Tarjan<'a> {
    cfg: &'a Cfg,
    index: u32,
    indices: Vec<Option<u32>>,
    low: Vec<u32>,
    stack: Vec<usize>,
    on_stack: Vec<bool>,
    sccs: Vec<BTreeSet<BlockId>>,
}

fn tarjan(cfg: &Cfg) -> Vec<BTreeSet<BlockId>> {
    let n = cfg.blocks.len();
    let mut search = Tarjan {
        cfg,
        index: 0,
        indices: vec![None; n],
        low: vec![0; n],
        stack: Vec::new(),
        on_stack: vec![false; n],
        sccs: Vec::new(),
    };
    for start in 0..n {
        if search.indices[start].is_none() {
            search.visit(start);
        }
    }
    search.sccs
}

impl Tarjan<'_> {
    fn visit(&mut self, v: usize) {
        self.indices[v] = Some(self.index);
        self.low[v] = self.index;
        self.index += 1;
        self.stack.push(v);
        self.on_stack[v] = true;
        let succs = self.cfg.succs.get(v).cloned().unwrap_or_default();
        for succ in succs {
            let w = succ.0 as usize;
            if w >= self.indices.len() {
                continue;
            }
            if self.indices[w].is_none() {
                self.visit(w);
                self.low[v] = self.low[v].min(self.low[w]);
            } else if self.on_stack[w] {
                self.low[v] = self.low[v].min(self.indices[w].unwrap_or(self.low[v]));
            }
        }
        if self.low[v] == self.indices[v].unwrap_or(u32::MAX) {
            let mut scc = BTreeSet::new();
            while let Some(w) = self.stack.pop() {
                self.on_stack[w] = false;
                scc.insert(BlockId(w as u32));
                if w == v {
                    break;
                }
            }
            self.sccs.push(scc);
        }
    }
}

fn peel(output: &mut LiftOutput, scc: &BTreeSet<BlockId>, entry: BlockId) -> bool {
    let saved_succs = output.func.cfg.succs.clone();
    let mut block_map = BTreeMap::new();
    let mut value_map = HashMap::new();
    let originals: Vec<BlockId> = scc.iter().copied().collect();
    for src in originals {
        let (new_id, local) = clone_block(&mut output.func, src);
        block_map.insert(src, new_id);
        value_map.extend(local);
        if let Some(cases) = output.switch_cases.get(&src).cloned() {
            output.switch_cases.insert(new_id, cases);
        }
        if let Some(labels) = output.func.case_labels.get(&src).cloned() {
            output.func.case_labels.insert(new_id, labels);
        }
    }
    for src in scc {
        let new_id = block_map[src];
        rewrite_copy(
            &mut output.func,
            new_id,
            *src == entry,
            scc,
            &block_map,
            &value_map,
        );
        if let Some(cases) = output.switch_cases.get_mut(&new_id) {
            for target in cases.iter_mut().map(|(_, target)| target) {
                if scc.contains(target) {
                    *target = block_map[target];
                }
            }
        }
    }
    for src in scc {
        let new_id = block_map[src];
        let succs = saved_succs.get(src.0 as usize).cloned().unwrap_or_default();
        for succ in succs {
            let target = if scc.contains(&succ) {
                block_map[&succ]
            } else {
                succ
            };
            add_edge(&mut output.func.cfg, new_id, target);
            if !scc.contains(&succ) {
                mirror_phi(&mut output.func, succ, *src, new_id, &value_map);
            }
        }
    }
    let outside: Vec<BlockId> = output.func.cfg.preds[entry.0 as usize]
        .iter()
        .copied()
        .filter(|pred| !scc.contains(pred))
        .collect();
    if outside.is_empty() {
        return false;
    }
    let copy_entry = block_map[&entry];
    for pred in outside {
        retarget_edge(output, pred, entry, copy_entry);
        strip_phi_pred(&mut output.func, entry, pred);
    }
    copy_types(&mut output.value_types, &value_map);
    output.func.next_value = output.func.values.len() as u32;
    edges_consistent(&output.func.cfg)
}

fn clone_block(func: &mut SsaFunction, src: BlockId) -> (BlockId, HashMap<SsaValueId, SsaValueId>) {
    let new_id = BlockId(func.cfg.blocks.len() as u32);
    let src_block = func.cfg.blocks[src.0 as usize].clone();
    let mut value_map = HashMap::new();
    let mut insts = Vec::new();
    let mut phis = Vec::new();
    for id in src_block.phis.iter().chain(src_block.insts.iter()) {
        let inst = func.values[id.0 as usize].clone();
        let new_value = SsaValueId(func.values.len() as u32);
        value_map.insert(inst.id, new_value);
        let slot = if src_block.phis.contains(id) {
            &mut phis
        } else {
            &mut insts
        };
        slot.push(new_value);
        func.values.push(SsaInstruction {
            id: new_value,
            op: inst.op,
            source_addr: inst.source_addr,
            block: new_id,
        });
    }
    func.cfg.blocks.push(revx_analysis::ssa::CfgBlock {
        id: new_id,
        start_addr: src_block.start_addr,
        end_addr: src_block.end_addr,
        insts,
        phis,
    });
    func.cfg.preds.push(Vec::new());
    func.cfg.succs.push(Vec::new());
    (new_id, value_map)
}

fn rewrite_copy(
    func: &mut SsaFunction,
    block: BlockId,
    peeled_entry: bool,
    scc: &BTreeSet<BlockId>,
    block_map: &BTreeMap<BlockId, BlockId>,
    value_map: &HashMap<SsaValueId, SsaValueId>,
) {
    let ids: Vec<SsaValueId> = func.cfg.blocks[block.0 as usize]
        .phis
        .iter()
        .chain(func.cfg.blocks[block.0 as usize].insts.iter())
        .copied()
        .collect();
    for id in ids {
        match &mut func.values[id.0 as usize].op {
            SsaOp::Jump { target } => {
                if scc.contains(target) {
                    *target = block_map[target];
                }
            }
            SsaOp::Branch {
                cond,
                true_block,
                false_block,
            } => {
                *cond = remap_operand(cond, value_map);
                if scc.contains(true_block) {
                    *true_block = block_map[true_block];
                }
                if scc.contains(false_block) {
                    *false_block = block_map[false_block];
                }
            }
            SsaOp::Phi { incoming } => {
                let mut next = Vec::new();
                for (pred, value) in incoming.drain(..) {
                    let mapped = value_map.get(&value).copied().unwrap_or(value);
                    if scc.contains(&pred) {
                        next.push((block_map[&pred], mapped));
                    } else if peeled_entry {
                        next.push((pred, mapped));
                    }
                }
                *incoming = next;
            }
            other => remap_op_operands(other, value_map),
        }
    }
}

fn remap_op_operands(op: &mut SsaOp, value_map: &HashMap<SsaValueId, SsaValueId>) {
    match op {
        SsaOp::Load { addr } => *addr = remap_operand(addr, value_map),
        SsaOp::Store { addr, value } => {
            *addr = remap_operand(addr, value_map);
            *value = remap_operand(value, value_map);
        }
        SsaOp::BinOp { lhs, rhs, .. } => {
            *lhs = remap_operand(lhs, value_map);
            *rhs = remap_operand(rhs, value_map);
        }
        SsaOp::UnaryOp { src, .. } => *src = remap_operand(src, value_map),
        SsaOp::Copy { src } => *src = remap_operand(src, value_map),
        SsaOp::Call { target, args } => {
            *target = remap_operand(target, value_map);
            for arg in args {
                *arg = remap_operand(arg, value_map);
            }
        }
        SsaOp::Return { value } => {
            if let Some(value) = value {
                *value = remap_operand(value, value_map);
            }
        }
        SsaOp::Branch { cond, .. } => *cond = remap_operand(cond, value_map),
        SsaOp::Jump { .. } | SsaOp::Phi { .. } | SsaOp::Unknown => {}
    }
}

fn remap_operand(op: &Operand, value_map: &HashMap<SsaValueId, SsaValueId>) -> Operand {
    match op {
        Operand::Value(id) => Operand::Value(value_map.get(id).copied().unwrap_or(*id)),
        Operand::Deref { base, offset } => Operand::Deref {
            base: Box::new(remap_operand(base, value_map)),
            offset: *offset,
        },
        other => other.clone(),
    }
}

pub(crate) fn add_edge(cfg: &mut Cfg, from: BlockId, to: BlockId) {
    let succs = &mut cfg.succs[from.0 as usize];
    if !succs.contains(&to) {
        succs.push(to);
    }
    let preds = &mut cfg.preds[to.0 as usize];
    if !preds.contains(&from) {
        preds.push(from);
    }
}

fn mirror_phi(
    func: &mut SsaFunction,
    target: BlockId,
    original_pred: BlockId,
    new_pred: BlockId,
    value_map: &HashMap<SsaValueId, SsaValueId>,
) {
    let phis = func.cfg.blocks[target.0 as usize].phis.clone();
    for phi in phis {
        if let SsaOp::Phi { incoming } = &mut func.values[phi.0 as usize].op {
            if incoming.iter().any(|(pred, _)| *pred == new_pred) {
                continue;
            }
            if let Some((_, value)) = incoming.iter().find(|(pred, _)| *pred == original_pred) {
                let mapped = value_map.get(value).copied().unwrap_or(*value);
                incoming.push((new_pred, mapped));
            }
        }
    }
}

pub(crate) fn retarget_edge(output: &mut LiftOutput, pred: BlockId, from: BlockId, to: BlockId) {
    for succ in &mut output.func.cfg.succs[pred.0 as usize] {
        if *succ == from {
            *succ = to;
        }
    }
    dedup_blocks(&mut output.func.cfg.succs[pred.0 as usize]);
    output.func.cfg.preds[from.0 as usize].retain(|block| *block != pred);
    let preds = &mut output.func.cfg.preds[to.0 as usize];
    if !preds.contains(&pred) {
        preds.push(pred);
    }
    let ids: Vec<SsaValueId> = output.func.cfg.blocks[pred.0 as usize].insts.clone();
    for id in ids {
        match &mut output.func.values[id.0 as usize].op {
            SsaOp::Jump { target } if *target == from => *target = to,
            SsaOp::Branch {
                true_block,
                false_block,
                ..
            } => {
                if *true_block == from {
                    *true_block = to;
                }
                if *false_block == from {
                    *false_block = to;
                }
            }
            _ => {}
        }
    }
    if let Some(cases) = output.switch_cases.get_mut(&pred) {
        for target in cases.iter_mut().map(|(_, target)| target) {
            if *target == from {
                *target = to;
            }
        }
    }
}

fn strip_phi_pred(func: &mut SsaFunction, block: BlockId, pred: BlockId) {
    let phis = func.cfg.blocks[block.0 as usize].phis.clone();
    for phi in phis {
        if let SsaOp::Phi { incoming } = &mut func.values[phi.0 as usize].op {
            incoming.retain(|(from, _)| *from != pred);
        }
    }
}

fn copy_types(types: &mut crate::types::ValueTypes, value_map: &HashMap<SsaValueId, SsaValueId>) {
    let extra: Vec<_> = value_map
        .iter()
        .filter_map(|(old, new)| types.get(old).cloned().map(|ty| (*new, ty)))
        .collect();
    for (id, ty) in extra {
        types.insert(id, ty);
    }
}

fn dedup_blocks(blocks: &mut Vec<BlockId>) {
    let mut seen = BTreeSet::new();
    blocks.retain(|block| seen.insert(*block));
}

pub(crate) fn edges_consistent(cfg: &Cfg) -> bool {
    let n = cfg.blocks.len();
    if cfg.preds.len() != n || cfg.succs.len() != n {
        return false;
    }
    for (index, succs) in cfg.succs.iter().enumerate() {
        for succ in succs {
            let succ_index = succ.0 as usize;
            if succ_index >= n || !cfg.preds[succ_index].contains(&BlockId(index as u32)) {
                return false;
            }
        }
    }
    for (index, preds) in cfg.preds.iter().enumerate() {
        for pred in preds {
            let pred_index = pred.0 as usize;
            if pred_index >= n || !cfg.succs[pred_index].contains(&BlockId(index as u32)) {
                return false;
            }
        }
    }
    true
}
