use crate::exception::{HandlerUse, SharedHandler};
use crate::lift::LiftOutput;
use crate::loopnorm::{
    DEFAULT_MAX_NEW_BLOCKS, add_edge, clone_block, copy_types, edges_consistent, remap_op_operands,
    remap_operand, retarget_edge,
};
use revx_analysis::ssa::{BlockId, Cfg, CfgBlock, Operand, SsaFunction, SsaOp, SsaValueId};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandlerPrepBudget {
    pub max_new_blocks: usize,
}

impl Default for HandlerPrepBudget {
    fn default() -> Self {
        Self {
            max_new_blocks: DEFAULT_MAX_NEW_BLOCKS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandlerPrepRefusal {
    ExpansionBudget,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandlerPrepReport {
    pub nodes_split: usize,
    pub refusal: Option<HandlerPrepRefusal>,
}

pub struct HandlerPrepOutcome {
    pub lift: Option<LiftOutput>,
    pub report: HandlerPrepReport,
}

pub fn prepare_handlers(output: &LiftOutput) -> HandlerPrepOutcome {
    prepare_handlers_with_budget(output, HandlerPrepBudget::default())
}

pub fn prepare_handlers_with_budget(
    output: &LiftOutput,
    budget: HandlerPrepBudget,
) -> HandlerPrepOutcome {
    if !needs_prep(output) {
        return HandlerPrepOutcome {
            lift: None,
            report: HandlerPrepReport {
                nodes_split: 0,
                refusal: None,
            },
        };
    }
    let mut lift = output.clone();
    match prepare(&mut lift, budget.max_new_blocks) {
        Ok(nodes_split) => {
            if nodes_split == 0 {
                return HandlerPrepOutcome {
                    lift: None,
                    report: HandlerPrepReport {
                        nodes_split: 0,
                        refusal: None,
                    },
                };
            }
            lift.func.dom_tree = revx_analysis::ssa::DominatorTree::compute(&lift.func.cfg);
            HandlerPrepOutcome {
                lift: Some(lift),
                report: HandlerPrepReport {
                    nodes_split,
                    refusal: None,
                },
            }
        }
        Err(refusal) => HandlerPrepOutcome {
            lift: None,
            report: HandlerPrepReport {
                nodes_split: 0,
                refusal: Some(refusal),
            },
        },
    }
}

fn needs_prep(output: &LiftOutput) -> bool {
    let flow = &output.exception_flow;
    !flow.shared_handlers.is_empty()
        || flow
            .regions
            .iter()
            .flat_map(|region| &region.handlers)
            .any(|handler| handler.ordinary_entry_reachable)
}

fn prepare(output: &mut LiftOutput, remaining: usize) -> Result<usize, HandlerPrepRefusal> {
    let snapshot = output.clone();
    let mut used = 0usize;
    match prepare_inner(output, remaining, &mut used) {
        Ok(()) => Ok(used),
        Err(reason) => {
            *output = snapshot;
            Err(reason)
        }
    }
}

fn prepare_inner(
    output: &mut LiftOutput,
    remaining: usize,
    used: &mut usize,
) -> Result<(), HandlerPrepRefusal> {
    let ordinary: BTreeSet<BlockId> = output
        .exception_flow
        .regions
        .iter()
        .flat_map(|region| region.handlers.iter())
        .filter(|handler| handler.ordinary_entry_reachable)
        .filter_map(|handler| handler.block)
        .collect();
    for block in ordinary {
        split_ordinary(output, block, remaining, used)?;
    }
    refresh_flow(output);
    let shared = shared_blocks(output);
    for (block, uses) in shared {
        if uses.len() <= 1 {
            continue;
        }
        let body = exception_only_body(&output.func.cfg, block);
        for use_ref in uses.into_iter().skip(1) {
            let mapped = clone_body(output, &body, remaining, used)?;
            let entry = mapped
                .get(&block)
                .copied()
                .ok_or(HandlerPrepRefusal::Unsupported)?;
            let handler = output
                .exception_flow
                .regions
                .get_mut(use_ref.try_index)
                .and_then(|region| region.handlers.get_mut(use_ref.handler_index))
                .ok_or(HandlerPrepRefusal::Unsupported)?;
            handler.block = Some(entry);
            for edge in &mut output.exception_flow.edges {
                if edge.try_index == use_ref.try_index
                    && edge.handler_index == use_ref.handler_index
                {
                    edge.to = entry;
                }
            }
        }
    }
    refresh_flow(output);
    if !edges_consistent(&output.func.cfg) {
        return Err(HandlerPrepRefusal::Unsupported);
    }
    let reachable = ordinary_reachable(&output.func.cfg);
    if output
        .exception_flow
        .regions
        .iter()
        .flat_map(|region| &region.handlers)
        .any(|handler| {
            handler
                .block
                .is_some_and(|block| reachable.contains(&block))
        })
        || !output.exception_flow.shared_handlers.is_empty()
    {
        return Err(HandlerPrepRefusal::Unsupported);
    }
    Ok(())
}

fn split_ordinary(
    output: &mut LiftOutput,
    block: BlockId,
    remaining: usize,
    used: &mut usize,
) -> Result<(), HandlerPrepRefusal> {
    let prefix =
        exception_prefix_len(&output.func, block).ok_or(HandlerPrepRefusal::Unsupported)?;
    if let Some(target) = continuation_target(&output.func, block, prefix) {
        let preds: Vec<BlockId> = output.func.cfg.preds[block.0 as usize].clone();
        for pred in preds {
            retarget_edge(output, pred, block, target);
        }
        if output.func.cfg.entry == block {
            output.func.cfg.entry = target;
        }
        return Ok(());
    }
    if *used + 1 > remaining || output.func.cfg.blocks.len() + 1 > 256 {
        return Err(HandlerPrepRefusal::ExpansionBudget);
    }
    let rest: Vec<SsaValueId> = output.func.cfg.blocks[block.0 as usize].insts[prefix..].to_vec();
    let old_succs = output.func.cfg.succs[block.0 as usize].clone();
    let addr = output.func.cfg.blocks[block.0 as usize].start_addr;
    let cont = BlockId(output.func.cfg.blocks.len() as u32);
    output.func.cfg.blocks.push(CfgBlock {
        id: cont,
        start_addr: addr,
        end_addr: addr,
        insts: Vec::new(),
        phis: Vec::new(),
    });
    output.func.cfg.preds.push(Vec::new());
    output.func.cfg.succs.push(Vec::new());
    *used += 1;
    output.func.cfg.blocks[block.0 as usize]
        .insts
        .truncate(prefix);
    for succ in &old_succs {
        remove_edge(&mut output.func.cfg, block, *succ);
    }
    for id in &rest {
        output.func.values[id.0 as usize].block = cont;
    }
    output.func.cfg.blocks[cont.0 as usize].insts = rest;
    if let Some(cases) = output.switch_cases.remove(&block) {
        output.switch_cases.insert(cont, cases);
    }
    if let Some(labels) = output.func.case_labels.remove(&block) {
        output.func.case_labels.insert(cont, labels);
    }
    let jump = push_jump(&mut output.func, block, cont, addr);
    output.func.cfg.blocks[block.0 as usize].insts.push(jump);
    add_edge(&mut output.func.cfg, block, cont);
    for succ in old_succs {
        add_edge(&mut output.func.cfg, cont, succ);
    }
    let preds: Vec<BlockId> = output.func.cfg.preds[block.0 as usize]
        .iter()
        .copied()
        .filter(|pred| *pred != cont)
        .collect();
    for pred in preds {
        retarget_edge(output, pred, block, cont);
    }
    if output.func.cfg.entry == block {
        output.func.cfg.entry = cont;
    }
    Ok(())
}

fn clone_body(
    output: &mut LiftOutput,
    body: &BTreeSet<BlockId>,
    remaining: usize,
    used: &mut usize,
) -> Result<BTreeMap<BlockId, BlockId>, HandlerPrepRefusal> {
    if body.is_empty() {
        return Err(HandlerPrepRefusal::Unsupported);
    }
    if *used + body.len() > remaining || output.func.cfg.blocks.len() + body.len() > 256 {
        return Err(HandlerPrepRefusal::ExpansionBudget);
    }
    let saved_succs = output.func.cfg.succs.clone();
    let mut block_map = BTreeMap::new();
    let mut value_map = HashMap::new();
    for src in body {
        let (new_id, local) = clone_block(&mut output.func, *src);
        block_map.insert(*src, new_id);
        value_map.extend(local);
        if let Some(cases) = output.switch_cases.get(src).cloned() {
            output.switch_cases.insert(new_id, cases);
        }
        if let Some(labels) = output.func.case_labels.get(src).cloned() {
            output.func.case_labels.insert(new_id, labels);
        }
    }
    *used += body.len();
    for src in body {
        rewrite_clone(
            &mut output.func,
            block_map[src],
            body,
            &block_map,
            &value_map,
        );
        if let Some(cases) = output.switch_cases.get_mut(&block_map[src]) {
            for target in cases.iter_mut().map(|(_, target)| target) {
                if let Some(mapped) = block_map.get(target) {
                    *target = *mapped;
                }
            }
        }
    }
    for src in body {
        let new_id = block_map[src];
        let succs = saved_succs.get(src.0 as usize).cloned().unwrap_or_default();
        for succ in succs {
            let target = block_map.get(&succ).copied().unwrap_or(succ);
            add_edge(&mut output.func.cfg, new_id, target);
        }
    }
    copy_types(&mut output.value_types, &value_map);
    output.func.next_value = output.func.values.len() as u32;
    Ok(block_map)
}

fn rewrite_clone(
    func: &mut SsaFunction,
    block: BlockId,
    body: &BTreeSet<BlockId>,
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
                if let Some(mapped) = block_map.get(target) {
                    *target = *mapped;
                }
            }
            SsaOp::Branch {
                cond,
                true_block,
                false_block,
            } => {
                *cond = remap_operand(cond, value_map);
                if let Some(mapped) = block_map.get(true_block) {
                    *true_block = *mapped;
                }
                if let Some(mapped) = block_map.get(false_block) {
                    *false_block = *mapped;
                }
            }
            SsaOp::Phi { incoming } => {
                let mut next = Vec::new();
                for (pred, value) in incoming.drain(..) {
                    let mapped = value_map.get(&value).copied().unwrap_or(value);
                    if body.contains(&pred) {
                        next.push((block_map[&pred], mapped));
                    }
                }
                *incoming = next;
            }
            other => remap_op_operands(other, value_map),
        }
    }
}

fn exception_prefix_len(func: &SsaFunction, block: BlockId) -> Option<usize> {
    let insts = &func.cfg.blocks[block.0 as usize].insts;
    let first = insts.first()?;
    match &func.values[first.0 as usize].op {
        SsaOp::Call {
            target: Operand::Symbol(name),
            args,
        } if name == "__exception" && args.is_empty() => {}
        _ => return None,
    }
    let mut len = 1;
    if let Some(second) = insts.get(1)
        && let SsaOp::Copy {
            src: Operand::Value(src),
        } = &func.values[second.0 as usize].op
        && src == first
    {
        len = 2;
    }
    Some(len)
}

fn continuation_target(func: &SsaFunction, block: BlockId, prefix: usize) -> Option<BlockId> {
    let insts = &func.cfg.blocks[block.0 as usize].insts[prefix..];
    let succs = func.cfg.succs.get(block.0 as usize)?;
    if insts.is_empty() && succs.len() == 1 {
        return Some(succs[0]);
    }
    if insts.len() == 1
        && let SsaOp::Jump { target } = &func.values[insts[0].0 as usize].op
        && succs.as_slice() == [*target]
    {
        return Some(*target);
    }
    None
}

fn exception_only_body(cfg: &Cfg, entry: BlockId) -> BTreeSet<BlockId> {
    let mut body = BTreeSet::from([entry]);
    let mut changed = true;
    while changed {
        changed = false;
        let members: Vec<BlockId> = body.iter().copied().collect();
        for block in members {
            for succ in cfg.succs.get(block.0 as usize).into_iter().flatten() {
                if body.contains(succ) {
                    continue;
                }
                let preds = cfg
                    .preds
                    .get(succ.0 as usize)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                if !preds.is_empty() && preds.iter().all(|pred| body.contains(pred)) {
                    body.insert(*succ);
                    changed = true;
                }
            }
        }
    }
    body
}

fn shared_blocks(output: &LiftOutput) -> Vec<(BlockId, Vec<HandlerUse>)> {
    let mut uses: BTreeMap<BlockId, Vec<HandlerUse>> = BTreeMap::new();
    for (try_index, region) in output.exception_flow.regions.iter().enumerate() {
        for (handler_index, handler) in region.handlers.iter().enumerate() {
            if let Some(block) = handler.block {
                uses.entry(block).or_default().push(HandlerUse {
                    try_index,
                    handler_index,
                });
            }
        }
    }
    uses.into_iter()
        .filter(|(_, refs)| refs.len() > 1)
        .collect()
}

fn refresh_flow(output: &mut LiftOutput) {
    let reachable = ordinary_reachable(&output.func.cfg);
    let mut uses: BTreeMap<BlockId, (u32, Vec<HandlerUse>)> = BTreeMap::new();
    for (try_index, region) in output.exception_flow.regions.iter_mut().enumerate() {
        for (handler_index, handler) in region.handlers.iter_mut().enumerate() {
            handler.ordinary_entry_reachable = handler
                .block
                .is_some_and(|block| reachable.contains(&block));
            if let Some(block) = handler.block {
                uses.entry(block)
                    .or_insert_with(|| (handler.addr, Vec::new()))
                    .1
                    .push(HandlerUse {
                        try_index,
                        handler_index,
                    });
            }
        }
    }
    output.exception_flow.shared_handlers = uses
        .into_iter()
        .filter(|(_, (_, refs))| refs.len() > 1)
        .map(|(block, (addr, references))| SharedHandler {
            addr,
            block: Some(block),
            references,
        })
        .collect();
}

fn ordinary_reachable(cfg: &Cfg) -> BTreeSet<BlockId> {
    let mut seen = BTreeSet::new();
    let mut pending = VecDeque::new();
    if (cfg.entry.0 as usize) < cfg.blocks.len() {
        pending.push_back(cfg.entry);
    }
    while let Some(block) = pending.pop_front() {
        if !seen.insert(block) {
            continue;
        }
        pending.extend(
            cfg.succs
                .get(block.0 as usize)
                .into_iter()
                .flatten()
                .copied(),
        );
    }
    seen
}

fn remove_edge(cfg: &mut Cfg, from: BlockId, to: BlockId) {
    cfg.succs[from.0 as usize].retain(|block| *block != to);
    cfg.preds[to.0 as usize].retain(|block| *block != from);
}

fn push_jump(func: &mut SsaFunction, block: BlockId, target: BlockId, addr: u64) -> SsaValueId {
    let id = SsaValueId(func.values.len() as u32);
    func.values.push(revx_analysis::ssa::SsaInstruction {
        id,
        op: SsaOp::Jump { target },
        source_addr: addr,
        block,
    });
    func.next_value = func.values.len() as u32;
    id
}
