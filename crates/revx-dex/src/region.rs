use crate::exception::{ExceptionRegion, HandlerKind};
use crate::lift::LiftOutput;
use crate::{CodeItem, DexFile};
use revx_analysis::ssa::{BinOpKind, BlockId, Operand, SsaOp, SsaValueId};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StructuringMode {
    #[default]
    Auto,
    Legacy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegionFallbackReason {
    SharedHandler,
    OrdinaryReachableHandler,
    InvalidTryMetadata,
    NestedOrCrossScope,
    UnsupportedShape,
    Budget,
    ValidationFailed,
}

impl RegionFallbackReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SharedHandler => "shared_handler",
            Self::OrdinaryReachableHandler => "ordinary_reachable_handler",
            Self::InvalidTryMetadata => "invalid_exception_metadata",
            Self::NestedOrCrossScope => "cross_region_edge",
            Self::UnsupportedShape => "unsupported_control_flow",
            Self::Budget => "budget_exceeded",
            Self::ValidationFailed => "validation_failed",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegionPathInfo {
    pub used: bool,
    pub fallback_reason: Option<RegionFallbackReason>,
    pub structured_try_count: usize,
}

#[derive(Clone, Debug)]
pub enum Region {
    Sequence(Vec<Region>),
    Block(BlockId),
    Loop {
        head: BlockId,
        body: Box<Region>,
    },
    Break,
    Continue,
    Switch {
        source: BlockId,
        value: Operand,
        cases: Vec<(Vec<String>, Region)>,
    },
    If {
        source: BlockId,
        condition: Operand,
        yes: Box<Region>,
        no: Box<Region>,
    },
    TryCatch {
        try_index: usize,
        body: Box<Region>,
        catches: Vec<CatchRegion>,
    },
}

#[derive(Clone, Debug)]
pub struct CatchRegion {
    pub kind: HandlerKind,
    pub binding: SsaValueId,
    pub body: Region,
}

#[derive(Clone, Debug)]
pub struct RegionTree {
    pub root: Region,
    pub owned_blocks: BTreeSet<BlockId>,
    pub represented_edges: BTreeSet<(BlockId, BlockId)>,
    pub structured_try_count: usize,
}

pub struct RegionResult {
    pub pseudocode: String,
    pub used_region_path: bool,
    pub fallback_reason: Option<RegionFallbackReason>,
    pub structured_try_count: usize,
}

struct Builder<'a> {
    output: &'a LiftOutput,
    owned: BTreeSet<BlockId>,
    edges: BTreeSet<(BlockId, BlockId)>,
    tries: BTreeSet<usize>,
    work: usize,
    loops: Vec<(BlockId, BlockId)>,
    loop_heads: BTreeSet<BlockId>,
}

type Failure = RegionFallbackReason;

impl Builder<'_> {
    fn path(
        &mut self,
        mut current: BlockId,
        allowed: &BTreeSet<BlockId>,
        stop: Option<BlockId>,
        active_try: Option<usize>,
        depth: usize,
    ) -> Result<Region, Failure> {
        if depth > 48 {
            return Err(Failure::Budget);
        }
        let mut nodes = Vec::new();
        loop {
            if let Some(&(head, exit)) = self.loops.last() {
                if current == exit {
                    nodes.push(Region::Break);
                    break;
                }
                if current == head && self.owned.contains(&head) {
                    nodes.push(Region::Continue);
                    break;
                }
            }
            if Some(current) == stop {
                break;
            }
            self.work += 1;
            if self.work > 4096 {
                return Err(Failure::Budget);
            }
            if !allowed.contains(&current) {
                return Err(Failure::NestedOrCrossScope);
            }
            if let Some(region) = self
                .output
                .exception_flow
                .regions
                .iter()
                .find(|r| {
                    r.protected_blocks.first() == Some(&current) && Some(r.try_index) != active_try
                })
                .cloned()
            {
                if !self.tries.insert(region.try_index) {
                    return Err(Failure::NestedOrCrossScope);
                }
                let protected: BTreeSet<_> = region.protected_blocks.iter().copied().collect();
                if !protected.is_subset(allowed) {
                    return Err(Failure::NestedOrCrossScope);
                }
                let exits: BTreeSet<_> = protected
                    .iter()
                    .flat_map(|b| self.output.func.cfg.succs[b.0 as usize].iter().copied())
                    .filter(|b| !protected.contains(b))
                    .collect();
                if exits.len() > 1 {
                    return Err(Failure::NestedOrCrossScope);
                }
                let join = exits.first().copied();
                self.check_entries(&protected, current)?;
                let body =
                    self.path(current, &protected, join, Some(region.try_index), depth + 1)?;
                let mut catches = Vec::new();
                for handler in &region.handlers {
                    let entry = handler.block.ok_or(Failure::InvalidTryMetadata)?;
                    let members = self.closure(entry, join)?;
                    if members
                        .iter()
                        .any(|b| protected.contains(b) || self.owned.contains(b))
                    {
                        return Err(Failure::NestedOrCrossScope);
                    }
                    self.check_entries(&members, entry)?;
                    if self.output.func.cfg.preds[entry.0 as usize]
                        .iter()
                        .any(|p| !members.contains(p))
                    {
                        return Err(Failure::NestedOrCrossScope);
                    }
                    let block = &self.output.func.cfg.blocks[entry.0 as usize];
                    let binding = *block.insts.first().ok_or(Failure::UnsupportedShape)?;
                    match &self.output.func.values[binding.0 as usize].op {
                        SsaOp::Call {
                            target: Operand::Symbol(s),
                            args,
                        } if s == "__exception" && args.is_empty() => {}
                        _ => return Err(Failure::UnsupportedShape),
                    }
                    let catch_body = self.path(entry, &members, join, None, depth + 1)?;
                    if !members.is_subset(&self.owned) {
                        return Err(Failure::ValidationFailed);
                    }
                    catches.push(CatchRegion {
                        kind: handler.kind.clone(),
                        binding,
                        body: catch_body,
                    });
                }
                nodes.push(Region::TryCatch {
                    try_index: region.try_index,
                    body: Box::new(body),
                    catches,
                });
                if let Some(next) = join {
                    current = next;
                    continue;
                }
                break;
            }
            if self.loop_heads.contains(&current)
                && !self.loops.iter().any(|(head, _)| *head == current)
            {
                let dom = revx_analysis::ssa::DominatorTree::compute(&self.output.func.cfg);
                let mut members = BTreeSet::from([current]);
                let mut pending: Vec<_> = self.output.func.cfg.preds[current.0 as usize]
                    .iter()
                    .copied()
                    .filter(|p| dom.dominates(current, *p))
                    .collect();
                while let Some(b) = pending.pop() {
                    self.work += 1;
                    if self.work > 4096 {
                        return Err(Failure::Budget);
                    }
                    if members.insert(b) {
                        pending.extend(self.output.func.cfg.preds[b.0 as usize].iter().copied());
                    }
                }
                if !members.is_subset(allowed) {
                    return Err(Failure::NestedOrCrossScope);
                }
                self.check_entries(&members, current)?;
                let exits: BTreeSet<_> = members
                    .iter()
                    .flat_map(|b| self.output.func.cfg.succs[b.0 as usize].iter().copied())
                    .filter(|b| !members.contains(b))
                    .collect();
                if exits.len() != 1 {
                    return Err(Failure::UnsupportedShape);
                }
                let exit = *exits.first().unwrap();
                self.loops.push((current, exit));
                let body = self.path(current, &members, None, active_try, depth + 1)?;
                self.loops.pop();
                if !members.is_subset(&self.owned) {
                    return Err(Failure::ValidationFailed);
                }
                nodes.push(Region::Loop {
                    head: current,
                    body: Box::new(body),
                });
                current = exit;
                continue;
            }
            if !self.owned.insert(current) {
                return Err(Failure::UnsupportedShape);
            }
            let block = self
                .output
                .func
                .cfg
                .blocks
                .get(current.0 as usize)
                .ok_or(Failure::ValidationFailed)?;
            if !block.phis.is_empty() {
                return Err(Failure::UnsupportedShape);
            }
            nodes.push(Region::Block(current));
            let successors = &self.output.func.cfg.succs[current.0 as usize];
            let last = block
                .insts
                .last()
                .and_then(|id| self.output.func.values.get(id.0 as usize));
            if let Some(cases) = self.output.switch_cases.get(&current) {
                if !self.loops.is_empty() {
                    return Err(Failure::UnsupportedShape);
                }
                let value = block
                    .insts
                    .iter()
                    .find_map(|id| match &self.output.func.values[id.0 as usize].op {
                        SsaOp::Call {
                            target: Operand::Symbol(s),
                            args,
                        } if s == "__switch" => args.first().cloned(),
                        _ => None,
                    })
                    .ok_or(Failure::UnsupportedShape)?;
                let mut groups = std::collections::BTreeMap::<BlockId, Vec<String>>::new();
                for (key, target) in cases {
                    if key != "default" && key.parse::<i32>().is_err() {
                        return Err(Failure::UnsupportedShape);
                    }
                    groups.entry(*target).or_default().push(key.clone());
                }
                if !cases.iter().any(|(key, _)| key == "default")
                    || groups.keys().copied().collect::<BTreeSet<_>>()
                        != successors.iter().copied().collect()
                {
                    return Err(Failure::UnsupportedShape);
                }
                let mut arms = Vec::new();
                for (target, keys) in groups {
                    self.edges.insert((current, target));
                    let members = self.closure(target, None)?;
                    if !members.is_subset(allowed) || members.iter().any(|b| self.owned.contains(b))
                    {
                        return Err(Failure::UnsupportedShape);
                    }
                    self.check_entries(&members, target)?;
                    let arm = self.path(target, &members, None, active_try, depth + 1)?;
                    arms.push((keys, arm));
                }
                nodes.push(Region::Switch {
                    source: current,
                    value,
                    cases: arms,
                });
                break;
            }
            if let Some(inst) = last {
                match &inst.op {
                    SsaOp::Branch {
                        cond,
                        true_block,
                        false_block,
                    } => {
                        let (yes, no, condition) = (*true_block, *false_block, cond.clone());
                        let expected = BTreeSet::from([yes, no]);
                        if successors.iter().copied().collect::<BTreeSet<_>>() != expected {
                            return Err(Failure::ValidationFailed);
                        }
                        self.edges.insert((current, yes));
                        self.edges.insert((current, no));
                        let join = if self.loops.last().is_some_and(|(head, exit)| {
                            [yes, no].contains(head) || [yes, no].contains(exit)
                        }) {
                            stop
                        } else {
                            self.join(yes, no, stop)?
                        };
                        let then = self.path(yes, allowed, join, active_try, depth + 1)?;
                        let otherwise = self.path(no, allowed, join, active_try, depth + 1)?;
                        nodes.push(Region::If {
                            source: current,
                            condition,
                            yes: Box::new(then),
                            no: Box::new(otherwise),
                        });
                        if let Some(next) = join {
                            current = next;
                            continue;
                        }
                        break;
                    }
                    SsaOp::Return { .. } => {
                        if !successors.is_empty() {
                            return Err(Failure::ValidationFailed);
                        }
                        break;
                    }
                    SsaOp::Jump { target } if successors.as_slice() != [*target] => {
                        return Err(Failure::ValidationFailed);
                    }
                    _ => {}
                }
            }
            match successors.as_slice() {
                [next] => {
                    self.edges.insert((current, *next));
                    current = *next;
                }
                [] => return Err(Failure::UnsupportedShape),
                _ => return Err(Failure::UnsupportedShape),
            }
        }
        Ok(Region::Sequence(nodes))
    }

    fn closure(
        &mut self,
        entry: BlockId,
        stop: Option<BlockId>,
    ) -> Result<BTreeSet<BlockId>, Failure> {
        let mut found = BTreeSet::new();
        let mut pending = vec![entry];
        while let Some(b) = pending.pop() {
            self.work += 1;
            if self.work > 4096 {
                return Err(Failure::Budget);
            }
            if Some(b) == stop || !found.insert(b) {
                continue;
            }
            let edges = self
                .output
                .func
                .cfg
                .succs
                .get(b.0 as usize)
                .ok_or(Failure::ValidationFailed)?;
            pending.extend(edges);
        }
        Ok(found)
    }

    fn join(
        &mut self,
        yes: BlockId,
        no: BlockId,
        stop: Option<BlockId>,
    ) -> Result<Option<BlockId>, Failure> {
        if yes == no {
            return Ok(Some(yes));
        }
        let y = self.closure(yes, stop)?;
        let n = self.closure(no, stop)?;
        let common: BTreeSet<_> = y.intersection(&n).copied().collect();
        if common.is_empty() {
            return Ok(stop);
        }
        let candidates: Vec<_> = common
            .iter()
            .copied()
            .filter(|b| {
                !self.output.func.cfg.preds[b.0 as usize]
                    .iter()
                    .any(|p| common.contains(p))
            })
            .collect();
        if candidates.len() != 1 {
            return Err(Failure::UnsupportedShape);
        }
        Ok(Some(candidates[0]))
    }

    fn check_entries(&self, members: &BTreeSet<BlockId>, entry: BlockId) -> Result<(), Failure> {
        for b in members {
            if *b != entry
                && self.output.func.cfg.preds[b.0 as usize]
                    .iter()
                    .any(|p| !members.contains(p))
            {
                return Err(Failure::NestedOrCrossScope);
            }
        }
        Ok(())
    }
}

fn validate_metadata(output: &LiftOutput, dex: &DexFile) -> Result<(), Failure> {
    let flow = &output.exception_flow;
    if !flow.diagnostics.is_empty()
        || flow
            .regions
            .iter()
            .any(|r| !r.valid_range || r.handlers.is_empty())
    {
        return Err(Failure::InvalidTryMetadata);
    }
    if !flow.shared_handlers.is_empty() {
        return Err(Failure::SharedHandler);
    }
    if flow
        .regions
        .iter()
        .flat_map(|r| &r.handlers)
        .any(|h| h.ordinary_entry_reachable)
    {
        return Err(Failure::OrdinaryReachableHandler);
    }
    let mut ordered: Vec<&ExceptionRegion> = flow.regions.iter().collect();
    ordered.sort_by_key(|r| r.start);
    if ordered
        .windows(2)
        .any(|w| w[0].end.is_none_or(|e| e > w[1].start))
    {
        return Err(Failure::NestedOrCrossScope);
    }
    for h in flow.regions.iter().flat_map(|r| &r.handlers) {
        if let HandlerKind::Typed { type_idx } = h.kind
            && !dex
                .types
                .get(type_idx as usize)
                .is_some_and(|s| s.starts_with('L') && s.ends_with(';'))
        {
            return Err(Failure::InvalidTryMetadata);
        }
    }
    Ok(())
}

pub fn build_region_tree(output: &LiftOutput, dex: &DexFile) -> Result<RegionTree, Failure> {
    if output.func.cfg.blocks.len() > 256 {
        return Err(Failure::Budget);
    }
    validate_metadata(output, dex)?;
    if output
        .func
        .values
        .iter()
        .any(|i| matches!(i.op, SsaOp::Phi { .. }))
    {
        return Err(Failure::UnsupportedShape);
    }
    let all: BTreeSet<_> = output.func.cfg.blocks.iter().map(|b| b.id).collect();
    let dom = revx_analysis::ssa::DominatorTree::compute(&output.func.cfg);
    let loop_heads = output
        .func
        .cfg
        .blocks
        .iter()
        .flat_map(|b| {
            output.func.cfg.succs[b.id.0 as usize]
                .iter()
                .filter(|s| dom.dominates(**s, b.id))
                .copied()
        })
        .collect();
    let mut builder = Builder {
        output,
        owned: BTreeSet::new(),
        edges: BTreeSet::new(),
        tries: BTreeSet::new(),
        work: 0,
        loops: Vec::new(),
        loop_heads,
    };
    let root = builder.path(output.func.cfg.entry, &all, None, None, 0)?;
    let expected: BTreeSet<_> = output
        .func
        .cfg
        .blocks
        .iter()
        .flat_map(|b| {
            output.func.cfg.succs[b.id.0 as usize]
                .iter()
                .map(move |s| (b.id, *s))
        })
        .collect();
    if builder.owned != all
        || builder.edges != expected
        || builder.tries.len() != output.exception_flow.regions.len()
    {
        return Err(Failure::ValidationFailed);
    }
    Ok(RegionTree {
        root,
        owned_blocks: builder.owned,
        represented_edges: builder.edges,
        structured_try_count: builder.tries.len(),
    })
}

fn operand(op: &Operand) -> Result<String, Failure> {
    match op {
        Operand::Value(id) => Ok(format!("v{}", id.0)),
        Operand::Constant(v) => Ok(v.to_string()),
        Operand::Symbol(s) => Ok(s.clone()),
        Operand::Deref { .. } => Err(Failure::UnsupportedShape),
    }
}

fn binop(kind: BinOpKind) -> &'static str {
    match kind {
        BinOpKind::Add => "+",
        BinOpKind::Sub => "-",
        BinOpKind::Mul => "*",
        BinOpKind::Div => "/",
        BinOpKind::Mod => "%",
        BinOpKind::And => "&",
        BinOpKind::Or => "|",
        BinOpKind::Xor => "^",
        BinOpKind::Shl => "<<",
        BinOpKind::Shr => ">>",
        BinOpKind::Sar => ">>>",
        BinOpKind::Eq => "==",
        BinOpKind::Ne => "!=",
        BinOpKind::Lt => "<",
        BinOpKind::Le => "<=",
        BinOpKind::Gt => ">",
        BinOpKind::Ge => ">=",
    }
}

fn emit(
    node: &Region,
    output: &LiftOutput,
    dex: &DexFile,
    depth: usize,
    bindings: &BTreeSet<u32>,
    lines: &mut Vec<String>,
) -> Result<(), Failure> {
    let pad = "    ".repeat(depth);
    match node {
        Region::Sequence(nodes) => {
            for n in nodes {
                emit(n, output, dex, depth, bindings, lines)?;
            }
        }
        Region::Block(id) => {
            for iid in &output.func.cfg.blocks[id.0 as usize].insts {
                let inst = &output.func.values[iid.0 as usize];
                let rhs = match &inst.op {
                    SsaOp::Call {
                        target: Operand::Symbol(s),
                        args,
                    } if s == "__switch"
                        && args.len() == 1
                        && output.switch_cases.contains_key(id)
                        && output.func.cfg.blocks[id.0 as usize].insts.last() == Some(iid) =>
                    {
                        None
                    }
                    SsaOp::Copy { src } => Some(operand(src)?),
                    SsaOp::BinOp { kind, lhs, rhs } => Some(format!(
                        "{} {} {}",
                        operand(lhs)?,
                        binop(*kind),
                        operand(rhs)?
                    )),
                    SsaOp::Call {
                        target: Operand::Symbol(s),
                        args,
                    } if s == "__exception" && args.is_empty() && bindings.contains(&iid.0) => None,
                    SsaOp::Call {
                        target: Operand::Symbol(s),
                        args,
                    } if s.starts_with("@s:") || s.starts_with("@v:") || s.starts_with("@i:") => {
                        let sig = &s[3..];
                        if sig.contains("<init>") || !sig.contains("->") || !sig.contains(')') {
                            return Err(Failure::UnsupportedShape);
                        }
                        let result_used = !sig.ends_with(")V");
                        let arg_texts = args.iter().map(operand).collect::<Result<Vec<_>, _>>()?;
                        let call = crate::render::render_invoke_call(
                            s.as_bytes()[1] as char,
                            sig,
                            &arg_texts,
                            result_used,
                            &format!("v{}", iid.0),
                        );
                        lines.push(format!("{pad}{call}"));
                        None
                    }
                    SsaOp::Return { value } => {
                        lines.push(format!(
                            "{pad}return{};",
                            value
                                .as_ref()
                                .map(|v| operand(v).map(|s| format!(" {s}")))
                                .transpose()?
                                .unwrap_or_default()
                        ));
                        None
                    }
                    SsaOp::Branch { .. } | SsaOp::Jump { .. } => None,
                    _ => return Err(Failure::UnsupportedShape),
                };
                if let Some(rhs) = rhs {
                    lines.push(format!("{pad}v{} = {rhs};", iid.0));
                }
            }
        }
        Region::Loop { body, .. } => {
            lines.push(format!("{pad}while (true) {{"));
            emit(body, output, dex, depth + 1, bindings, lines)?;
            lines.push(format!("{pad}}}"));
        }
        Region::Break => lines.push(format!("{pad}break;")),
        Region::Continue => lines.push(format!("{pad}continue;")),
        Region::Switch { value, cases, .. } => {
            lines.push(format!("{pad}switch ({}) {{", operand(value)?));
            for (keys, body) in cases {
                for key in keys {
                    lines.push(if key == "default" {
                        format!("{pad}default:")
                    } else {
                        format!("{pad}case {key}:")
                    });
                }
                lines.push(format!("{pad}{{"));
                emit(body, output, dex, depth + 1, bindings, lines)?;
                lines.push(format!("{pad}}}"));
            }
            lines.push(format!("{pad}}}"));
        }
        Region::If {
            condition, yes, no, ..
        } => {
            lines.push(format!("{pad}if ({}) {{", operand(condition)?));
            emit(yes, output, dex, depth + 1, bindings, lines)?;
            lines.push(format!("{pad}}} else {{"));
            emit(no, output, dex, depth + 1, bindings, lines)?;
            lines.push(format!("{pad}}}"));
        }
        Region::TryCatch { body, catches, .. } => {
            lines.push(format!("{pad}try {{"));
            emit(body, output, dex, depth + 1, bindings, lines)?;
            for catch in catches {
                let ty = match catch.kind {
                    HandlerKind::Typed { type_idx } => {
                        crate::types::java_type(&dex.types[type_idx as usize])
                    }
                    HandlerKind::CatchAll => "Throwable".into(),
                };
                lines.push(format!("{pad}}} catch ({ty} v{}) {{", catch.binding.0));
                let mut bound = bindings.clone();
                bound.insert(catch.binding.0);
                emit(&catch.body, output, dex, depth + 1, &bound, lines)?;
            }
            lines.push(format!("{pad}}}"));
        }
    }
    Ok(())
}

pub fn render_region_tree(
    tree: &RegionTree,
    output: &LiftOutput,
    dex: &DexFile,
) -> Result<String, Failure> {
    let mut lines = Vec::new();
    emit(&tree.root, output, dex, 1, &BTreeSet::new(), &mut lines)?;
    Ok(lines.join("\n"))
}

pub fn structure_method(
    dex: &DexFile,
    code: &CodeItem,
    method_idx: u32,
    mode: StructuringMode,
) -> RegionResult {
    let output = crate::lift::lift_method_to_ssa(dex, code, method_idx);
    structure_lifted(
        dex,
        &crate::render::build_try_info(dex, &code.tries),
        &output,
        mode,
    )
    .0
}

pub fn structure_lifted(
    dex: &DexFile,
    info: &crate::render::TryInfo,
    output: &LiftOutput,
    mode: StructuringMode,
) -> (RegionResult, crate::structure::StructuringDiagnostics) {
    let reason = if mode == StructuringMode::Auto {
        match build_region_tree(output, dex)
            .and_then(|tree| render_region_tree(&tree, output, dex).map(|text| (tree, text)))
        {
            Ok((tree, pseudocode)) => {
                return (
                    RegionResult {
                        pseudocode,
                        used_region_path: true,
                        fallback_reason: None,
                        structured_try_count: tree.structured_try_count,
                    },
                    Default::default(),
                );
            }
            Err(reason) => Some(reason),
        }
    } else {
        None
    };
    let (pseudocode, diagnostics) =
        crate::render::render_method_pseudocode_with_diagnostics(output, info);
    (
        RegionResult {
            pseudocode,
            used_region_path: false,
            fallback_reason: reason,
            structured_try_count: 0,
        },
        diagnostics,
    )
}
