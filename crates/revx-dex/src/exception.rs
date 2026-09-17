use crate::CodeItem;
use crate::lift::Insn;
use revx_analysis::ssa::{BlockId, Cfg};
use std::collections::{BTreeMap, BTreeSet};

pub const EXCEPTION_FLOW_MEANING: &str = "Conservative metadata-derived block-to-handler edges for every protected block; not instruction-level may-throw analysis or proven runtime dispatch. Normal CFG is unchanged; final goto provenance remains unknown.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandlerKind {
    Typed { type_idx: u32 },
    CatchAll,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandlerRef {
    pub kind: HandlerKind,
    pub addr: u32,
    pub block: Option<BlockId>,
    pub ordinary_entry_reachable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExceptionRegion {
    pub try_index: usize,
    pub start: u32,
    pub insn_count: u16,
    pub end: Option<u32>,
    pub valid_range: bool,
    pub protected_blocks: Vec<BlockId>,
    pub handlers: Vec<HandlerRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandlerUse {
    pub try_index: usize,
    pub handler_index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedHandler {
    pub addr: u32,
    pub block: Option<BlockId>,
    pub references: Vec<HandlerUse>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExceptionEdge {
    pub from: BlockId,
    pub to: BlockId,
    pub try_index: usize,
    pub handler_index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExceptionDiagnostic {
    pub try_index: usize,
    pub handler_index: Option<usize>,
    pub code: &'static str,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExceptionFlow {
    pub regions: Vec<ExceptionRegion>,
    pub shared_handlers: Vec<SharedHandler>,
    pub edges: Vec<ExceptionEdge>,
    pub diagnostics: Vec<ExceptionDiagnostic>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExceptionFlowCounts {
    pub try_regions: usize,
    pub valid_try_regions: usize,
    pub typed_handler_refs: usize,
    pub catch_all_handler_refs: usize,
    pub protected_blocks: usize,
    pub handler_blocks: usize,
    pub ordinary_entry_reachable_handler_blocks: usize,
    pub shared_handler_addresses: usize,
    pub conservative_edges: usize,
    pub diagnostics: usize,
}

impl ExceptionFlowCounts {
    pub fn add(&mut self, other: &Self) {
        self.try_regions += other.try_regions;
        self.valid_try_regions += other.valid_try_regions;
        self.typed_handler_refs += other.typed_handler_refs;
        self.catch_all_handler_refs += other.catch_all_handler_refs;
        self.protected_blocks += other.protected_blocks;
        self.handler_blocks += other.handler_blocks;
        self.ordinary_entry_reachable_handler_blocks +=
            other.ordinary_entry_reachable_handler_blocks;
        self.shared_handler_addresses += other.shared_handler_addresses;
        self.conservative_edges += other.conservative_edges;
        self.diagnostics += other.diagnostics;
    }
}

impl ExceptionFlow {
    pub fn new(code: &CodeItem, insns: &BTreeMap<u32, (Insn, usize)>, cfg: &Cfg) -> Self {
        let mut flow = Self::default();
        if code.tries.is_empty() {
            return flow;
        }
        let len = code.insns.len() as u64;
        let starts: BTreeMap<_, _> = cfg.blocks.iter().map(|b| (b.start_addr, b.id)).collect();
        let mut reachable = BTreeSet::new();
        let mut pending = vec![cfg.entry];
        while let Some(id) = pending.pop() {
            if cfg.blocks.get(id.0 as usize).is_some() && reachable.insert(id) {
                pending.extend(cfg.succs.get(id.0 as usize).into_iter().flatten().copied());
            }
        }
        let instruction = |addr: u32| {
            insns.get(&addr).is_some_and(|(_, size)| {
                *size > 0
                    && (addr as u64)
                        .checked_add(*size as u64)
                        .is_some_and(|end| end <= len)
            })
        };
        let mut uses: BTreeMap<u32, (Option<BlockId>, Vec<HandlerUse>)> = BTreeMap::new();
        for (try_index, t) in code.tries.iter().enumerate() {
            let end = t.start_addr.checked_add(u32::from(t.insn_count));
            let range_error = match end {
                None => Some("range_overflow"),
                Some(_) if t.insn_count == 0 => Some("empty_range"),
                Some(end) if t.start_addr as u64 >= len || end as u64 > len => {
                    Some("range_out_of_bounds")
                }
                Some(end)
                    if !instruction(t.start_addr) || (end as u64 != len && !instruction(end)) =>
                {
                    Some("range_not_instruction_boundary")
                }
                Some(end)
                    if !starts.contains_key(&(t.start_addr as u64))
                        || (end as u64 != len && !starts.contains_key(&(end as u64))) =>
                {
                    Some("range_not_block_boundary")
                }
                _ => None,
            };
            let mut region = ExceptionRegion {
                try_index,
                start: t.start_addr,
                insn_count: t.insn_count,
                end,
                valid_range: range_error.is_none(),
                protected_blocks: Vec::new(),
                handlers: Vec::new(),
            };
            if let Some(code) = range_error {
                flow.diagnostics.push(ExceptionDiagnostic {
                    try_index,
                    handler_index: None,
                    code,
                });
            } else if let Some(end) = end {
                let mut blocks: Vec<_> = cfg
                    .blocks
                    .iter()
                    .filter(|b| b.start_addr >= t.start_addr as u64 && b.start_addr < end as u64)
                    .collect();
                blocks.sort_by_key(|b| b.start_addr);
                let mut cursor = t.start_addr as u64;
                for b in blocks {
                    if b.start_addr != cursor
                        || b.end_addr <= b.start_addr
                        || b.end_addr > end as u64
                        || !instruction(b.start_addr as u32)
                        || (b.end_addr != len && !instruction(b.end_addr as u32))
                    {
                        region.valid_range = false;
                        break;
                    }
                    cursor = b.end_addr;
                    region.protected_blocks.push(b.id);
                }
                if cursor != end as u64 || !region.valid_range {
                    region.valid_range = false;
                    region.protected_blocks.clear();
                    flow.diagnostics.push(ExceptionDiagnostic {
                        try_index,
                        handler_index: None,
                        code: "range_invalid_block_coverage",
                    });
                }
            }
            let handlers = t
                .handlers
                .iter()
                .map(|h| {
                    (
                        HandlerKind::Typed {
                            type_idx: h.type_idx,
                        },
                        h.addr,
                    )
                })
                .chain(t.catch_all_addr.map(|addr| (HandlerKind::CatchAll, addr)));
            for (handler_index, (kind, addr)) in handlers.enumerate() {
                let error = if addr as u64 >= len {
                    Some("handler_out_of_bounds")
                } else if !instruction(addr) {
                    Some("handler_not_instruction_boundary")
                } else if !starts.contains_key(&(addr as u64)) {
                    Some("handler_not_block_boundary")
                } else {
                    None
                };
                let block = if let Some(code) = error {
                    flow.diagnostics.push(ExceptionDiagnostic {
                        try_index,
                        handler_index: Some(handler_index),
                        code,
                    });
                    None
                } else {
                    starts.get(&(addr as u64)).copied()
                };
                let ordinary_entry_reachable = block.is_some_and(|id| reachable.contains(&id));
                region.handlers.push(HandlerRef {
                    kind,
                    addr,
                    block,
                    ordinary_entry_reachable,
                });
                uses.entry(addr)
                    .or_insert_with(|| (block, Vec::new()))
                    .1
                    .push(HandlerUse {
                        try_index,
                        handler_index,
                    });
                if let Some(to) = block {
                    for &from in &region.protected_blocks {
                        flow.edges.push(ExceptionEdge {
                            from,
                            to,
                            try_index,
                            handler_index,
                        });
                    }
                }
            }
            flow.regions.push(region);
        }
        flow.shared_handlers = uses
            .into_iter()
            .filter(|(_, (_, refs))| refs.len() > 1)
            .map(|(addr, (block, references))| SharedHandler {
                addr,
                block,
                references,
            })
            .collect();
        flow
    }

    pub fn counts(&self) -> ExceptionFlowCounts {
        let handlers: Vec<_> = self.regions.iter().flat_map(|r| &r.handlers).collect();
        ExceptionFlowCounts {
            try_regions: self.regions.len(),
            valid_try_regions: self.regions.iter().filter(|r| r.valid_range).count(),
            typed_handler_refs: handlers
                .iter()
                .filter(|h| matches!(h.kind, HandlerKind::Typed { .. }))
                .count(),
            catch_all_handler_refs: handlers
                .iter()
                .filter(|h| h.kind == HandlerKind::CatchAll)
                .count(),
            protected_blocks: self
                .regions
                .iter()
                .flat_map(|r| r.protected_blocks.iter().copied())
                .collect::<BTreeSet<_>>()
                .len(),
            handler_blocks: handlers
                .iter()
                .filter_map(|h| h.block)
                .collect::<BTreeSet<_>>()
                .len(),
            ordinary_entry_reachable_handler_blocks: handlers
                .iter()
                .filter(|h| h.ordinary_entry_reachable)
                .filter_map(|h| h.block)
                .collect::<BTreeSet<_>>()
                .len(),
            shared_handler_addresses: self.shared_handlers.len(),
            conservative_edges: self.edges.len(),
            diagnostics: self.diagnostics.len(),
        }
    }
}
