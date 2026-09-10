//! Structured control-flow rendering for lifted Dalvik SSA.
//!
//! javac-produced CFGs are highly structured: diamonds for if/else,
//! single-header loops for while. The structural walk consumes a
//! pre-rendered statement table (block -> lines) plus branch condition
//! text, and emits `if/else` and `while` constructs, falling back to a
//! labeled `goto` per construct when the shape resists structuring.

use revx_analysis::ssa::{BlockId, Cfg, CfgBlock, DominatorTree, SsaFunction};
use std::collections::{BTreeSet, HashMap, HashSet};

pub struct BlockRender {
    pub lines: Vec<String>,
    pub cond: Option<(String, BlockId, BlockId)>,
    pub jump: Option<BlockId>,
    pub switch: Option<(String, Vec<(String, BlockId)>)>,
}

pub struct StructuredRenderer<'a> {
    func: &'a SsaFunction,
    dom: DominatorTree,
    postdom: DominatorTree,
    exit_id: BlockId,
    loop_heads: HashSet<BlockId>,
    visited: HashSet<BlockId>,
    goto_targets: BTreeSet<BlockId>,
    block_starts: HashMap<BlockId, usize>,
    loop_stack: Vec<(BlockId, BlockId)>,
    lines: Vec<String>,
    depth: usize,
    hop: usize,
    bailed: bool,
}

const MAX_DEPTH: usize = 48;
const MAX_LINES: usize = 6000;
const MAX_LOOP_MEMBERS: usize = 128;

pub fn render_structured(
    func: &SsaFunction,
    blocks: &HashMap<BlockId, BlockRender>,
) -> (String, bool) {
    let mut r = StructuredRenderer::new(func);
    r.walk(func.cfg.entry, blocks, None);
    if r.lines.is_empty() {
        return ("    <empty>".to_string(), r.bailed);
    }
    let mut insertions: Vec<(usize, String)> = Vec::new();
    let existing_labels: HashSet<String> = r
        .lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| l.ends_with(':') && l.starts_with('L'))
        .map(|l| l.to_string())
        .collect();
    for (&target, &start) in &r.block_starts {
        if r.goto_targets.contains(&target) {
            let label = format!("L{}:", target.0);
            if !existing_labels.contains(&label) {
                let indent = r
                    .lines
                    .get(start)
                    .map(|l| l.len() - l.trim_start().len())
                    .unwrap_or(0);
                insertions.push((start, format!("{}{}", " ".repeat(indent), label)));
            }
        }
    }
    insertions.sort_by_key(|(i, _)| *i);
    for (i, (pos, label)) in insertions.iter().enumerate() {
        r.lines.insert(pos + i, label.clone());
    }
    let mut orphans: Vec<&CfgBlock> = func
        .cfg
        .blocks
        .iter()
        .filter(|b| !r.visited.contains(&b.id))
        .collect();
    orphans.sort_by_key(|b| b.start_addr);
    for b in orphans {
        let Some(br) = blocks.get(&b.id) else {
            continue;
        };
        if r.goto_targets.contains(&b.id) {
            r.lines.push(format!("{}L{}:", r.indent(), b.id.0));
        }
        for l in &br.lines {
            r.push(l.clone());
        }
    }
    let mut out = String::new();
    for line in &r.lines {
        out.push_str(line);
        out.push('\n');
    }
    (out, r.bailed)
}

impl<'a> StructuredRenderer<'a> {
    pub fn new(func: &'a SsaFunction) -> Self {
        let dom = DominatorTree::compute(&func.cfg);
        let n = func.cfg.blocks.len();
        let exit_id = BlockId(n as u32);
        let mut rev = Cfg {
            blocks: (0..=n)
                .map(|i| CfgBlock {
                    id: BlockId(i as u32),
                    ..Default::default()
                })
                .collect(),
            preds: vec![Vec::new(); n + 1],
            succs: vec![Vec::new(); n + 1],
            entry: exit_id,
        };
        for (i, _) in func.cfg.blocks.iter().enumerate() {
            if func.cfg.succs.get(i).is_none_or(|s| s.is_empty()) {
                rev.succs[n].push(BlockId(i as u32));
                rev.preds[i].push(exit_id);
            }
            if let Some(preds) = func.cfg.preds.get(i) {
                for &p in preds {
                    rev.succs[i].push(p);
                    rev.preds[p.0 as usize].push(BlockId(i as u32));
                }
            }
        }
        let postdom = DominatorTree::compute(&rev);
        let mut loop_heads = HashSet::new();
        for (i, preds) in func.cfg.preds.iter().enumerate() {
            let head = BlockId(i as u32);
            if preds.iter().any(|&u| u != head && dom.dominates(head, u)) {
                loop_heads.insert(head);
            }
        }
        Self {
            func,
            dom,
            postdom,
            exit_id,
            loop_heads,
            visited: HashSet::new(),
            goto_targets: BTreeSet::new(),
            block_starts: HashMap::new(),
            loop_stack: Vec::new(),
            lines: Vec::new(),
            depth: 0,
            hop: 0,
            bailed: false,
        }
    }

    fn indent(&self) -> String {
        "    ".repeat(self.depth.min(12))
    }

    fn push(&mut self, line: impl Into<String>) {
        let line = line.into();
        self.lines.push(format!("{}{}", self.indent(), line));
    }

    fn emit_goto(&mut self, target: BlockId) {
        if let Some(&(head, exit)) = self.loop_stack.last() {
            if target == exit {
                self.push("break;");
                return;
            }
            if target == head {
                let is_latch = self
                    .lines
                    .last()
                    .is_some_and(|l| !l.trim().is_empty() && !l.trim().starts_with('}'));
                if is_latch {
                    self.push("continue;");
                }
                return;
            }
        }
        self.goto_targets.insert(target);
        self.push(format!("goto L{};", target.0));
    }

    fn loop_members(&self, head: BlockId) -> HashSet<BlockId> {
        let mut members = HashSet::new();
        members.insert(head);
        let mut stack: Vec<BlockId> = Vec::new();
        if let Some(preds) = self.func.cfg.preds.get(head.0 as usize) {
            for &u in preds {
                if u != head && self.dom.dominates(head, u) {
                    stack.push(u);
                }
            }
        }
        while let Some(b) = stack.pop() {
            if !members.insert(b) {
                continue;
            }
            if let Some(preds) = self.func.cfg.preds.get(b.0 as usize) {
                for &p in preds {
                    if p != head {
                        stack.push(p);
                    }
                }
            }
        }
        members
    }

    fn loop_exit(&self, members: &HashSet<BlockId>) -> Option<BlockId> {
        let mut exit: Option<BlockId> = None;
        for &m in members {
            let Some(succs) = self.func.cfg.succs.get(m.0 as usize) else {
                continue;
            };
            for &s in succs {
                if members.contains(&s) {
                    continue;
                }
                match exit {
                    None => exit = Some(s),
                    Some(e) if e == s => {}
                    Some(_) => return None,
                }
            }
        }
        exit
    }

    fn walk(
        &mut self,
        block: BlockId,
        blocks: &HashMap<BlockId, BlockRender>,
        stop_at: Option<BlockId>,
    ) {
        if let Some(&(_, exit)) = self.loop_stack.last()
            && block == exit
            && !self.visited.contains(&block)
        {
            self.push("break;");
            return;
        }
        if Some(block) == stop_at {
            return;
        }
        if self.depth > MAX_DEPTH || self.lines.len() > MAX_LINES {
            self.bailed = true;
            return;
        }
        if self.visited.contains(&block) {
            if self.hop < 16
                && let Some(render) = blocks.get(&block)
                && render.cond.is_none()
                && render.switch.is_none()
                && render
                    .lines
                    .iter()
                    .all(|l| l.trim().is_empty() || l.trim().starts_with("//"))
                && let Some(next) = render.jump
                && next != block
            {
                self.hop += 1;
                self.walk(next, blocks, stop_at);
                self.hop -= 1;
                return;
            }
            self.emit_goto(block);
            return;
        }
        if self.loop_heads.contains(&block) && !self.loop_stack.iter().any(|(h, _)| *h == block) {
            let pretty = blocks
                .get(&block)
                .and_then(|r| r.cond.as_ref())
                .is_some_and(|(_, t, f)| self.while_shape(block, *t, *f).is_some());
            if !pretty {
                let members = self.loop_members(block);
                if let Some(exit) = self.loop_exit(&members) {
                    self.push("while (true) {");
                    self.loop_stack.push((block, exit));
                    self.walk(block, blocks, Some(exit));
                    self.loop_stack.pop();
                    self.push("}");
                    self.walk(exit, blocks, stop_at);
                    return;
                }
            }
        }
        self.visited.insert(block);
        self.depth += 1;
        self.block_starts.insert(block, self.lines.len());

        let Some(render) = blocks.get(&block) else {
            self.depth -= 1;
            return;
        };
        for line in &render.lines {
            self.lines.push(format!("{}{}", self.indent(), line));
        }

        if let Some((cond_text, t, f)) = &render.cond {
            let cond_text = cond_text.clone();
            let (t, f) = (*t, *f);
            self.handle_branch(block, &cond_text, t, f, blocks, stop_at);
        } else if let Some(target) = render.jump {
            self.handle_jump(target, blocks, stop_at);
        } else if let Some((switch_val, cases)) = &render.switch {
            let switch_val = switch_val.clone();
            let cases = cases.clone();
            self.handle_switch(&switch_val, &cases, blocks, stop_at);
        }
        self.depth -= 1;
    }

    fn handle_branch(
        &mut self,
        head: BlockId,
        cond_text: &str,
        t: BlockId,
        f: BlockId,
        blocks: &HashMap<BlockId, BlockRender>,
        outer_stop: Option<BlockId>,
    ) {
        if let Some((body, exit)) = self.while_shape(head, t, f) {
            let cond = if body == t {
                cond_text.to_string()
            } else {
                negate(cond_text)
            };
            self.push(format!("while ({cond}) {{"));
            self.loop_stack.push((head, exit));
            self.walk(body, blocks, Some(exit));
            self.loop_stack.pop();
            self.push("}");
            self.walk(exit, blocks, outer_stop);
            return;
        }
        let join = self.join_of(t, f);
        let is_virtual = join == self.exit_id;
        let stop = if is_virtual { None } else { Some(join) };
        if !is_virtual && t == join && f == join {
            self.walk(join, blocks, outer_stop);
            return;
        }
        if !is_virtual && t == join {
            let negated = negate(cond_text);
            self.push(format!("if ({negated}) {{"));
            self.walk(f, blocks, stop);
            self.push("}");
        } else if !is_virtual && f == join {
            self.push(format!("if ({cond_text}) {{"));
            self.walk(t, blocks, stop);
            self.push("}");
        } else {
            self.push(format!("if ({cond_text}) {{"));
            self.walk(t, blocks, stop);
            self.push("} else {");
            self.walk(f, blocks, stop);
            self.push("}");
        }
        if !is_virtual && Some(join) != outer_stop {
            self.walk(join, blocks, outer_stop);
        }
    }

    fn handle_jump(
        &mut self,
        target: BlockId,
        blocks: &HashMap<BlockId, BlockRender>,
        stop_at: Option<BlockId>,
    ) {
        if self.visited.contains(&target) {
            self.emit_goto(target);
            return;
        }
        self.walk(target, blocks, stop_at);
    }

    fn handle_switch(
        &mut self,
        switch_val: &str,
        cases: &[(String, BlockId)],
        blocks: &HashMap<BlockId, BlockRender>,
        stop_at: Option<BlockId>,
    ) {
        self.push(format!("switch ({switch_val}) {{"));
        for (key, target) in cases {
            self.push(format!("case {key}:"));
            self.walk(*target, blocks, stop_at);
        }
        self.push("}");
        let after = cases.iter().map(|(_, t)| t.0).max().map(|m| BlockId(m + 1));
        if let Some(next) = after
            && (next.0 as usize) < self.func.cfg.blocks.len()
        {
            self.walk(next, blocks, stop_at);
        }
    }

    fn while_shape(&self, head: BlockId, t: BlockId, f: BlockId) -> Option<(BlockId, BlockId)> {
        if t == f {
            return None;
        }
        if self.find_latch(head, t, f).is_some() {
            return Some((t, f));
        }
        if self.find_latch(head, f, t).is_some() {
            return Some((f, t));
        }
        None
    }

    fn find_latch(&self, head: BlockId, from: BlockId, exit: BlockId) -> Option<BlockId> {
        let mut visited = HashSet::new();
        let mut stack = vec![from];
        while let Some(block) = stack.pop() {
            if block == exit || block == head {
                continue;
            }
            if !visited.insert(block) {
                continue;
            }
            if visited.len() > MAX_LOOP_MEMBERS {
                return None;
            }
            if !self.dom.dominates(head, block) {
                continue;
            }
            let succs = &self.func.cfg.succs[block.0 as usize];
            for succ in succs {
                if *succ == head {
                    return Some(block);
                }
                stack.push(*succ);
            }
        }
        None
    }

    fn join_of(&self, t: BlockId, f: BlockId) -> BlockId {
        let limit = self.func.cfg.blocks.len() + 2;
        let mut chain_t = vec![t];
        let mut cur = t;
        for _ in 0..limit {
            let Some(dom) = self.postdom.idom_of(cur) else {
                break;
            };
            chain_t.push(dom);
            if dom == cur || dom == self.exit_id {
                break;
            }
            cur = dom;
        }
        cur = f;
        for _ in 0..limit {
            if chain_t.contains(&cur) {
                return cur;
            }
            let Some(dom) = self.postdom.idom_of(cur) else {
                break;
            };
            if dom == cur {
                break;
            }
            cur = dom;
        }
        self.exit_id
    }
}

fn negate(cond: &str) -> String {
    if let Some(inner) = cond.strip_prefix("!(") {
        return inner.strip_suffix(')').unwrap_or(cond).to_string();
    }
    if cond.contains(" == ") {
        return cond.replace(" == ", " != ");
    }
    if cond.contains(" != ") {
        return cond.replace(" != ", " == ");
    }
    if cond.contains(" <=") {
        return cond.replace(" <=", " >");
    }
    if cond.contains(" >=") {
        return cond.replace(" >=", " <");
    }
    if cond.contains(" < ") && !cond.contains("<<") {
        return cond.replace(" < ", " >= ");
    }
    if cond.contains(" > ") && !cond.contains(">>") {
        return cond.replace(" > ", " <= ");
    }
    format!("!({cond})")
}
