//! Structured control-flow rendering for lifted Dalvik SSA.
//!
//! javac-produced CFGs are highly structured: diamonds for if/else,
//! single-header loops for while. The structural walk consumes a
//! pre-rendered statement table (block -> lines) plus branch condition
//! text, and emits `if/else` and `while` constructs, falling back to a
//! labeled `goto` per construct when the shape resists structuring.

use revx_analysis::ssa::{BlockId, DominatorTree, SsaFunction};
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
    visited: HashSet<BlockId>,
    goto_targets: BTreeSet<BlockId>,
    block_starts: HashMap<BlockId, usize>,
    loop_stack: Vec<(BlockId, BlockId)>,
    lines: Vec<String>,
    depth: usize,
}

const MAX_DEPTH: usize = 48;
const MAX_LINES: usize = 6000;
const MAX_LOOP_MEMBERS: usize = 128;

pub fn render_structured(func: &SsaFunction, blocks: &HashMap<BlockId, BlockRender>) -> String {
    let mut r = StructuredRenderer::new(func);
    r.walk(func.cfg.entry, blocks, None);
    if r.lines.is_empty() {
        return "    <empty>".to_string();
    }
    let mut insertions: Vec<(usize, String)> = Vec::new();
    let existing_labels: HashSet<String> = r
        .lines
        .iter()
        .filter(|l| l.ends_with(':') && l.starts_with('L'))
        .cloned()
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
    let mut out = String::new();
    for line in &r.lines {
        out.push_str(line);
        out.push('\n');
    }
    out
}

impl<'a> StructuredRenderer<'a> {
    pub fn new(func: &'a SsaFunction) -> Self {
        let dom = DominatorTree::compute(&func.cfg);
        Self {
            func,
            dom,
            visited: HashSet::new(),
            goto_targets: BTreeSet::new(),
            block_starts: HashMap::new(),
            loop_stack: Vec::new(),
            lines: Vec::new(),
            depth: 0,
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
            return;
        }
        if self.visited.contains(&block) {
            self.emit_goto(block);
            return;
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
        if t == join && f == join {
            self.walk(join, blocks, outer_stop);
            return;
        }
        if t == join {
            let negated = negate(cond_text);
            self.push(format!("if ({negated}) {{"));
            self.walk(f, blocks, Some(join));
            self.push("}");
        } else if f == join {
            self.push(format!("if ({cond_text}) {{"));
            self.walk(t, blocks, Some(join));
            self.push("}");
        } else {
            self.push(format!("if ({cond_text}) {{"));
            self.walk(t, blocks, Some(join));
            self.push("} else {");
            self.walk(f, blocks, Some(join));
            self.push("}");
        }
        self.walk(join, blocks, outer_stop);
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
        let mut chain_t = vec![t];
        let mut cur = t;
        for _ in 0..self.func.cfg.blocks.len() {
            let Some(dom) = self.dom.idom_of(cur) else {
                break;
            };
            chain_t.push(dom);
            if dom == cur {
                break;
            }
            cur = dom;
        }
        cur = f;
        for _ in 0..=self.func.cfg.blocks.len() {
            if let Some(pos) = chain_t.iter().position(|&b| b == cur) {
                return chain_t[pos];
            }
            let Some(dom) = self.dom.idom_of(cur) else {
                break;
            };
            if dom == cur {
                break;
            }
            cur = dom;
        }
        f
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
