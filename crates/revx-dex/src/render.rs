//! Java-style pseudocode rendering for lifted Dalvik SSA.

use crate::lift::lift_method_to_ssa;
use crate::{CodeItem, DexFile};
use revx_analysis::ssa::{BlockId, Operand, SsaFunction, SsaOp, SsaValueId};
use std::collections::{HashMap, HashSet};

struct RenderCtx<'a> {
    func: &'a SsaFunction,
    value_names: HashMap<SsaValueId, String>,
    emitted_defs: HashSet<SsaValueId>,
    value_types: crate::types::ValueTypes,
}

impl<'a> RenderCtx<'a> {
    fn new(func: &'a SsaFunction) -> Self {
        Self {
            func,
            value_names: HashMap::new(),
            emitted_defs: HashSet::new(),
            value_types: HashMap::new(),
        }
    }

    fn name_of(&mut self, id: SsaValueId) -> String {
        if let Some(name) = self.value_names.get(&id) {
            return name.clone();
        }
        let name = format!("v{}", self.value_names.len());
        self.value_names.insert(id, name.clone());
        name
    }

    fn operand_text(&mut self, op: &Operand) -> String {
        match op {
            Operand::Value(id) => self.value_text(*id),
            Operand::Constant(v) => format!("{v}"),
            Operand::Symbol(s) => s.clone(),
            Operand::Deref { base, offset } => {
                let base_text = self.operand_text(base);
                if *offset == 0 {
                    format!("*{base_text}")
                } else {
                    format!("*({base_text} + {offset})")
                }
            }
        }
    }

    fn resolve_cmp(&mut self, op: &Operand) -> Option<(String, String)> {
        enum Step {
            Cmp(Vec<Operand>),
            Follow(SsaValueId),
            Stop,
        }
        let Operand::Value(mut id) = *op else {
            return None;
        };
        for _ in 0..4 {
            let step = {
                let inst = self.func.values.get(id.0 as usize)?;
                match &inst.op {
                    SsaOp::Call {
                        target: Operand::Symbol(s),
                        args,
                    } if (s.starts_with("cmpl_") || s.starts_with("cmpg_") || s == "cmp_long")
                        && args.len() == 2 =>
                    {
                        Step::Cmp(args.clone())
                    }
                    SsaOp::Copy {
                        src: Operand::Value(v),
                    } => Step::Follow(*v),
                    _ => Step::Stop,
                }
            };
            match step {
                Step::Cmp(args) => {
                    let a = self.operand_text(&args[0]);
                    let b = self.operand_text(&args[1]);
                    return Some((a, b));
                }
                Step::Follow(v) => id = v,
                Step::Stop => return None,
            }
        }
        None
    }

    fn cond_text(&mut self, cond: &Operand) -> String {
        let Operand::Value(id) = cond else {
            return self.operand_text(cond);
        };
        let Some(inst) = self.func.values.get(id.0 as usize) else {
            return format!("v{}", id.0);
        };
        match &inst.op {
            SsaOp::BinOp { kind, lhs, rhs } => {
                let op = match kind {
                    revx_analysis::ssa::BinOpKind::Eq => "==",
                    revx_analysis::ssa::BinOpKind::Ne => "!=",
                    revx_analysis::ssa::BinOpKind::Lt => "<",
                    revx_analysis::ssa::BinOpKind::Le => "<=",
                    revx_analysis::ssa::BinOpKind::Gt => ">",
                    revx_analysis::ssa::BinOpKind::Ge => ">=",
                    _ => "?",
                };
                let r = self.operand_text(rhs);
                if r == "0"
                    && let Some((a, b)) = self.resolve_cmp(lhs)
                {
                    return format!("{a} {op} {b}");
                }
                let l = self.operand_text(lhs);
                format!("{l} {op} {r}")
            }
            _ => self.value_text(*id),
        }
    }

    fn value_text(&mut self, id: SsaValueId) -> String {
        if let Some(inst) = self.func.values.get(id.0 as usize) {
            match &inst.op {
                SsaOp::Copy { src } => match src {
                    Operand::Symbol(s) => {
                        if s.starts_with('p') || s == "this" {
                            return s.clone();
                        }
                        self.name_of(id)
                    }
                    Operand::Constant(_) | Operand::Value(_) | Operand::Deref { .. } => {
                        self.name_of(id)
                    }
                },
                SsaOp::Phi { .. } => self.name_of(id),
                _ => self.name_of(id),
            }
        } else {
            format!("v{id:?}")
        }
    }

    fn resolve_param_alias(&self, id: SsaValueId, depth: usize) -> Option<String> {
        if depth > 4 {
            return None;
        }
        let inst = self.func.values.get(id.0 as usize)?;
        match &inst.op {
            SsaOp::Copy { src } => match src {
                Operand::Symbol(s) => {
                    if s == "this"
                        || (s.starts_with('p') && s[1..].chars().all(|c| c.is_ascii_digit()))
                    {
                        Some(s.clone())
                    } else {
                        None
                    }
                }
                Operand::Value(other) => self.resolve_param_alias(*other, depth + 1),
                _ => None,
            },
            _ => None,
        }
    }

    fn render_inst(&mut self, id: SsaValueId) -> Option<String> {
        let inst = self.func.values.get(id.0 as usize)?;
        let line = match &inst.op {
            SsaOp::Copy { src } => {
                if self.emitted_defs.contains(&id) {
                    return None;
                }
                self.emitted_defs.insert(id);
                if let Some(param) = self.resolve_param_alias(id, 0) {
                    self.value_names.insert(id, param);
                    return None;
                }
                let src_text = self.operand_text(src);
                let name = self.name_of(id);
                if src_text == name {
                    return None;
                }
                format!("{name} = {src_text};")
            }
            SsaOp::BinOp { kind, lhs, rhs } => {
                if self.emitted_defs.contains(&id) {
                    return None;
                }
                self.emitted_defs.insert(id);
                let l = self.operand_text(lhs);
                let r = self.operand_text(rhs);
                let op = match kind {
                    revx_analysis::ssa::BinOpKind::Add => "+",
                    revx_analysis::ssa::BinOpKind::Sub => "-",
                    revx_analysis::ssa::BinOpKind::Mul => "*",
                    revx_analysis::ssa::BinOpKind::Div => "/",
                    revx_analysis::ssa::BinOpKind::Mod => "%",
                    revx_analysis::ssa::BinOpKind::And => "&",
                    revx_analysis::ssa::BinOpKind::Or => "|",
                    revx_analysis::ssa::BinOpKind::Xor => "^",
                    revx_analysis::ssa::BinOpKind::Shl => "<<",
                    revx_analysis::ssa::BinOpKind::Shr => ">>",
                    revx_analysis::ssa::BinOpKind::Sar => ">>>",
                    revx_analysis::ssa::BinOpKind::Eq => "==",
                    revx_analysis::ssa::BinOpKind::Ne => "!=",
                    revx_analysis::ssa::BinOpKind::Lt => "<",
                    revx_analysis::ssa::BinOpKind::Le => "<=",
                    revx_analysis::ssa::BinOpKind::Gt => ">",
                    revx_analysis::ssa::BinOpKind::Ge => ">=",
                };
                let name = self.name_of(id);
                format!("{name} = {l} {op} {r};")
            }
            SsaOp::UnaryOp { kind, src } => {
                if self.emitted_defs.contains(&id) {
                    return None;
                }
                self.emitted_defs.insert(id);
                let s = self.operand_text(src);
                let op = match kind {
                    revx_analysis::ssa::UnaryOpKind::Neg => "-",
                    revx_analysis::ssa::UnaryOpKind::Not => "~",
                    revx_analysis::ssa::UnaryOpKind::Bswap => "bswap",
                };
                let name = self.name_of(id);
                format!("{name} = {op}{s};")
            }
            SsaOp::Load { addr } => {
                if self.emitted_defs.contains(&id) {
                    return None;
                }
                self.emitted_defs.insert(id);
                let a = self.operand_text(addr);
                let name = self.name_of(id);
                format!("{name} = *{a};")
            }
            SsaOp::Store { addr, value } => {
                let a = self.operand_text(addr);
                let v = self.operand_text(value);
                format!("*{a} = {v};")
            }
            SsaOp::Call { target, args } => {
                let t = self.operand_text(target);
                let arg_texts: Vec<String> = args.iter().map(|a| self.operand_text(a)).collect();
                if t.starts_with("__aget") {
                    let arr = arg_texts.first().cloned().unwrap_or_default();
                    let idx = arg_texts.get(1).cloned().unwrap_or_default();
                    let name = self.name_of(id);
                    format!("{name} = {arr}[{idx}];")
                } else if t.starts_with("__aput") {
                    let arr = arg_texts.first().cloned().unwrap_or_default();
                    let idx = arg_texts.get(1).cloned().unwrap_or_default();
                    let val = arg_texts.get(2).cloned().unwrap_or_default();
                    format!("{arr}[{idx}] = {val};")
                } else if t.starts_with("__iget:") {
                    let field = t.strip_prefix("__iget:").unwrap_or("");
                    let obj = arg_texts.first().cloned().unwrap_or_default();
                    let fname = field_name(field);
                    let name = self.name_of(id);
                    format!("{name} = {obj}.{fname};")
                } else if t.starts_with("__iput:") {
                    let field = t.strip_prefix("__iput:").unwrap_or("");
                    let obj = arg_texts.first().cloned().unwrap_or_default();
                    let val = arg_texts.get(1).cloned().unwrap_or_default();
                    let fname = field_name(field);
                    format!("{obj}.{fname} = {val};")
                } else if t.starts_with("__sget:") {
                    let field = t.strip_prefix("__sget:").unwrap_or("");
                    let fname = field_name(field);
                    let owner = field_class(field);
                    let name = self.name_of(id);
                    format!("{name} = {owner}.{fname};")
                } else if t.starts_with("__sput:") {
                    let field = t.strip_prefix("__sput:").unwrap_or("");
                    let val = arg_texts.first().cloned().unwrap_or_default();
                    let fname = field_name(field);
                    let owner = field_class(field);
                    format!("{owner}.{fname} = {val};")
                } else if t.starts_with("new ") {
                    let ty_desc = t.strip_prefix("new ").unwrap_or("");
                    let name = self.name_of(id);
                    let class_name = clean_type_name(ty_desc);
                    if args.is_empty() {
                        format!("{name} = new {class_name}();")
                    } else {
                        format!("{name} = new {class_name}({});", arg_texts.join(", "))
                    }
                } else if t == "monitorEnter" {
                    format!(
                        "synchronized ({}) {{",
                        arg_texts.first().cloned().unwrap_or_default()
                    )
                } else if t == "monitorExit" {
                    "}".to_string()
                } else if t == "throw" {
                    format!("throw {};", arg_texts.first().cloned().unwrap_or_default())
                } else if t.starts_with("instanceof ") {
                    let ty = t.strip_prefix("instanceof ").unwrap_or("");
                    let obj = arg_texts.first().cloned().unwrap_or_default();
                    let name = self.name_of(id);
                    format!("{name} = ({obj} instanceof {});", clean_type_name(ty))
                } else if t.starts_with('(') && t.ends_with(')') {
                    let ty = &t[1..t.len() - 1];
                    let obj = arg_texts.first().cloned().unwrap_or_default();
                    let name = self.name_of(id);
                    format!("{name} = ({}) {obj};", clean_type_name(ty))
                } else if t == "arrayLength" {
                    let arr = arg_texts.first().cloned().unwrap_or_default();
                    let name = self.name_of(id);
                    format!("{name} = {arr}.length;")
                } else if t == "fillArrayData" {
                    format!("// fill-array-data {}", arg_texts.join(", "))
                } else if t.starts_with("cmpl_") || t.starts_with("cmpg_") || t == "cmp_long" {
                    let l = arg_texts.first().cloned().unwrap_or_default();
                    let r = arg_texts.get(1).cloned().unwrap_or_default();
                    let name = self.name_of(id);
                    format!("{name} = ({l} < {r} ? -1 : ({l} == {r} ? 0 : 1));")
                } else if t == "__switch" {
                    format!(
                        "// switch ({})",
                        arg_texts.first().cloned().unwrap_or_default()
                    )
                } else if t == "__exception" {
                    "// exception handler".to_string()
                } else if let Some(rest) = t.strip_prefix("@lcs:") {
                    let (iface, impl_sig) = rest.split_once(':').unwrap_or((rest, ""));
                    let mr = crate::lift::format_method_ref(impl_sig);
                    let name = self.name_of(id);
                    if arg_texts.is_empty() {
                        format!("{name} = ({iface}) {mr};")
                    } else {
                        format!("{name} = ({iface}) ({}) -> {mr};", arg_texts.join(", "))
                    }
                } else if t.starts_with("@cs:") {
                    let cs = t.strip_prefix("@cs:").unwrap_or("");
                    let name = self.name_of(id);
                    format!("{name} = invokedynamic@{cs}({});", arg_texts.join(", "))
                } else if t.starts_with('@') && t.len() > 3 && &t[2..3] == ":" {
                    let kind_char = t.chars().nth(1).unwrap_or('v');
                    let sig = &t[3..];
                    let is_used = self.is_used(id);
                    let name = self.name_of(id);
                    render_invoke_call(kind_char, sig, &arg_texts, is_used, &name)
                } else {
                    let is_used = self.is_used(id);
                    let name = self.name_of(id);
                    if is_used {
                        format!("{name} = {t}({});", arg_texts.join(", "))
                    } else {
                        format!("{t}({});", arg_texts.join(", "))
                    }
                }
            }
            SsaOp::Return { value } => match value {
                Some(v) => {
                    let v_text = self.operand_text(v);
                    format!("return {v_text};")
                }
                None => "return;".to_string(),
            },
            SsaOp::Branch {
                cond,
                true_block,
                false_block,
            } => {
                let c = self.operand_text(cond);
                format!(
                    "if ({c}) goto L{}; else goto L{};",
                    true_block.0, false_block.0
                )
            }
            SsaOp::Jump { target } => {
                format!("goto L{};", target.0)
            }
            SsaOp::Phi { .. } => {
                if self.emitted_defs.contains(&id) {
                    return None;
                }
                self.emitted_defs.insert(id);
                let name = self.name_of(id);
                format!("{name} = phi();")
            }
            SsaOp::Unknown => "// unknown".to_string(),
        };
        Some(line)
    }

    fn is_used(&self, id: SsaValueId) -> bool {
        self.func.values.iter().any(|inst| match &inst.op {
            SsaOp::BinOp { lhs, rhs, .. } => operand_uses(lhs, id) || operand_uses(rhs, id),
            SsaOp::UnaryOp { src, .. } => operand_uses(src, id),
            SsaOp::Copy { src } => operand_uses(src, id),
            SsaOp::Call { args, .. } => args.iter().any(|a| operand_uses(a, id)),
            SsaOp::Store { value, .. } => operand_uses(value, id),
            SsaOp::Return { value } => value.as_ref().is_some_and(|v| operand_uses(v, id)),
            _ => false,
        })
    }
}

fn operand_uses(op: &Operand, id: SsaValueId) -> bool {
    match op {
        Operand::Value(v) => *v == id,
        Operand::Deref { base, .. } => operand_uses(base, id),
        _ => false,
    }
}

fn reverse_post_order(func: &SsaFunction) -> Vec<BlockId> {
    let n = func.cfg.blocks.len();
    if n == 0 {
        return vec![];
    }
    let mut visited = vec![false; n];
    let mut post: Vec<BlockId> = Vec::with_capacity(n);
    let mut stack: Vec<(BlockId, usize)> = vec![(func.cfg.entry, 0)];
    visited[func.cfg.entry.0 as usize] = true;
    while let Some(&mut (bid, ref mut next)) = stack.last_mut() {
        let succs = func
            .cfg
            .succs
            .get(bid.0 as usize)
            .cloned()
            .unwrap_or_default();
        if *next < succs.len() {
            let succ = succs[*next];
            *next += 1;
            if (succ.0 as usize) < n && !visited[succ.0 as usize] {
                visited[succ.0 as usize] = true;
                stack.push((succ, 0));
            }
        } else {
            post.push(bid);
            stack.pop();
        }
    }
    post.reverse();
    post
}

fn apply_typed_declarations(
    text: &str,
    value_types: &crate::types::ValueTypes,
    name_to_id: &HashMap<String, SsaValueId>,
) -> String {
    let mut var_type: HashMap<String, String> = HashMap::new();
    for (name, id) in name_to_id {
        if let Some(t) = value_types.get(id)
            && !t.is_empty()
        {
            var_type.insert(name.clone(), crate::types::java_type(t));
        }
    }
    if var_type.is_empty() {
        return text.to_string();
    }
    let mut out_lines: Vec<String> = Vec::new();
    let mut declared: HashSet<String> = HashSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some((var, rest)) = trimmed.strip_suffix(';').and_then(|l| l.split_once(" = ")) {
            let var = var.trim();
            if let Some(t) = var_type.get(var)
                && !declared.contains(var)
                && var.starts_with('v')
                && !rest.trim().starts_with("new ")
            {
                declared.insert(var.to_string());
                let indent_len = line.len() - line.trim_start().len();
                out_lines.push(format!("{}{t} {var} = {rest};", " ".repeat(indent_len)));
                continue;
            }
        }
        out_lines.push(line.to_string());
    }
    out_lines.join("\n")
}

fn fuse_new_init(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim().to_string();
        let Some((var, expr)) = line.strip_suffix(';').and_then(|l| l.split_once(" = ")) else {
            i += 1;
            continue;
        };
        if !expr.starts_with("new ") || !expr.ends_with("()") {
            i += 1;
            continue;
        }
        let Some(class_part) = expr.strip_prefix("new ").and_then(|r| r.strip_suffix("()")) else {
            i += 1;
            continue;
        };
        let mut fused = false;
        for j in (i + 1)..lines.len().min(i + 40) {
            let l = lines[j].trim().to_string();
            let def_pattern = format!("{var} = ");
            let comma_pattern = format!("{var},");
            if l.starts_with(&def_pattern) || l.contains(&comma_pattern) {
                break;
            }
            if l.contains("<init>") || l.contains("super(") {
                break;
            }
            if let Some((_m_var, m_expr)) = l.strip_suffix(';').and_then(|x| x.split_once(" = "))
                && let Some(after_new) = m_expr.strip_prefix("new ")
            {
                let chars: Vec<char> = after_new.chars().collect();
                let Some(open) = chars.iter().position(|&c| c == '(') else {
                    continue;
                };
                let m_class: String = chars[..open].iter().collect();
                if m_class != class_part {
                    continue;
                }
                let Some(close) = paren_match(&chars, open) else {
                    continue;
                };
                if close != chars.len() - 1 {
                    continue;
                }
                let args: String = chars[open + 1..close].iter().collect();
                let indent_len = lines[i].len() - lines[i].trim_start().len();
                lines[i] = format!(
                    "{}{var} = new {class_part}({args});",
                    " ".repeat(indent_len)
                );
                lines.remove(j);
                fused = true;
                break;
            }
        }
        if fused {
            continue;
        }
        i += 1;
    }
    lines.join("\n")
}

fn apply_copy_chain_collapse(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let mut changed = true;
    let mut rounds = 0;
    while changed && rounds < 10 {
        changed = false;
        rounds += 1;
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i].trim().to_string();
            let Some((raw_var, expr)) = line.strip_suffix(';').and_then(|l| l.split_once(" = "))
            else {
                i += 1;
                continue;
            };
            let var = raw_var.split_whitespace().last().unwrap_or(raw_var).trim();
            let expr = expr.trim();
            if !is_inlinable_expr(var, expr) {
                i += 1;
                continue;
            }
            let mut use_lines: Vec<usize> = Vec::new();
            for (j, l) in lines.iter().enumerate() {
                if j == i {
                    continue;
                }
                if contains_token(l, var) {
                    use_lines.push(j);
                }
            }
            if use_lines.len() == 1 && use_lines[0] > i {
                let j = use_lines[0];
                let target = lines[j].trim().to_string();
                if target.starts_with("goto ") || target.starts_with('L') && target.ends_with(':') {
                    i += 1;
                    continue;
                }
                let use_is_plain_copy = target
                    .strip_suffix(';')
                    .map(|t| {
                        t.split_once(" = ")
                            .is_some_and(|(_, rhs)| rhs.trim() == var)
                    })
                    .unwrap_or(false);
                let replacement = if use_is_plain_copy
                    || expr
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
                {
                    expr.to_string()
                } else {
                    format!("({expr})")
                };
                lines[j] = replace_token(&lines[j], var, &replacement);
                lines.remove(i);
                changed = true;
            } else {
                i += 1;
            }
        }
    }
    lines.join("\n")
}

fn is_inlinable_expr(var: &str, expr: &str) -> bool {
    if !(var.starts_with('v') && var[1..].chars().all(|c| c.is_ascii_digit())) {
        return false;
    }
    if expr.contains("new ")
        || expr.contains("super(")
        || expr.starts_with("synchronized")
        || expr.starts_with("throw")
        || expr.starts_with("return")
    {
        return false;
    }
    if expr.starts_with('"') && expr.ends_with('"') {
        return true;
    }
    if expr.parse::<i64>().is_ok() {
        return true;
    }
    if expr
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
    {
        return true;
    }
    if expr.starts_with('(') && expr.ends_with(')') && !expr.contains(" new ") {
        return true;
    }
    let op_head = expr
        .split_whitespace()
        .nth(1)
        .map(|op| {
            matches!(
                op,
                "+" | "-"
                    | "*"
                    | "/"
                    | "%"
                    | "&"
                    | "|"
                    | "^"
                    | "<<"
                    | ">>"
                    | ">>>"
                    | "=="
                    | "!="
                    | "<"
                    | ">"
                    | "<="
                    | ">="
            )
        })
        .unwrap_or(false);
    if op_head {
        return true;
    }
    if expr.contains('[') && expr.contains(']') && !expr.contains("->") {
        return true;
    }
    if expr.contains('(') && expr.contains(')') && !expr.contains("-><init>") {
        return true;
    }
    false
}

fn contains_token(line: &str, token: &str) -> bool {
    line.split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|t| t == token)
}

fn replace_token(line: &str, token: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut last = 0;
    for (start, part) in line.match_indices(token) {
        let before = line[..start].chars().last();
        let after = line[start + part.len()..].chars().next();
        let before_ok = before.is_none_or(|c| !c.is_alphanumeric() && c != '_');
        let after_ok = after.is_none_or(|c| !c.is_alphanumeric() && c != '_');
        if before_ok && after_ok {
            out.push_str(&line[last..start]);
            out.push_str(replacement);
            last = start + part.len();
        }
    }
    out.push_str(&line[last..]);
    out
}

pub struct MethodPseudocode {
    pub signature: String,
    pub pseudocode: String,
    pub registers: u16,
    pub insn_units: usize,
}

pub fn decompile_method(dex: &DexFile, code: &CodeItem, method_idx: u32) -> MethodPseudocode {
    let output = lift_method_to_ssa(dex, code, method_idx);
    let sig = dex.method_signature(method_idx);
    let try_info = build_try_info(dex, &code.tries);
    let text = render_method_pseudocode_full(&output, &try_info);
    MethodPseudocode {
        signature: sig,
        pseudocode: text,
        registers: code.registers_size,
        insn_units: code.insns.len(),
    }
}

fn apply_string_concat_fold(text: &str) -> String {
    let mut out_lines: Vec<String> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.contains(".append(")
            && trimmed.contains(".toString()")
            && let Some(folded) = fold_concat_line(trimmed)
        {
            let indent = line.len() - line.trim_start().len();
            out_lines.push(format!("{}{}", " ".repeat(indent), folded));
            continue;
        }
        out_lines.push(line.to_string());
    }
    out_lines.join("\n")
}

fn fold_concat_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let (prefix, chain) = if let Some(rest) = trimmed.strip_prefix("return ") {
        let after_semi = rest.trim().strip_suffix(';').unwrap_or(rest.trim());
        let inner = after_semi
            .strip_suffix(')')
            .and_then(|r| r.strip_suffix(".toString()"))
            .or_else(|| after_semi.strip_suffix(".toString()"))
            .unwrap_or(after_semi)
            .trim();
        ("return ".to_string(), inner.to_string())
    } else if let Some((p, rest)) = trimmed.split_once(" = ") {
        if p.contains('"') {
            return None;
        }
        let inner = rest
            .trim()
            .strip_suffix(';')
            .and_then(|r| r.strip_suffix(".toString()"))
            .unwrap_or(rest.trim())
            .trim();
        (format!("{p} = "), inner.to_string())
    } else {
        return None;
    };
    if !chain.contains(".append(") {
        return None;
    }
    let parts = split_append_args(&chain);
    if parts.len() >= 2 {
        Some(format!("{prefix}{};", parts.join(" + ")))
    } else {
        None
    }
}

fn split_append_args(chain: &str) -> Vec<String> {
    let segments: Vec<&str> = chain.split(".append(").collect();
    if segments.len() < 2 {
        return vec![];
    }
    let mut args: Vec<String> = Vec::new();
    for seg in &segments[1..] {
        let arg = balanced_prefix(seg);
        let arg = arg.trim();
        let arg = arg
            .strip_prefix('(')
            .and_then(|a| a.strip_suffix(')'))
            .unwrap_or(arg);
        if !arg.is_empty() {
            args.push(arg.trim().to_string());
        }
    }
    args
}

fn balanced_prefix(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut end = s.len();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'"' && (i == 0 || bytes[i - 1] != b'\\') {
            in_string = !in_string;
        }
        if in_string {
            continue;
        }
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            if depth == 0 {
                end = i;
                break;
            }
            depth -= 1;
            if depth == 0 {
                end = i + 1;
                break;
            }
        }
    }
    &s[..end.min(s.len())]
}

fn apply_for_loop_recovery(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let mut i = 0usize;
    while i < lines.len() {
        let trimmed = lines[i].trim().to_string();
        let Some(cond) = trimmed
            .strip_prefix("while (")
            .and_then(|r| r.strip_suffix(") {"))
        else {
            i += 1;
            continue;
        };
        let Some(var) = loop_var(cond) else {
            i += 1;
            continue;
        };
        // find init: previous non-empty line is TYPE VAR = INIT;
        let init_line = if i > 0 {
            lines[i - 1].trim().to_string()
        } else {
            String::new()
        };
        let Some(init_info) = parse_init(&init_line, &var) else {
            i += 1;
            continue;
        };
        // find matching close brace and check last body line for increment
        let open_indent = lines[i].len() - lines[i].trim_start().len();
        let mut j = i + 1;
        let mut depth = 1usize;
        while j < lines.len() && depth > 0 {
            let t = lines[j].trim();
            depth += t.matches('{').count();
            depth = depth.saturating_sub(t.matches('}').count());
            if depth == 0 {
                break;
            }
            j += 1;
        }
        if j >= lines.len() {
            i += 1;
            continue;
        }
        // last non-empty line inside the loop
        let mut last_body = j;
        while last_body > i + 1 && lines[last_body - 1].trim().is_empty() {
            last_body -= 1;
        }
        last_body -= 1;
        let inc_line = lines[last_body].trim().to_string();
        let Some(inc_text) = parse_increment(&inc_line, &var) else {
            i += 1;
            continue;
        };
        // transform: remove init line, rewrite while line, remove increment line
        let indent = " ".repeat(open_indent);
        lines[i] = format!(
            "{indent}for ({} {} = {}; {}; {}) {{",
            init_info.0, var, init_info.1, cond, inc_text
        );
        lines[last_body] = String::new();
        lines[i - 1] = String::new();
        i = j;
    }
    lines.join("\n")
}

fn loop_var(cond: &str) -> Option<String> {
    for op in [" <= ", " >= ", " < ", " > ", " != ", " == "] {
        if let Some(pos) = cond.find(op) {
            let lhs = cond[..pos].trim();
            if lhs.chars().all(|c| c.is_alphanumeric() || c == '_') && !lhs.is_empty() {
                return Some(lhs.to_string());
            }
        }
    }
    None
}

fn parse_init(line: &str, var: &str) -> Option<(String, String)> {
    let (decl, init) = line.strip_suffix(';').and_then(|l| l.split_once(" = "))?;
    let init = init.trim();
    let name = decl.split_whitespace().last()?;
    if name != var {
        return None;
    }
    let ty = decl.split_whitespace().next()?;
    if ty == name {
        return None;
    }
    Some((ty.to_string(), init.to_string()))
}

fn parse_increment(line: &str, var: &str) -> Option<String> {
    let line = line.strip_suffix(';').unwrap_or(line);
    let Some((lhs, rhs)) = line.split_once(" = ") else {
        if line == format!("{var}++") || line == format!("++{var}") {
            return Some(format!("{var}++"));
        }
        return None;
    };
    if lhs.trim() != var {
        return None;
    }
    let rhs = rhs.trim();
    for op in [" + ", " - "] {
        if let Some(pos) = rhs.find(op) {
            let base = rhs[..pos].trim();
            let step = rhs[pos + op.len()..].trim();
            if base == var && step.parse::<i64>().is_ok() {
                let n: i64 = step.parse().ok()?;
                let sign = if op == " + " { "+" } else { "-" };
                let mag = n.unsigned_abs();
                if sign == "+" && mag == 1 {
                    return Some(format!("{var}++"));
                }
                if sign == "-" && mag == 1 {
                    return Some(format!("{var}--"));
                }
                return Some(format!("{var} {sign}= {mag}"));
            }
        }
    }
    None
}

fn apply_boxing_cleanup(text: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let mut l = line.to_string();
        // Simple iterative replacement: String.valueOf(X) → X for simple X
        while let Some(start) = l.find("String.valueOf(") {
            let after = &l[start + 15..];
            if let Some(close) = after.find(')') {
                let inner = &after[..close];
                if inner
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '$' || c == '"')
                    && !inner.is_empty()
                {
                    l = format!("{}{}{}", &l[..start], inner, &l[start + 15 + close + 1..]);
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        l = l.replace("(java.lang.Object) ", "");
        out.push(l);
    }
    out.join("\n")
}

#[allow(clippy::mut_range_bound)]
fn apply_loop_recovery(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    // Build label -> line index map
    let mut labels: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if t.len() > 2 && t.starts_with('L') && t.ends_with(':') {
            labels.insert(t[..t.len() - 1].to_string(), i);
        }
    }
    if labels.is_empty() {
        return lines.join("\n");
    }
    // Find backward gotos: "goto L{N};" where L{N} label appears earlier
    let mut i = 0usize;
    while i < lines.len() {
        let t = lines[i].trim().to_string();
        let Some(goto_target) = t
            .strip_prefix("goto ")
            .and_then(|r| r.strip_suffix(';'))
            .map(|s| s.to_string())
        else {
            i += 1;
            continue;
        };
        let Some(&label_line) = labels.get(&goto_target) else {
            i += 1;
            continue;
        };
        if label_line >= i {
            i += 1;
            continue;
        }
        // Backward goto found. Check if the label line is followed by an if/while
        let mut if_line = label_line + 1;
        while if_line < lines.len() && lines[if_line].trim().is_empty() {
            if_line += 1;
        }
        if if_line >= lines.len() || !lines[if_line].trim().starts_with("if (") {
            i += 1;
            continue;
        }
        // Strict shape check: the if's then-block must close with a plain `}`
        // (no else), the backward goto must be inside that block, and no other
        // goto may target the label (it is about to be deleted).
        let net = |l: &str| -> i32 {
            let t = l.trim();
            let mut d = 0i32;
            if t.ends_with('{') {
                d += 1;
            }
            if t.starts_with('}') {
                d -= 1;
            }
            d
        };
        let mut depth = net(&lines[if_line]);
        let mut close_line = None;
        for (j, line) in lines.iter().enumerate().skip(if_line + 1) {
            depth += net(line);
            if depth <= 0 {
                close_line = Some(j);
                break;
            }
        }
        let Some(close_line) = close_line else {
            i += 1;
            continue;
        };
        if !(if_line < i && i < close_line) {
            i += 1;
            continue;
        }
        let close_t = lines[close_line].trim();
        if close_t.starts_with("} else") || close_t.starts_with("else") {
            i += 1;
            continue;
        }
        let mut after = close_line + 1;
        while after < lines.len() && lines[after].trim().is_empty() {
            after += 1;
        }
        if after < lines.len() && lines[after].trim().starts_with("else") {
            i += 1;
            continue;
        }
        let goto_stmt = format!("goto {goto_target};");
        let outside = lines
            .iter()
            .enumerate()
            .any(|(j, l)| l.trim() == goto_stmt && j != i && (j <= if_line || j >= close_line));
        if outside {
            i += 1;
            continue;
        }
        // Convert: label → remove, if → while (with proper condition), goto → remove
        let indent = lines[if_line].len() - lines[if_line].trim_start().len();
        let cond = lines[if_line]
            .trim()
            .strip_prefix("if (")
            .and_then(|r| r.strip_suffix(") {"))
            .unwrap_or("")
            .to_string();
        // If the condition is a negation (from empty-then inversion), unwrap it for while
        let while_cond =
            if let Some(inner) = cond.strip_prefix("!(").and_then(|s| s.strip_suffix(')')) {
                inner.to_string()
            } else {
                cond.clone()
            };
        lines[if_line] = format!("{}while ({while_cond}) {{", " ".repeat(indent));
        lines[label_line] = String::new();
        lines[i] = String::new();
        // Remove any remaining goto to the same label within the while body
        for line_ref in lines.iter_mut().take(close_line).skip(if_line + 1) {
            if line_ref.trim() == format!("goto {goto_target};") {
                *line_ref = String::new();
            }
        }
        i += 1;
    }
    lines.join("\n")
}

fn apply_loop_wrap(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let indent_of = |l: &str| l.len() - l.trim_start().len();
    for _round in 0..64 {
        let mut labels: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            if t.len() > 2 && t.starts_with('L') && t.ends_with(':') {
                labels.insert(t[..t.len() - 1].to_string(), i);
            }
        }
        let mut fired = false;
        for i in 0..lines.len() {
            let t = lines[i].trim();
            let Some(target) = t.strip_prefix("goto ").and_then(|r| r.strip_suffix(';')) else {
                continue;
            };
            let Some(&ll) = labels.get(target) else {
                continue;
            };
            if ll >= i {
                continue;
            }
            let d = indent_of(&lines[ll]);
            if indent_of(&lines[i]) != d {
                continue;
            }
            let mut depth = 0i32;
            let mut ok = true;
            for line in lines.iter().take(i).skip(ll + 1) {
                let t2 = line.trim();
                if t2.is_empty() {
                    continue;
                }
                if indent_of(line) < d {
                    ok = false;
                    break;
                }
                if t2.ends_with('{') {
                    depth += 1;
                }
                if t2.starts_with('}') {
                    depth -= 1;
                }
                if depth < 0 {
                    ok = false;
                    break;
                }
            }
            if !ok || depth != 0 {
                continue;
            }
            let pad = " ".repeat(d);
            let inner = " ".repeat(d + 4);
            let goto_stmt = format!("goto {target};");
            let residual = lines
                .iter()
                .enumerate()
                .any(|(k, l)| k != i && l.trim() == goto_stmt);
            let mut out: Vec<String> = Vec::with_capacity(lines.len() + 2);
            out.extend_from_slice(&lines[..ll]);
            out.push(format!("{pad}while (true) {{"));
            if residual {
                out.push(format!("{inner}{target}:"));
            }
            for line in lines.iter().take(i).skip(ll + 1) {
                if line.trim().is_empty() {
                    out.push(String::new());
                } else {
                    out.push(format!("    {line}"));
                }
            }
            out.push(format!("{pad}}}"));
            out.extend_from_slice(&lines[i + 1..]);
            lines = out;
            fired = true;
            break;
        }
        if !fired {
            break;
        }
    }
    lines.join("\n")
}

fn apply_unused_label_cleanup(text: &str) -> String {
    let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let mut targets: std::collections::HashSet<String> = std::collections::HashSet::new();
    for l in &lines {
        let t = l.trim();
        if let Some(target) = t.strip_prefix("goto ").and_then(|r| r.strip_suffix(';')) {
            targets.insert(target.to_string());
        }
    }
    let out: Vec<String> = lines
        .into_iter()
        .map(|l| {
            let t = l.trim();
            if t.len() > 2
                && t.starts_with('L')
                && t.ends_with(':')
                && !targets.contains(&t[..t.len() - 1])
            {
                String::new()
            } else {
                l
            }
        })
        .collect();
    out.join("\n")
}

fn apply_control_kind_repair(text: &str) -> String {
    let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let opener_kind = |s: &str| -> &str {
        for (kw, kind) in [
            ("if ", "if"),
            ("while ", "while"),
            ("for ", "for"),
            ("switch ", "switch"),
            ("try", "try"),
            ("synchronized ", "synchronized"),
            ("do", "do"),
        ] {
            if s.starts_with(kw) {
                return kind;
            }
        }
        "block"
    };
    let mut stack: Vec<String> = Vec::new();
    let mut inserts: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        let closes = t.chars().take_while(|&c| c == '}').count();
        let rest = t[closes..].trim_start();
        let is_else = rest.starts_with("else");
        if is_else && closes > 0 {
            let mut k = 0;
            while let Some(top) = stack.last() {
                if top == "if" {
                    break;
                }
                k += 1;
                stack.pop();
            }
            if k > 0 {
                inserts.insert(i, k);
            }
        }
        for _ in 0..closes {
            stack.pop();
        }
        if t.ends_with('{') {
            let kind = if is_else {
                "if"
            } else if rest.starts_with("catch") {
                "catch"
            } else {
                opener_kind(rest)
            };
            stack.push(kind.to_string());
        }
    }
    if inserts.is_empty() {
        return lines.join("\n");
    }
    let mut out: Vec<String> = Vec::with_capacity(lines.len() + inserts.len());
    for (i, l) in lines.iter().enumerate() {
        if let Some(&k) = inserts.get(&i) {
            let indent = " ".repeat(l.len() - l.trim_start().len());
            for _ in 0..k {
                out.push(format!("{indent}}}"));
            }
        }
        out.push(l.clone());
    }
    out.join("\n")
}

fn apply_condition_paren_repair(text: &str) -> String {
    let out: Vec<String> = text
        .lines()
        .map(|l| {
            let t = l.trim();
            let Some((kw, rest)) = ["if ", "while ", "for ", "switch ", "synchronized "]
                .iter()
                .find_map(|kw| t.strip_prefix(kw).map(|r| (*kw, r)))
            else {
                return l.to_string();
            };
            if !rest.ends_with(") {") || !rest.starts_with('(') || rest.len() < 5 {
                return l.to_string();
            }
            let cond = &rest[1..rest.len() - 3];
            let mut depth = 0i32;
            let mut repaired = String::with_capacity(cond.len());
            let mut in_str = false;
            let mut esc = false;
            for c in cond.chars() {
                if in_str {
                    repaired.push(c);
                    if esc {
                        esc = false;
                    } else if c == '\\' {
                        esc = true;
                    } else if c == '"' {
                        in_str = false;
                    }
                    continue;
                }
                match c {
                    '"' => {
                        in_str = true;
                        repaired.push(c);
                    }
                    '(' => {
                        depth += 1;
                        repaired.push(c);
                    }
                    ')' => {
                        if depth == 0 {
                            continue;
                        }
                        depth -= 1;
                        repaired.push(c);
                    }
                    _ => repaired.push(c),
                }
            }
            for _ in 0..depth {
                repaired.push(')');
            }
            if repaired == cond {
                return l.to_string();
            }
            let indent = " ".repeat(l.len() - l.trim_start().len());
            format!("{indent}{kw}({repaired}) {{")
        })
        .collect();
    out.join("\n")
}

fn apply_stmt_paren_repair(text: &str) -> String {
    let out: Vec<String> = text
        .lines()
        .map(|l| {
            let t = l.trim();
            if t.is_empty() || t.starts_with("//") || !t.ends_with(';') {
                return l.to_string();
            }
            if t.starts_with("case ") || t.starts_with("default:") {
                return l.to_string();
            }
            let chars: Vec<char> = t.chars().collect();
            let mut repaired: Vec<char> = Vec::with_capacity(chars.len() + 4);
            let mut depth = 0i32;
            let mut in_str = false;
            let mut in_chr = false;
            let mut esc = false;
            for &c in &chars {
                if in_str || in_chr {
                    repaired.push(c);
                    if esc {
                        esc = false;
                    } else if c == '\\' {
                        esc = true;
                    } else if (c == '"' && in_str) || (c == '\'' && in_chr) {
                        in_str = false;
                        in_chr = false;
                    }
                    continue;
                }
                match c {
                    '"' => {
                        in_str = true;
                        repaired.push(c);
                    }
                    '\'' => {
                        in_chr = true;
                        repaired.push(c);
                    }
                    '(' => {
                        depth += 1;
                        repaired.push(c);
                    }
                    ')' => {
                        if depth == 0 {
                            continue;
                        }
                        depth -= 1;
                        repaired.push(c);
                    }
                    _ => repaired.push(c),
                }
            }
            if depth == 0 && repaired.len() == chars.len() {
                return l.to_string();
            }
            repaired.pop();
            repaired.extend(")".repeat(depth as usize).chars());
            repaired.push(';');
            let indent = " ".repeat(l.len() - l.trim_start().len());
            let body: String = repaired.into_iter().collect();
            format!("{indent}{body}")
        })
        .collect();
    out.join("\n")
}

fn apply_dead_goto_after_else(text: &str) -> String {
    #[derive(Clone, Copy, PartialEq)]
    enum FrameKind {
        If,
        ElseIf,
        Else,
        Plain,
        Loopish,
    }
    struct Frame {
        kind: FrameKind,
        last_term: bool,
        then_term: bool,
    }
    let is_terminal = |t: &str| -> bool {
        t.starts_with("return")
            || t.starts_with("throw ")
            || t.starts_with("goto L")
            || t == "break;"
            || t == "continue;"
    };
    let opener_kind = |s: &str| -> FrameKind {
        if s.starts_with("if ") {
            FrameKind::If
        } else if s.starts_with("while ")
            || s.starts_with("for ")
            || s.starts_with("switch ")
            || s.starts_with("try")
            || s.starts_with("catch ")
        {
            FrameKind::Loopish
        } else {
            FrameKind::Plain
        }
    };
    let lines: Vec<&str> = text.lines().collect();
    let mut stack: Vec<Frame> = Vec::new();
    let mut dead: Vec<usize> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") || (t.starts_with('L') && t.ends_with(':')) {
            continue;
        }
        let closes = t.chars().take_while(|&c| c == '}').count();
        let rest = t[closes..].trim_start();
        let mut popped_then: Option<bool> = None;
        for _ in 0..closes {
            let Some(f) = stack.pop() else {
                continue;
            };
            let term = match f.kind {
                FrameKind::If | FrameKind::ElseIf | FrameKind::Loopish => false,
                FrameKind::Else => f.then_term && f.last_term,
                FrameKind::Plain => f.last_term,
            };
            match f.kind {
                FrameKind::If => popped_then = Some(f.last_term),
                FrameKind::ElseIf => popped_then = Some(f.then_term && f.last_term),
                _ => {}
            }
            if term && f.kind == FrameKind::Else {
                dead.push(i);
            }
            if let Some(parent) = stack.last_mut() {
                parent.last_term = term;
            }
        }
        if rest.ends_with('{') {
            let (kind, then_term) = if rest.starts_with("else if ") || rest.starts_with("else if(")
            {
                (FrameKind::ElseIf, popped_then.unwrap_or(false))
            } else if rest.starts_with("else") {
                (FrameKind::Else, popped_then.unwrap_or(false))
            } else {
                (opener_kind(rest), false)
            };
            stack.push(Frame {
                kind,
                last_term: false,
                then_term,
            });
        } else if closes == 0
            && let Some(top) = stack.last_mut()
        {
            top.last_term = is_terminal(t);
        }
    }
    if dead.is_empty() {
        return text.to_string();
    }
    let mut remove: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for &p in &dead {
        let mut j = p + 1;
        while j < lines.len() {
            let t = lines[j].trim();
            if t.is_empty() || t.starts_with("//") {
                j += 1;
                continue;
            }
            if t.starts_with("goto L") && t.ends_with(';') {
                remove.insert(j);
                j += 1;
            } else {
                break;
            }
        }
    }
    lines
        .iter()
        .enumerate()
        .filter(|(i, _)| !remove.contains(i))
        .map(|(_, l)| l.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

fn apply_guard_flatten(text: &str) -> String {
    #[derive(Clone, Copy, PartialEq)]
    enum FrameKind {
        If,
        ElseIf,
        Else,
        Plain,
        Loopish,
    }
    struct Frame {
        kind: FrameKind,
        last_term: bool,
        then_term: bool,
    }
    let is_terminal = |t: &str| -> bool {
        t.starts_with("return")
            || t.starts_with("throw ")
            || t.starts_with("goto L")
            || t == "break;"
            || t == "continue;"
    };
    let opener_kind = |s: &str| -> FrameKind {
        if s.starts_with("if ") {
            FrameKind::If
        } else if s.starts_with("while ")
            || s.starts_with("for ")
            || s.starts_with("switch ")
            || s.starts_with("try")
            || s.starts_with("catch ")
        {
            FrameKind::Loopish
        } else {
            FrameKind::Plain
        }
    };
    let net = |l: &str| -> i32 {
        let t = l.trim();
        let closes = t.chars().take_while(|&c| c == '}').count() as i32;
        let opens = i32::from(t.ends_with('{'));
        opens - closes
    };
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    for _round in 0..128 {
        let mut stack: Vec<Frame> = Vec::new();
        let mut hit: Option<(usize, bool)> = None;
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            if t.is_empty() || t.starts_with("//") || (t.starts_with('L') && t.ends_with(':')) {
                continue;
            }
            let closes = t.chars().take_while(|&c| c == '}').count();
            let rest = t[closes..].trim_start();
            let mut popped_then: Option<bool> = None;
            for _ in 0..closes {
                let Some(f) = stack.pop() else {
                    continue;
                };
                let term = match f.kind {
                    FrameKind::If | FrameKind::ElseIf | FrameKind::Loopish => false,
                    FrameKind::Else => f.then_term && f.last_term,
                    FrameKind::Plain => f.last_term,
                };
                match f.kind {
                    FrameKind::If => popped_then = Some(f.last_term),
                    FrameKind::ElseIf => popped_then = Some(f.then_term && f.last_term),
                    _ => {}
                }
                if let Some(parent) = stack.last_mut() {
                    parent.last_term = term;
                }
            }
            if rest.ends_with('{') {
                if rest.starts_with("else") && popped_then == Some(true) {
                    hit = Some((
                        i,
                        rest.starts_with("else if ") || rest.starts_with("else if("),
                    ));
                    break;
                }
                let (kind, then_term) =
                    if rest.starts_with("else if ") || rest.starts_with("else if(") {
                        (FrameKind::ElseIf, popped_then.unwrap_or(false))
                    } else if rest.starts_with("else") {
                        (FrameKind::Else, popped_then.unwrap_or(false))
                    } else {
                        (opener_kind(rest), false)
                    };
                stack.push(Frame {
                    kind,
                    last_term: false,
                    then_term,
                });
            } else if closes == 0
                && let Some(top) = stack.last_mut()
            {
                top.last_term = is_terminal(t);
            }
        }
        let Some((i, is_else_if)) = hit else {
            break;
        };
        let indent = " ".repeat(lines[i].len() - lines[i].trim_start().len());
        if is_else_if {
            let t = lines[i].trim();
            let cond_part = t
                .trim_start_matches('}')
                .trim_start()
                .strip_prefix("else ")
                .unwrap_or("")
                .to_string();
            lines[i] = format!("{indent}}}");
            lines.insert(i + 1, format!("{indent}{cond_part}"));
        } else {
            let mut depth = net(&lines[i]);
            let mut close_at = None;
            for (j, line) in lines.iter().enumerate().skip(i + 1) {
                depth += net(line);
                if depth <= 0 {
                    let tj = lines[j].trim();
                    if tj == "}" && !tj.ends_with('{') {
                        close_at = Some(j);
                    }
                    break;
                }
            }
            let Some(close_at) = close_at else {
                break;
            };
            lines[i] = format!("{indent}}}");
            lines.remove(close_at);
        }
    }
    lines.join("\n")
}

fn apply_else_if_collapse(text: &str) -> String {
    let net = |l: &str| -> i32 {
        let t = l.trim();
        let closes = t.chars().take_while(|&c| c == '}').count() as i32;
        i32::from(t.ends_with('{')) - closes
    };
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    for _round in 0..8 {
        let mut changed = false;
        let mut i = 0usize;
        while i < lines.len() {
            if lines[i].trim() != "} else {" {
                i += 1;
                continue;
            }
            let e_indent = lines[i].len() - lines[i].trim_start().len();
            let mut depth = 1i32;
            let mut e_close = None;
            for (j, line) in lines.iter().enumerate().skip(i + 1) {
                depth += net(line);
                if depth <= 0 {
                    if depth == 0 {
                        e_close = Some(j);
                    }
                    break;
                }
            }
            let Some(e_close) = e_close else {
                i += 1;
                continue;
            };
            if lines[e_close].trim() != "}" {
                i += 1;
                continue;
            }
            let mut k = i + 1;
            while k < e_close && (lines[k].trim().is_empty() || lines[k].trim().starts_with("//")) {
                k += 1;
            }
            if k >= e_close {
                i += 1;
                continue;
            }
            let bt = lines[k].trim().to_string();
            if !bt.starts_with("if ") || !bt.ends_with('{') {
                i += 1;
                continue;
            }
            let mut depth2 = 1i32;
            let mut if_close = None;
            for (j, line) in lines.iter().enumerate().skip(k + 1).take(e_close - k - 1) {
                depth2 += net(line);
                if depth2 <= 0 {
                    if depth2 == 0 {
                        if_close = Some(j);
                    }
                    break;
                }
            }
            let Some(if_close) = if_close else {
                i += 1;
                continue;
            };
            let tail_clean = lines
                .iter()
                .take(e_close)
                .skip(if_close + 1)
                .all(|l| l.trim().is_empty() || l.trim().starts_with("//"));
            if !tail_clean {
                i += 1;
                continue;
            }
            let indent = " ".repeat(e_indent);
            lines[i] = format!("{indent}}} else {bt}");
            lines.remove(e_close);
            lines.remove(k);
            changed = true;
            i += 1;
        }
        if !changed {
            break;
        }
    }
    lines.join("\n")
}

fn replace_var_token(line: &str, tok: &str, rep: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let chars: Vec<char> = line.chars().collect();
    let tc: Vec<char> = tok.chars().collect();
    let mut i = 0usize;
    let mut in_str = false;
    let mut esc = false;
    while i < chars.len() {
        let c = chars[i];
        if in_str {
            out.push(c);
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        if i + tc.len() <= chars.len() && chars[i..i + tc.len()] == tc[..] {
            let before_ok = i == 0
                || !(chars[i - 1].is_alphanumeric() || chars[i - 1] == '_' || chars[i - 1] == '.');
            let after = i + tc.len();
            let after_ok =
                after >= chars.len() || !(chars[after].is_alphanumeric() || chars[after] == '_');
            if before_ok && after_ok {
                out.push_str(rep);
                i = after;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

fn name_from_type(ty: &str) -> String {
    let t = ty.trim();
    if let Some(elem) = t.strip_suffix("[]") {
        return format!("{}Arr", name_from_type(elem));
    }
    match t {
        "int" => return "i".to_string(),
        "long" => return "j".to_string(),
        "float" => return "f".to_string(),
        "double" => return "d".to_string(),
        "boolean" => return "z".to_string(),
        "byte" => return "b".to_string(),
        "char" => return "c".to_string(),
        "short" => return "s".to_string(),
        "java.lang.String" | "String" => return "str".to_string(),
        "java.lang.Object" | "Object" => return "obj".to_string(),
        _ => {}
    }
    let simple = t.rsplit('.').next().unwrap_or(t);
    let simple = simple.split('<').next().unwrap_or(simple);
    if simple.is_empty() || !simple.chars().next().is_some_and(|c| c.is_uppercase()) {
        return String::new();
    }
    camel_case(simple)
}

fn apply_type_based_names(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let mut var_types: std::collections::HashMap<String, Option<String>> =
        std::collections::HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for l in &lines {
        let t = l.trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        let Some((lhs, _)) = t.split_once(" = ") else {
            continue;
        };
        let Some(sp) = lhs.rfind(' ') else {
            continue;
        };
        let ty = &lhs[..sp];
        let var = &lhs[sp + 1..];
        if var.len() < 2 || !var.starts_with('v') || !var[1..].chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if ty.is_empty() || ty.contains('(') || ty.contains(';') || ty.contains(',') {
            continue;
        }
        let name = name_from_type(ty);
        if name.is_empty() {
            continue;
        }
        let entry = var_types.entry(var.to_string()).or_insert_with(|| {
            order.push(var.to_string());
            Some(name.clone())
        });
        if let Some(existing) = entry
            && *existing != name
        {
            *entry = None;
        }
    }
    let mut taken: std::collections::HashSet<String> = std::collections::HashSet::new();
    for l in &lines {
        if l.trim_start().starts_with("//") {
            continue;
        }
        let chars: Vec<char> = l.chars().collect();
        let mut i = 0usize;
        let mut in_str = false;
        while i < chars.len() {
            let c = chars[i];
            if in_str {
                if c == '"' {
                    in_str = false;
                }
                i += 1;
                continue;
            }
            if c == '"' {
                in_str = true;
                i += 1;
                continue;
            }
            if c.is_alphabetic() || c == '_' {
                let start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let tok: String = chars[start..i].iter().collect();
                let mut p = start;
                while p > 0 && chars[p - 1].is_whitespace() {
                    p -= 1;
                }
                let after_dot = p > 0 && chars[p - 1] == '.';
                let is_v = tok.starts_with('v')
                    && tok.len() > 1
                    && tok[1..].chars().all(|ch| ch.is_ascii_digit());
                if !after_dot && !is_v {
                    taken.insert(tok);
                }
            } else {
                i += 1;
            }
        }
    }
    let mut renames: Vec<(String, String)> = Vec::new();
    for var in order {
        let Some(Some(name)) = var_types.get(&var) else {
            continue;
        };
        let mut n = 1u32;
        let mut chosen: Option<String> = None;
        while n <= 50 {
            let cand = if n == 1 {
                name.clone()
            } else {
                format!("{name}{n}")
            };
            if !taken.contains(&cand) {
                taken.insert(cand.clone());
                chosen = Some(cand);
                break;
            }
            n += 1;
        }
        if let Some(c) = chosen {
            renames.push((var, c));
        }
    }
    for (var, name) in renames {
        for l in lines.iter_mut() {
            if l.trim_start().starts_with("//") {
                continue;
            }
            if l.contains(&var) {
                *l = replace_var_token(l, &var, &name);
            }
        }
    }
    lines.join("\n")
}

fn apply_empty_else_removal(text: &str) -> String {
    let net = |l: &str| -> i32 {
        let t = l.trim();
        let closes = t.chars().take_while(|&c| c == '}').count() as i32;
        i32::from(t.ends_with('{')) - closes
    };
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let mut changed = true;
    while changed {
        changed = false;
        let mut i = 0usize;
        while i < lines.len() {
            if lines[i].trim() == "} else {" {
                let mut depth = 1i32;
                let mut j = i + 1;
                let mut only_blank = true;
                while j < lines.len() {
                    depth += net(&lines[j]);
                    if depth <= 0 {
                        break;
                    }
                    if !lines[j].trim().is_empty() {
                        only_blank = false;
                    }
                    j += 1;
                }
                if j < lines.len() && depth == 0 && only_blank && lines[j].trim() == "}" {
                    let indent = lines[i].len() - lines[i].trim_start().len();
                    lines[i] = format!("{}}}", " ".repeat(indent));
                    lines.remove(j);
                    changed = true;
                }
            }
            i += 1;
        }
    }
    lines.join("\n")
}

fn apply_labeled_continue(text: &str) -> String {
    let net = |l: &str| -> i32 {
        let t = l.trim();
        let closes = t.chars().take_while(|&c| c == '}').count() as i32;
        i32::from(t.ends_with('{')) - closes
    };
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let mut i = 0usize;
    while i < lines.len() {
        if lines[i].trim() != "while (true) {" {
            i += 1;
            continue;
        }
        let w = i;
        let mut j = w + 1;
        while j < lines.len() && lines[j].trim().is_empty() {
            j += 1;
        }
        let label = {
            let t = lines[j].trim().to_string();
            if j < lines.len() && t.len() > 2 && t.starts_with('L') && t.ends_with(':') {
                t[..t.len() - 1].to_string()
            } else {
                i += 1;
                continue;
            }
        };
        let label_line = j;
        let mut depth = net(&lines[w]);
        let mut close = None;
        for (k, line) in lines.iter().enumerate().skip(w + 1) {
            depth += net(line);
            if depth <= 0 {
                if depth == 0 {
                    close = Some(k);
                }
                break;
            }
        }
        let Some(close) = close else {
            i += 1;
            continue;
        };
        let goto_stmt = format!("goto {label};");
        let inside: Vec<usize> = (w..close)
            .filter(|&k| lines[k].trim() == goto_stmt)
            .collect();
        if inside.is_empty() {
            i = close + 1;
            continue;
        }
        let indent = " ".repeat(lines[w].len() - lines[w].trim_start().len());
        lines[w] = format!("{indent}{label}: while (true) {{");
        for &k in &inside {
            let ind = " ".repeat(lines[k].len() - lines[k].trim_start().len());
            lines[k] = format!("{ind}continue {label};");
        }
        lines[label_line] = String::new();
        i = close + 1;
    }
    lines.join("\n")
}

fn apply_try_catch_syntax(text: &str) -> String {
    let net = |l: &str| -> i32 {
        let t = l.trim();
        let closes = t.chars().take_while(|&c| c == '}').count() as i32;
        i32::from(t.ends_with('{')) - closes
    };
    let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let mut try_open: HashMap<usize, usize> = HashMap::new();
    let mut try_close: HashMap<usize, usize> = HashMap::new();
    let mut catch_open: HashMap<usize, (usize, String)> = HashMap::new();
    let mut catch_close: HashMap<usize, usize> = HashMap::new();
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        if let Some(ks) = t.strip_prefix("// try@")
            && let Ok(k) = ks.parse::<usize>()
        {
            let poisoned = try_open.insert(k, i).is_some();
            if poisoned {
                try_open.insert(k, usize::MAX);
            }
        } else if let Some(ks) = t.strip_prefix("// endtry@")
            && let Ok(k) = ks.parse::<usize>()
        {
            let poisoned = try_close.insert(k, i).is_some();
            if poisoned {
                try_close.insert(k, usize::MAX);
            }
        } else if let Some(rest) = t.strip_prefix("// catch@") {
            if let Some((ks, types_part)) = rest.split_once(" (")
                && let Ok(k) = ks.parse::<usize>()
            {
                let types = types_part.strip_suffix(" e)").unwrap_or("").to_string();
                if types.is_empty() {
                    continue;
                }
                let poisoned = catch_open.insert(k, (i, types)).is_some();
                if poisoned {
                    catch_open.insert(k, (usize::MAX, String::new()));
                }
            }
        } else if let Some(ks) = t.strip_prefix("// endcatch@")
            && let Ok(k) = ks.parse::<usize>()
        {
            let poisoned = catch_close.insert(k, i).is_some();
            if poisoned {
                catch_close.insert(k, usize::MAX);
            }
        }
    }
    let mut replaces: HashMap<usize, String> = HashMap::new();
    let mut deletes: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut insert_after: HashMap<usize, Vec<String>> = HashMap::new();
    let mut ks: Vec<usize> = catch_open.keys().copied().collect();
    ks.sort_by_key(|k| {
        let span = match (try_open.get(k), try_close.get(k)) {
            (Some(&a), Some(&b)) if a < b && a != usize::MAX && b != usize::MAX => b - a,
            _ => usize::MAX,
        };
        (span, *k)
    });
    let has_marker = |v: &[String]| -> bool {
        v.iter().any(|l| {
            let t = l.trim();
            t.starts_with("// try@")
                || t.starts_with("// endtry@")
                || t.starts_with("// catch@")
                || t.starts_with("// endcatch@")
        })
    };
    let balanced = |v: &[String]| -> bool {
        let mut d = 0i32;
        for l in v {
            d += net(l);
            if d < 0 {
                return false;
            }
        }
        d == 0
    };
    for k in ks {
        let (Some(&a), Some(&b)) = (try_open.get(&k), try_close.get(&k)) else {
            continue;
        };
        let (Some((c, types)), Some(&e)) = (catch_open.get(&k), catch_close.get(&k)) else {
            continue;
        };
        if a == usize::MAX || b == usize::MAX || *c == usize::MAX || e == usize::MAX {
            continue;
        }
        if !(a < b) || !(*c < e) {
            continue;
        }
        if (*c >= a && *c <= b) || (e >= a && e <= b) {
            continue;
        }
        if replaces.contains_key(&a) || replaces.contains_key(&b) {
            continue;
        }
        if (*c..=e).any(|x| deletes.contains(&x) || replaces.contains_key(&x)) {
            continue;
        }
        let region: Vec<String> = lines[a + 1..b].to_vec();
        let cbody: Vec<String> = lines[c + 1..e].to_vec();
        if !balanced(&region) || !balanced(&cbody) {
            continue;
        }
        if has_marker(&region) || has_marker(&cbody) {
            continue;
        }
        let indent = " ".repeat(lines[a].len() - lines[a].trim_start().len());
        replaces.insert(a, format!("{indent}try {{"));
        replaces.insert(b, format!("{indent}}} catch ({types} e) {{"));
        let mut ins = cbody;
        ins.push(format!("{indent}}}"));
        insert_after.insert(b, ins);
        for x in *c..=e {
            deletes.insert(x);
        }
    }
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    for (i, l) in lines.iter().enumerate() {
        if deletes.contains(&i) {
            continue;
        }
        if let Some(rep) = replaces.get(&i) {
            out.push(rep.clone());
        } else {
            let t = l.trim();
            let indent = &l[..l.len() - t.len()];
            if t.starts_with("// try@") {
                out.push(format!("{indent}// try"));
            } else if t.starts_with("// endtry@") {
                out.push(format!("{indent}// end try"));
            } else if let Some(rest) = t.strip_prefix("// catch@") {
                match rest.split_once(" (") {
                    Some((_, tp)) => out.push(format!("{indent}// catch ({tp}")),
                    None => out.push(format!("{indent}// catch")),
                }
            } else if t.starts_with("// endcatch@") {
                continue;
            } else {
                out.push(l.clone());
            }
        }
        if let Some(ins) = insert_after.get(&i) {
            out.extend(ins.iter().cloned());
        }
    }
    out.join("\n")
}

fn apply_brace_repair(text: &str) -> String {
    let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let lead_closes = |t: &str| t.chars().take_while(|&c| c == '}').count() as i32;
    let mut keep = vec![true; lines.len()];
    let mut depth = 0i32;
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        let c = lead_closes(t);
        let o = i32::from(t.ends_with('{'));
        let mut unmatched = false;
        for _ in 0..c {
            if depth == 0 {
                unmatched = true;
                break;
            }
            depth -= 1;
        }
        if unmatched {
            keep[i] = false;
        } else {
            depth += o;
        }
    }
    let mut depth2 = 0i32;
    for i in (0..lines.len()).rev() {
        if !keep[i] {
            continue;
        }
        let t = lines[i].trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        depth2 += lead_closes(t);
        if t.ends_with('{') {
            if depth2 == 0 {
                keep[i] = false;
            } else {
                depth2 -= 1;
            }
        }
    }
    lines
        .iter()
        .enumerate()
        .filter(|(i, _)| keep[*i])
        .map(|(_, l)| l.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn apply_reindent(text: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut depth = 1i32;
    let mut prev_blank = false;
    for l in text.lines() {
        let t = l.trim();
        if t.is_empty() {
            if !prev_blank && !out.is_empty() {
                out.push(String::new());
                prev_blank = true;
            }
            continue;
        }
        prev_blank = false;
        let closes = t.chars().take_while(|&c| c == '}').count() as i32;
        depth = (depth - closes).max(0);
        out.push(format!("{}{}", "    ".repeat(depth as usize), t));
        if t.ends_with('{') {
            depth += 1;
        }
    }
    while out.last().is_some_and(|l| l.is_empty()) {
        out.pop();
    }
    out.join("\n")
}

fn chunk_terminates(chunk: &[String]) -> bool {
    #[derive(Clone, Copy, PartialEq)]
    enum K {
        If,
        ElseIf,
        Else,
        Plain,
    }
    let mut stack: Vec<(K, bool, bool)> = Vec::new();
    let mut root_term = false;
    let is_term =
        |t: &str| t.starts_with("return") || t.starts_with("throw ") || t.starts_with("goto L");
    for l in chunk {
        let t = l.trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        if (t.starts_with('L') && t.ends_with(':'))
            || t.starts_with("break")
            || t.starts_with("continue")
            || t.starts_with("while ")
            || t.starts_with("for ")
            || t.starts_with("switch ")
            || t.starts_with("synchronized ")
            || t.starts_with("try")
            || t.starts_with("case ")
            || t.starts_with("default:")
        {
            return false;
        }
        let closes = t.chars().take_while(|&c| c == '}').count();
        let rest = t[closes..].trim_start();
        let mut popped_then: Option<bool> = None;
        for _ in 0..closes {
            let Some((kind, last_term, then_term)) = stack.pop() else {
                return false;
            };
            let term = match kind {
                K::If | K::ElseIf => false,
                K::Else => then_term && last_term,
                K::Plain => last_term,
            };
            match kind {
                K::If => popped_then = Some(last_term),
                K::ElseIf => popped_then = Some(then_term && last_term),
                _ => {}
            }
            if let Some(top) = stack.last_mut() {
                top.1 = term;
            } else {
                root_term = term;
            }
        }
        if rest.ends_with('{') {
            let kind = if rest.starts_with("else if ") || rest.starts_with("else if(") {
                K::ElseIf
            } else if rest.starts_with("else") {
                K::Else
            } else if rest.starts_with("if ") {
                K::If
            } else {
                K::Plain
            };
            let then_term = match kind {
                K::Else | K::ElseIf => popped_then.unwrap_or(false),
                _ => false,
            };
            stack.push((kind, false, then_term));
        } else if closes == 0 {
            let term = is_term(t);
            if let Some(top) = stack.last_mut() {
                top.1 = term;
            } else {
                root_term = term;
            }
        }
    }
    stack.is_empty() && root_term
}

fn try_chunk_inline(
    lines: &[String],
    lpos: usize,
    goto_indent: usize,
    sites: usize,
) -> Option<String> {
    let net = |l: &str| -> i32 {
        let t = l.trim();
        let closes = t.chars().take_while(|&c| c == '}').count() as i32;
        i32::from(t.ends_with('{')) - closes
    };
    let mut depth = 0i32;
    let mut saw_open = false;
    let mut end = None;
    for (j, line) in lines.iter().enumerate().skip(lpos + 1) {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        depth += net(line);
        if depth > 0 {
            saw_open = true;
        }
        if depth < 0 {
            return None;
        }
        if saw_open && depth == 0 {
            end = Some(j);
            break;
        }
    }
    let end = end?;
    let chunk: Vec<String> = lines[lpos + 1..=end]
        .iter()
        .filter(|l| !l.trim().is_empty())
        .cloned()
        .collect();
    if chunk.is_empty() || chunk.len() > 14 || chunk.len() * sites > 80 {
        return None;
    }
    if !chunk_terminates(&chunk) {
        return None;
    }
    let min_ind = chunk
        .iter()
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    let mut out: Vec<String> = Vec::new();
    for l in &chunk {
        let ind = l.len() - l.trim_start().len();
        let shift = goto_indent + ind.saturating_sub(min_ind);
        out.push(format!("{}{}", " ".repeat(shift), l.trim()));
    }
    Some(out.join("\n"))
}

fn apply_small_block_inline(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let mut label_pos: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (idx, line) in lines.iter().enumerate() {
        let t = line.trim();
        if t.len() > 2 && t.starts_with('L') && t.ends_with(':') {
            label_pos.insert(t[1..t.len() - 1].to_string(), idx);
        }
    }
    let mut inlined_labels: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut i = 0usize;
    while i < lines.len() {
        let t = lines[i].trim().to_string();
        let Some(target) = t.strip_prefix("goto L").and_then(|r| r.strip_suffix(';')) else {
            i += 1;
            continue;
        };
        let Some(&lpos) = label_pos.get(target) else {
            i += 1;
            continue;
        };
        // Collect flat statements after the label until terminal or control structure
        let goto_indent = lines[i].len() - lines[i].trim_start().len();
        let mut stmts: Vec<String> = Vec::new();
        let mut terminal: Option<String> = None;
        let mut ok = true;
        let mut j = lpos + 1;
        while j < lines.len() {
            let lj = lines[j].trim().to_string();
            if lj.is_empty() {
                j += 1;
                continue;
            }
            // Stop at next label
            if lj.starts_with('L') && lj.ends_with(':') {
                break;
            }
            // Stop at control structures (too complex to inline)
            if lj.starts_with("if ")
                || lj.starts_with("while ")
                || lj.starts_with("switch ")
                || lj.starts_with("for ")
                || lj == "}"
                || lj == "} else {"
            {
                ok = false;
                break;
            }
            if lj.starts_with("return") || lj.starts_with("throw") {
                terminal = Some(lj.clone());
                break;
            }
            stmts.push(lj.clone());
            if stmts.len() > 3 {
                ok = false;
                break;
            }
            j += 1;
        }
        if !ok || terminal.is_none() {
            let goto_stmt = format!("goto L{target};");
            let sites = lines.iter().filter(|l| l.trim() == goto_stmt).count();
            if let Some(replacement) = try_chunk_inline(&lines, lpos, goto_indent, sites) {
                lines[i] = replacement;
                inlined_labels.insert(target.to_string());
            }
            i += 1;
            continue;
        }
        // Inline: replace goto with statements + terminal at goto's indent
        let indent = " ".repeat(goto_indent);
        let mut replacement: Vec<String> = stmts.iter().map(|s| format!("{indent}{s}")).collect();
        replacement.push(format!("{indent}{}", terminal.unwrap()));
        lines[i] = replacement.join("\n");
        inlined_labels.insert(target.to_string());
        i += 1;
    }
    // Remove labels that no longer have any goto references
    let text = lines.join("\n");
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.len() > 2 && t.starts_with('L') && t.ends_with(':') {
            let label_num = &t[1..t.len() - 1];
            if inlined_labels.contains(label_num) && !text.contains(&format!("goto L{label_num};"))
            {
                continue;
            }
        }
        out.push(line.to_string());
    }
    out.join("\n")
}

fn apply_switch_break(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let mut i = 0usize;
    while i < lines.len() {
        let t = lines[i].trim().to_string();
        let Some(_target) = t.strip_prefix("goto L").and_then(|r| r.strip_suffix(';')) else {
            i += 1;
            continue;
        };
        // Next non-empty line must be a case boundary: "}", "case ", or "default:"
        let mut j = i + 1;
        while j < lines.len() && lines[j].trim().is_empty() {
            j += 1;
        }
        if j >= lines.len() {
            i += 1;
            continue;
        }
        let next = lines[j].trim();
        if !(next == "}" || next.starts_with("case ") || next.starts_with("default:")) {
            i += 1;
            continue;
        }
        // Look back for the enclosing switch (track brace depth for nested blocks)
        let mut depth = 0i32;
        let mut in_switch = false;
        for k in (0..i).rev() {
            let lt = lines[k].trim();
            depth += lt.matches('}').count() as i32;
            depth -= lt.matches('{').count() as i32;
            if depth < 0 {
                // We've exited the enclosing block
                if lt.starts_with("switch (") {
                    in_switch = true;
                }
                break;
            }
            if lt.starts_with("case ") || lt.starts_with("default:") {
                in_switch = true;
                break;
            }
        }
        if in_switch {
            let indent = lines[i].len() - lines[i].trim_start().len();
            lines[i] = format!("{}break;", " ".repeat(indent));
        }
        i += 1;
    }
    lines.join("\n")
}

fn apply_dead_assign(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<String> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        // Check for assignments to vN variables
        let Some((lhs, _)) = t.strip_suffix(';').and_then(|l| l.split_once(" = ")) else {
            out.push(line.to_string());
            continue;
        };
        let var = lhs.split_whitespace().last().unwrap_or(lhs).trim();
        if !(var.starts_with('v') && var[1..].chars().all(|c| c.is_ascii_digit())) {
            out.push(line.to_string());
            continue;
        }
        // Check if var appears in any subsequent line (within 100 lines)
        let mut used = false;
        for line_ref in lines.iter().take(lines.len().min(i + 100)).skip(i + 1) {
            if contains_token(line_ref, var) {
                used = true;
                break;
            }
        }
        if !used {
            // Also check if var is used in the same line (after =)
            // (already excluded by the split)
            continue;
        }
        out.push(line.to_string());
    }
    out.join("\n")
}

fn apply_empty_then_inversion(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let mut i = 0usize;
    while i < lines.len() {
        let t = lines[i].trim().to_string();
        let Some(cond) = t
            .strip_prefix("if (")
            .and_then(|r| r.strip_suffix(") {"))
            .map(|c| c.to_string())
        else {
            i += 1;
            continue;
        };
        // Next non-empty line must be "}" or "} else {" (empty then arm)
        let mut j = i + 1;
        while j < lines.len() && lines[j].trim().is_empty() {
            j += 1;
        }
        if j >= lines.len() {
            i += 1;
            continue;
        }
        let next_t = lines[j].trim();
        let (close_line, else_line) = if next_t == "} else {" {
            // Combined "} else {" on one line
            (j, j)
        } else if next_t == "}" {
            // Separate "}" then "else {"
            let mut k = j + 1;
            while k < lines.len() && lines[k].trim().is_empty() {
                k += 1;
            }
            if k >= lines.len() || lines[k].trim() != "else {" {
                i += 1;
                continue;
            }
            (j, k)
        } else {
            i += 1;
            continue;
        };
        // Invert: replace if-line, remove } and else {
        let indent = lines[i].len() - lines[i].trim_start().len();
        let negated = negate_condition_text(&cond);
        lines[i] = format!("{}if ({negated}) {{", " ".repeat(indent));
        if close_line == else_line {
            lines[close_line] = String::new();
        } else {
            lines[close_line] = String::new();
            lines[else_line] = String::new();
        }
        i = else_line + 1;
    }
    lines.join("\n")
}

fn negate_condition_text(cond: &str) -> String {
    let c = cond.trim();
    if let Some(inner) = c.strip_prefix("!(").and_then(|s| s.strip_suffix(')')) {
        return inner.to_string();
    }
    for (op, neg) in [
        (" == 0", " != 0"),
        (" != 0", " == 0"),
        (" == null", " != null"),
        (" != null", " == null"),
    ] {
        if c.ends_with(op) {
            let base = c.strip_suffix(op).unwrap_or(c);
            return format!("{base}{neg}");
        }
    }
    for (op, neg) in [
        (" == ", " != "),
        (" != ", " == "),
        (" < ", " >= "),
        (" >= ", " < "),
        (" > ", " <= "),
        (" <= ", " > "),
    ] {
        if let Some(pos) = c.rfind(op) {
            let lhs = &c[..pos];
            let rhs = &c[pos + op.len()..];
            return format!("{lhs}{neg}{rhs}");
        }
    }
    format!("!({c})")
}

fn apply_boolean_condition_simplify(text: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        out.push(simplify_condition_line(line));
    }
    out.join("\n")
}

fn simplify_condition_line(line: &str) -> String {
    let trimmed = line.trim();
    if !trimmed.starts_with("if (") && !trimmed.starts_with("while (") {
        return line.to_string();
    }
    // Extract the condition: everything between the first ( and the last ) before {
    let open = match line.find('(') {
        Some(p) => p,
        None => return line.to_string(),
    };
    let close = match line.rfind(") {") {
        Some(p) => p,
        None => return line.to_string(),
    };
    if close <= open {
        return line.to_string();
    }
    let cond = &line[open + 1..close];
    let indent = line.len() - line.trim_start().len();
    let prefix = &line[..open];
    let _suffix = &line[close + 2..];

    if let Some(expr) = cond.strip_suffix(" == 0") {
        let expr = expr.trim();
        let expr = strip_outer_parens_pair(expr);
        if is_boolean_call(expr) {
            return format!(
                "{}{} (!({})) {{",
                " ".repeat(indent),
                prefix.trim_end(),
                expr
            );
        }
        return line.to_string();
    }
    if let Some(expr) = cond.strip_suffix(" != 0") {
        let expr = expr.trim();
        let expr = strip_outer_parens_pair(expr);
        if is_boolean_call(expr) {
            return format!("{}{} ({}) {{", " ".repeat(indent), prefix.trim_end(), expr);
        }
        return line.to_string();
    }
    line.to_string()
}

fn is_boolean_call(expr: &str) -> bool {
    if !expr.contains('(') || !expr.contains(')') {
        return false;
    }
    !expr.contains(" & ") && !expr.contains(" | ") && !expr.contains(" ^ ")
}

fn strip_outer_parens_pair(s: &str) -> &str {
    s.strip_prefix('(')
        .and_then(|inner| inner.strip_suffix(')'))
        .unwrap_or(s)
}

fn extract_field_name(rhs: &str) -> Option<String> {
    // vN = this.fieldName; or vN = obj.fieldName;
    let r = rhs.trim().strip_suffix(';').unwrap_or(rhs.trim());
    let dot_pos = r.rfind('.')?;
    let field = &r[dot_pos + 1..];
    if field.is_empty() || field.contains('(') || field.contains(' ') {
        return None;
    }
    if !field
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
    {
        return None;
    }
    // Only if the receiver is `this` or a simple identifier
    let recv = &r[..dot_pos];
    if recv.contains('(') || recv.contains('[') {
        return None;
    }
    Some(camel_case(field))
}

fn extract_getter_name(rhs: &str) -> Option<String> {
    let r = rhs.trim().strip_suffix(';').unwrap_or(rhs.trim());
    let paren = r.find('(')?;
    if !r[paren..].ends_with("()") {
        return None;
    }
    let method_part = &r[..paren];
    let dot = method_part.rfind('.')?;
    let method = &method_part[dot + 1..];
    let rest = method
        .strip_prefix("get")
        .or_else(|| method.strip_prefix("is"))?;
    if rest.len() <= 1 || !rest.chars().next().is_some_and(|c| c.is_uppercase()) {
        return None;
    }
    let mut chars = rest.chars();
    let first = chars.next()?.to_lowercase().next()?;
    let name = format!("{first}{}", chars.as_str());
    if name.is_empty() {
        return None;
    }
    Some(name)
}

fn apply_semantic_names(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut name_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut type_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for line in &lines {
        let t = line.trim();
        let Some((lhs, rhs)) = t.strip_suffix(';').and_then(|l| l.split_once(" = ")) else {
            continue;
        };
        let var = lhs.split_whitespace().last().unwrap_or(lhs).trim();
        if !(var.starts_with('v') && var[1..].chars().all(|c| c.is_ascii_digit())) {
            continue;
        }
        let rhs_t = rhs.trim();
        let semantic = if let Some(t) = rhs_t
            .strip_prefix('(')
            .and_then(|r| r.split_once(')'))
            .map(|(t, _)| t.to_string())
            .filter(|t| looks_like_java_type(t))
        {
            let short = t.rsplit('.').next().unwrap_or(&t);
            camel_case(short)
        } else if rhs_t.ends_with(".iterator()") {
            "it".to_string()
        } else if rhs_t.ends_with(".size()") || rhs_t.ends_with(".length()") {
            "size".to_string()
        } else if rhs_t.ends_with(".toString()") {
            "str".to_string()
        } else if let Some(ty) = rhs_t.strip_prefix("new ") {
            let ty_name = ty.split('(').next().unwrap_or(ty).trim();
            let short = ty_name.rsplit('.').next().unwrap_or(ty_name);
            if short.is_empty() || !short.chars().next().is_some_and(|c| c.is_uppercase()) {
                continue;
            }
            camel_case(short)
        } else if let Some(field) = extract_field_name(rhs_t) {
            field
        } else if let Some(getter) = extract_getter_name(rhs_t) {
            getter
        } else {
            continue;
        };
        let count = type_counts.entry(semantic.clone()).or_insert(0);
        *count += 1;
        let final_name = if *count == 1 {
            semantic
        } else {
            format!("{semantic}{count}")
        };
        name_map.insert(var.to_string(), final_name);
    }
    if name_map.is_empty() {
        return text.to_string();
    }
    let mut out: Vec<String> = Vec::new();
    for line in &lines {
        let mut l = line.to_string();
        for (old, new) in &name_map {
            l = replace_token(&l, old, new);
        }
        out.push(l);
    }
    out.join("\n")
}

fn looks_like_java_type(s: &str) -> bool {
    if s.is_empty() || s.contains(' ') || s.contains('(') || s.contains(')') {
        return false;
    }
    let first = s.chars().next().unwrap();
    if !first.is_uppercase() {
        return false;
    }
    s.chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '_' || c == '$')
}

fn camel_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut first = true;
    for c in s.chars() {
        if first {
            out.extend(c.to_lowercase());
            first = false;
        } else {
            out.push(c);
        }
    }
    out
}

fn paren_match(chars: &[char], open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    for (i, &c) in chars.iter().enumerate().skip(open) {
        if in_str {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn unwrap_paren_ok(chars: &[char], i: usize, close: usize, prefix: &[char]) -> bool {
    let content = &chars[i + 1..close];
    if content.is_empty() {
        return false;
    }
    let cs: String = content.iter().collect();
    let base = cs.strip_suffix("[]").unwrap_or(&cs);
    if matches!(
        base,
        "int" | "byte" | "short" | "char" | "long" | "float" | "double" | "boolean"
    ) {
        return false;
    }
    let mut p = prefix.len();
    while p > 0 && prefix[p - 1].is_whitespace() {
        p -= 1;
    }
    if p > 0 {
        let pc = prefix[p - 1];
        if pc.is_alphanumeric() || pc == '_' || pc == ')' || pc == ']' || pc == '"' {
            let mut w = p;
            while w > 0 && (prefix[w - 1].is_alphanumeric() || prefix[w - 1] == '_') {
                w -= 1;
            }
            let word: String = prefix[w..p].iter().collect();
            if word != "return" && word != "throw" {
                return false;
            }
        }
    }
    let mut nx = close + 1;
    while nx < chars.len() && chars[nx].is_whitespace() {
        nx += 1;
    }
    if nx < chars.len() {
        let nc = chars[nx];
        if nc.is_alphanumeric() || nc == '_' || matches!(nc, '(' | '"' | '\'' | '!' | '~') {
            return false;
        }
    }
    if content[0] == '(' && paren_match(content, 0) == Some(content.len() - 1) {
        return true;
    }
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    for &c in content {
        if in_str {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            '+' | '-' | '*' | '/' | '%' | '&' | '|' | '^' | '<' | '>' | '=' | '?' | ':' | ','
            | '!' | '~'
                if depth == 0 =>
            {
                return false;
            }
            _ => {}
        }
    }
    true
}

fn apply_cast_paren_cleanup(text: &str) -> String {
    let out: Vec<String> = text
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("//") {
                return l.to_string();
            }
            let mut line = l.to_string();
            for _round in 0..8 {
                let chars: Vec<char> = line.chars().collect();
                let mut result: Vec<char> = Vec::with_capacity(chars.len());
                let mut drop: std::collections::HashSet<usize> = std::collections::HashSet::new();
                let mut i = 0usize;
                let mut in_str = false;
                let mut esc = false;
                let mut changed = false;
                while i < chars.len() {
                    if drop.contains(&i) {
                        i += 1;
                        continue;
                    }
                    let c = chars[i];
                    if in_str {
                        result.push(c);
                        if esc {
                            esc = false;
                        } else if c == '\\' {
                            esc = true;
                        } else if c == '"' {
                            in_str = false;
                        }
                        i += 1;
                        continue;
                    }
                    if c == '"' {
                        in_str = true;
                        result.push(c);
                        i += 1;
                        continue;
                    }
                    if c == '('
                        && let Some(close) = paren_match(&chars, i)
                        && unwrap_paren_ok(&chars, i, close, &result)
                    {
                        drop.insert(close);
                        changed = true;
                        i += 1;
                        continue;
                    }
                    result.push(c);
                    i += 1;
                }
                line = result.into_iter().collect();
                if !changed {
                    break;
                }
            }
            line
        })
        .collect();
    out.join("\n")
}

fn apply_enhanced_for(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let mut i = 0usize;
    while i < lines.len() {
        let t = lines[i].trim().to_string();
        let Some((lhs, rhs)) = t.strip_suffix(';').and_then(|l| l.split_once(" = ")) else {
            i += 1;
            continue;
        };
        let iter = lhs.split_whitespace().last().unwrap_or(lhs).trim();
        let recv = rhs.trim();
        let Some(coll) = recv.strip_suffix(".iterator()") else {
            i += 1;
            continue;
        };
        if iter.is_empty()
            || coll.is_empty()
            || !iter.chars().all(|c| c.is_alphanumeric() || c == '_')
        {
            i += 1;
            continue;
        }
        let has_call = format!("{iter}.hasNext(");
        let next_call = format!("{iter}.next(");
        // Scan forward (up to 5 non-empty lines) for the hasNext check
        let mut j = i + 1;
        let mut non_empty = 0;
        while j < lines.len() && non_empty < 5 {
            if lines[j].trim().is_empty() {
                j += 1;
                continue;
            }
            non_empty += 1;
            let w = lines[j].trim();
            if !(w.contains(&has_call) && w.ends_with('{')) {
                j += 1;
                continue;
            }
            // Found hasNext — check if while or inverted if
            let is_while = w.starts_with("while (");
            let is_inverted = w.starts_with("if (");
            if !is_while && !is_inverted {
                j += 1;
                continue;
            }
            let if_line = j;
            if is_inverted {
                let mut j2 = j + 1;
                while j2 < lines.len() && lines[j2].trim().is_empty() {
                    j2 += 1;
                }
                if j2 >= lines.len() || lines[j2].trim() != "} else {" {
                    j = j2;
                    continue;
                }
                j = j2;
            }
            // Scan forward for the .next() assignment
            let mut k = j + 1;
            let mut next_found = false;
            let mut elem_type = String::new();
            let mut elem_name = String::new();
            while k < lines.len() && k < j + 10 {
                let n = lines[k].trim();
                if n.is_empty() {
                    k += 1;
                    continue;
                }
                if n == "}" {
                    break;
                }
                if let Some((nlhs, nrhs)) = n.strip_suffix(';').and_then(|l| l.split_once(" = "))
                    && nrhs.contains(&next_call)
                {
                    let decl = nlhs.trim();
                    let name = decl.split_whitespace().last().unwrap_or(decl);
                    if decl.contains(' ') {
                        let (ty, _) = decl.rsplit_once(' ').unwrap();
                        elem_type = ty.to_string();
                    } else {
                        let cast_type = nrhs
                            .trim()
                            .strip_prefix('(')
                            .and_then(|r| r.split_once(')'))
                            .map(|(t, _)| t.to_string());
                        if let Some(ct) = cast_type {
                            elem_type = ct;
                        }
                    }
                    elem_name = name.to_string();
                    next_found = true;
                    break;
                }
                k += 1;
            }
            if !next_found || elem_type.is_empty() || elem_name.is_empty() {
                break;
            }
            let elem_type = elem_type
                .trim_start_matches('(')
                .trim_end_matches(')')
                .to_string();
            let indent = lines[j].len() - lines[j].trim_start().len();
            let coll_clean = coll
                .strip_prefix('(')
                .and_then(|c| c.strip_suffix(')'))
                .unwrap_or(coll);
            lines[j] = format!(
                "{}for ({} {} : {}) {{",
                " ".repeat(indent),
                elem_type,
                elem_name,
                coll_clean
            );
            lines[i] = String::new();
            lines[k] = String::new();
            if is_inverted {
                let orig_if = if_line;
                if orig_if < lines.len() {
                    lines[orig_if] = String::new();
                }
            }
            // For inverted: remove the "} else {" line
            if is_inverted {
                let mut j3 = j;
                while j3 > 0 && lines[j3].trim().is_empty() {
                    j3 -= 1;
                }
            }
            break;
        }
        i += 1;
    }
    lines.join("\n")
}

fn apply_arm_tail_goto_cleanup(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    // Build label positions to determine goto direction
    let mut label_pos: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (idx, line) in lines.iter().enumerate() {
        let t = line.trim();
        if t.len() > 2 && t.starts_with('L') && t.ends_with(':') {
            label_pos.insert(t[1..t.len() - 1].to_string(), idx);
        }
    }
    let mut i = 0usize;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if let Some(target) = trimmed
            .strip_prefix("goto L")
            .and_then(|r| r.strip_suffix(';'))
        {
            // Only remove FORWARD gotos (target label appears after this line)
            let is_forward = label_pos.get(target).is_some_and(|&pos| pos > i);
            if is_forward {
                let mut j = i + 1;
                while j < lines.len() && lines[j].trim().is_empty() {
                    j += 1;
                }
                if j < lines.len() {
                    let next = lines[j].trim();
                    if next == "}" || next == "} else {" {
                        lines[i] = String::new();
                    }
                }
            }
        }
        i += 1;
    }
    lines.join("\n")
}

fn apply_dead_allocation_cleanup(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("= new StringBuilder()") {
            let var = trimmed
                .strip_suffix(";")
                .and_then(|l| l.split_once(" = "))
                .map(|(v, _)| v.trim())
                .map(|v| v.split_whitespace().last().unwrap_or(v))
                .unwrap_or("");
            if !var.is_empty() {
                let uses = lines
                    .iter()
                    .enumerate()
                    .filter(|(j, l2)| *j != i && contains_token(l2, var))
                    .count();
                if uses == 0 {
                    continue;
                }
            }
        }
        out.push(*line);
    }
    out.join("\n")
}

fn apply_latch_continue_cleanup(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let mut i = 1usize;
    while i < lines.len() {
        if lines[i].trim() == "}" {
            let mut j = i;
            while j > 0 && lines[j - 1].trim().is_empty() {
                j -= 1;
            }
            if j > 0 && lines[j - 1].trim() == "continue;" {
                lines[j - 1] = String::new();
            }
        }
        i += 1;
    }
    lines.join("\n")
}

pub struct TryInfo {
    pub handler_types: HashMap<u32, Vec<String>>,
    pub catch_all_addrs: Vec<u32>,
    pub try_regions: Vec<(u32, u32)>,
    pub entries: Vec<TryEntry>,
    pub shared_handlers: std::collections::HashSet<u32>,
}

pub struct TryEntry {
    pub k: usize,
    pub start: u32,
    pub end: u32,
    pub handlers: Vec<(u32, Vec<String>)>,
}

pub fn build_try_info(dex: &DexFile, tries: &[crate::TryItem]) -> TryInfo {
    let mut handler_types: HashMap<u32, Vec<String>> = HashMap::new();
    let mut catch_all_addrs = Vec::new();
    let mut try_regions = Vec::new();
    let mut entries: Vec<TryEntry> = Vec::new();
    let mut handler_ref_count: HashMap<u32, usize> = HashMap::new();
    for (k, t) in tries.iter().enumerate() {
        let region = (t.start_addr, t.start_addr + t.insn_count as u32);
        if !try_regions.contains(&region) {
            try_regions.push(region);
        }
        let mut entry_handlers: Vec<(u32, Vec<String>)> = Vec::new();
        for h in &t.handlers {
            let type_desc = dex
                .types
                .get(h.type_idx as usize)
                .cloned()
                .unwrap_or_default();
            let jt = crate::types::java_type(&type_desc);
            let entry = handler_types.entry(h.addr).or_default();
            if !entry.contains(&jt) {
                entry.push(jt.clone());
            }
            *handler_ref_count.entry(h.addr).or_default() += 1;
            if let Some((_, types)) = entry_handlers.iter_mut().find(|(a, _)| *a == h.addr) {
                if !types.contains(&jt) {
                    types.push(jt);
                }
            } else {
                entry_handlers.push((h.addr, vec![jt]));
            }
        }
        if let Some(addr) = t.catch_all_addr {
            if !catch_all_addrs.contains(&addr) {
                catch_all_addrs.push(addr);
            }
            *handler_ref_count.entry(addr).or_default() += 1;
            let throwable = "Throwable".to_string();
            if let Some((_, types)) = entry_handlers.iter_mut().find(|(a, _)| *a == addr) {
                if !types.contains(&throwable) {
                    types.push(throwable);
                }
            } else {
                entry_handlers.push((addr, vec![throwable]));
            }
        }
        entries.push(TryEntry {
            k,
            start: t.start_addr,
            end: t.start_addr + t.insn_count as u32,
            handlers: entry_handlers,
        });
    }
    let shared_handlers = handler_ref_count
        .into_iter()
        .filter(|(_, c)| *c > 1)
        .map(|(a, _)| a)
        .collect();
    TryInfo {
        handler_types,
        catch_all_addrs,
        try_regions,
        entries,
        shared_handlers,
    }
}

pub fn render_method_pseudocode_full(
    output: &crate::lift::LiftOutput,
    try_info: &TryInfo,
) -> String {
    let func = &output.func;
    let value_types = &output.value_types;
    let switch_cases = &output.switch_cases;
    let mut ctx = RenderCtx::new(func);
    ctx.value_types = value_types.clone();

    let mut order = reverse_post_order(func);
    let reachable: std::collections::HashSet<BlockId> = order.iter().copied().collect();
    let mut orphans: Vec<BlockId> = func
        .cfg
        .blocks
        .iter()
        .map(|b| b.id)
        .filter(|id| !reachable.contains(id))
        .collect();
    orphans.sort_by_key(|id| func.cfg.blocks[id.0 as usize].start_addr);
    order.extend(orphans);
    let mut block_renders: HashMap<BlockId, crate::structure::BlockRender> = HashMap::new();
    for &bid in &order {
        let block = &func.cfg.blocks[bid.0 as usize];
        let mut lines = Vec::new();
        let mut cond: Option<(String, BlockId, BlockId)> = None;
        let mut jump: Option<BlockId> = None;
        let mut cond_value_id: Option<SsaValueId> = None;
        for &iid in &block.insts {
            if let Some(inst) = func.values.get(iid.0 as usize)
                && let SsaOp::Branch { cond: c, .. } = &inst.op
                && let Operand::Value(id) = c
            {
                cond_value_id = Some(*id);
            }
        }
        let mut is_switch_block = false;
        let mut switch_val = String::new();
        for &iid in &block.insts {
            let Some(inst) = func.values.get(iid.0 as usize) else {
                continue;
            };
            match &inst.op {
                SsaOp::Branch {
                    cond: c,
                    true_block,
                    false_block,
                } => {
                    cond = Some((ctx.cond_text(c), *true_block, *false_block));
                }
                SsaOp::Jump { target } => {
                    jump = Some(*target);
                }
                SsaOp::Call { target, args } => {
                    if let Operand::Symbol(s) = target
                        && s == "__switch"
                    {
                        is_switch_block = true;
                        switch_val = args
                            .first()
                            .map(|a| ctx.operand_text(a))
                            .unwrap_or_default();
                    } else {
                        if let Some(line) = ctx.render_inst(iid)
                            && !line.starts_with("// phi()")
                        {
                            lines.push(line);
                        }
                    }
                }
                _ => {
                    if cond_value_id == Some(iid) {
                        continue;
                    }
                    if let Some(line) = ctx.render_inst(iid)
                        && !line.starts_with("// phi()")
                    {
                        lines.push(line);
                    }
                }
            }
        }
        let switch = if is_switch_block && let Some(cases) = switch_cases.get(&bid) {
            lines.retain(|l| !l.contains("// switch ("));
            Some((switch_val.clone(), cases.clone()))
        } else {
            None
        };
        if cond.is_none()
            && jump.is_none()
            && switch.is_none()
            && let Some(succs) = func.cfg.succs.get(bid.0 as usize)
            && succs.len() == 1
        {
            jump = Some(succs[0]);
        }
        let block_addr = block.start_addr as u32;
        let mut prefix: Vec<String> = Vec::new();
        let suffix: Vec<String> = Vec::new();
        for e in &try_info.entries {
            if e.end == block_addr {
                prefix.push(format!("// endtry@{}", e.k));
            }
        }
        for e in &try_info.entries {
            if e.start == block_addr {
                prefix.push(format!("// try@{}", e.k));
            }
        }
        let mut catch_ks: Vec<(usize, String)> = Vec::new();
        for e in &try_info.entries {
            if let Some((_, types)) = e.handlers.iter().find(|(a, _)| *a == block_addr) {
                catch_ks.push((e.k, types.join(" | ")));
            }
        }
        let terminates = lines
            .iter()
            .rev()
            .map(|l| l.trim())
            .find(|t| !t.is_empty() && !t.starts_with("//"))
            .is_some_and(|t| {
                t.starts_with("return") || t.starts_with("throw ") || t.starts_with("goto L")
            });
        let mut all_lines = prefix;
        if !catch_ks.is_empty() && terminates {
            for (k, types) in &catch_ks {
                all_lines.push(format!("// catch@{k} ({types} e)"));
                all_lines.extend(lines.iter().cloned());
                all_lines.push(format!("// endcatch@{k}"));
            }
        } else {
            if !catch_ks.is_empty() {
                let mut all: Vec<String> = Vec::new();
                for (_, types) in &catch_ks {
                    for t in types.split(" | ") {
                        if !all.iter().any(|x| x == t) {
                            all.push(t.to_string());
                        }
                    }
                }
                all_lines.push(format!("// catch ({} e)", all.join(" | ")));
            }
            all_lines.extend(lines);
        }
        all_lines.extend(suffix);
        block_renders.insert(
            bid,
            crate::structure::BlockRender {
                lines: all_lines,
                cond,
                jump,
                switch,
            },
        );
    }

    let text = crate::structure::render_structured(func, &block_renders);
    let text = text.trim_end().to_string();
    if text.is_empty() {
        return "    <empty>".to_string();
    }
    let text = fuse_new_init(&text);
    let text = apply_copy_chain_collapse(&text);
    let text = apply_string_concat_fold(&text);
    let text = apply_for_loop_recovery(&text);
    let text = apply_latch_continue_cleanup(&text);
    let text = apply_dead_allocation_cleanup(&text);
    let text = apply_arm_tail_goto_cleanup(&text);
    let text = apply_boxing_cleanup(&text);
    let text = apply_enhanced_for(&text);
    let text = apply_empty_then_inversion(&text);
    let text = apply_boolean_condition_simplify(&text);
    let text = apply_semantic_names(&text);
    let text = apply_cast_paren_cleanup(&text);
    let text = apply_loop_recovery(&text);
    let text = apply_dead_goto_after_else(&text);
    let text = apply_guard_flatten(&text);
    let text = apply_else_if_collapse(&text);
    let text = apply_loop_wrap(&text);
    let text = apply_switch_break(&text);
    let text = apply_small_block_inline(&text);
    let text = apply_dead_assign(&text);
    let text = apply_guard_flatten(&text);
    let text = apply_else_if_collapse(&text);
    let text = apply_empty_else_removal(&text);
    let name_to_id: HashMap<String, SsaValueId> = ctx
        .value_names
        .iter()
        .map(|(id, name)| (name.clone(), *id))
        .collect();
    let text = apply_typed_declarations(&text, value_types, &name_to_id);
    let text = apply_type_based_names(&text);
    let text = apply_unused_label_cleanup(&text);
    let text = apply_control_kind_repair(&text);
    let text = apply_condition_paren_repair(&text);
    let text = apply_stmt_paren_repair(&text);
    let text = apply_cast_paren_cleanup(&text);
    let text = apply_brace_repair(&text);
    let text = apply_labeled_continue(&text);
    let text = apply_try_catch_syntax(&text);
    apply_reindent(&text)
}

pub fn decompile_dex(
    dex: &DexFile,
    class_filter: Option<&str>,
    method_filter: Option<&str>,
    limit: usize,
) -> Vec<MethodPseudocode> {
    let mut out = Vec::new();
    for class in &dex.classes {
        if let Some(f) = class_filter
            && !class.class.contains(f)
        {
            continue;
        }
        let Some(cd) = &class.class_data else {
            continue;
        };
        for m in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
            let sig = dex.method_signature(m.method_idx);
            if let Some(f) = method_filter
                && !sig.contains(f)
            {
                continue;
            }
            if m.code_off == 0 {
                out.push(MethodPseudocode {
                    signature: sig,
                    pseudocode: "    <no code>".to_string(),
                    registers: 0,
                    insn_units: 0,
                });
                continue;
            }
            match dex.code_item(m.code_off) {
                Ok(code) => {
                    let mc = decompile_method(dex, &code, m.method_idx);
                    out.push(mc);
                }
                Err(e) => {
                    out.push(MethodPseudocode {
                        signature: sig,
                        pseudocode: format!("    <code read error: {e}>"),
                        registers: 0,
                        insn_units: 0,
                    });
                }
            }
            if out.len() >= limit {
                return out;
            }
        }
    }
    out
}

fn field_name(field_ref: &str) -> String {
    field_ref
        .split_once("->")
        .map(|(_, rest)| rest.split(':').next().unwrap_or(rest).to_string())
        .unwrap_or_else(|| field_ref.to_string())
}

fn field_class(field_ref: &str) -> String {
    let class = field_ref
        .split_once("->")
        .map(|(class, _)| class)
        .unwrap_or(field_ref);
    crate::types::simple_name(&crate::types::java_type(class))
}

fn clean_type_name(t: &str) -> String {
    t.trim_start_matches('L')
        .trim_end_matches(';')
        .replace('/', ".")
        .replace("java.lang.", "")
        .replace("java.io.", "")
        .replace("java.util.", "")
}

fn render_invoke_call(
    kind_char: char,
    sig: &str,
    arg_texts: &[String],
    is_used: bool,
    name: &str,
) -> String {
    let Some((class_part, method_part)) = sig.split_once("->") else {
        return format!("{name} = {sig}({});", arg_texts.join(", "));
    };
    let class_name = clean_type_name(class_part);
    let method_name = method_part.split('(').next().unwrap_or(method_part);
    let is_constructor = method_name == "<init>";

    match kind_char {
        's' => {
            let args_str = arg_texts.join(", ");
            if is_used {
                format!("{name} = {class_name}.{method_name}({args_str});")
            } else {
                format!("{class_name}.{method_name}({args_str});")
            }
        }
        'v' | 'i' | 'p' => {
            let recv = arg_texts.first().cloned().unwrap_or_default();
            let call_args = if arg_texts.len() > 1 {
                arg_texts[1..].join(", ")
            } else {
                String::new()
            };
            if is_constructor {
                format!("{name} = new {class_name}({call_args});")
            } else if is_used {
                format!("{name} = {recv}.{method_name}({call_args});")
            } else {
                format!("{recv}.{method_name}({call_args});")
            }
        }
        'd' => {
            let recv = arg_texts.first().cloned().unwrap_or_default();
            let call_args = if arg_texts.len() > 1 {
                arg_texts[1..].join(", ")
            } else {
                String::new()
            };
            if is_constructor {
                if recv == "this" || recv == "p0" {
                    format!("super({call_args});")
                } else {
                    format!("{name} = new {class_name}({call_args});")
                }
            } else if is_used {
                format!("{name} = {recv}.{method_name}({call_args});")
            } else {
                format!("{recv}.{method_name}({call_args});")
            }
        }
        _ => {
            if is_used {
                format!(
                    "{name} = {class_name}.{method_name}({});",
                    arg_texts.join(", ")
                )
            } else {
                format!("{class_name}.{method_name}({});", arg_texts.join(", "))
            }
        }
    }
}

#[cfg(test)]
mod concat_tests {
    use super::*;

    #[test]
    fn folds_simple_append_chain() {
        let line = "return ((v1.append((\" [ SEQ = \"))).append(this.j)).toString();";
        let folded = fold_concat_line(line);
        eprintln!("folded: {folded:?}");
        assert!(folded.is_some(), "should fold");
    }

    #[test]
    fn folds_real_tostring_chain() {
        let line = "return (((((((((v1.append((this.a()))).append((\" [ SEQ = \"))).append(this.j)).append((\", ACK = \"))).append(v30)).append((\", LEN = \"))).append((this.b()))).append((\" ]\"))).toString();";
        let folded = fold_concat_line(line);
        eprintln!("folded: {folded:?}");
        assert!(folded.is_some(), "should fold real chain");
        let f = folded.unwrap();
        assert!(f.contains(" + "), "result should contain +: {f}");
        assert!(
            !f.contains("append"),
            "result should not contain append: {f}"
        );
    }

    #[test]
    fn trace_strip_steps() {
        let line = "return (((v1.append((this.a()))).append(v30)).toString());";
        let rest = line.trim().strip_prefix("return ").unwrap();
        let after_semi = rest.trim().strip_suffix(';');
        eprintln!("after_semi: {after_semi:?}");
        let after_paren = after_semi.and_then(|r| r.strip_suffix(')'));
        eprintln!("after_paren: {after_paren:?}");
        let after_ts = after_paren.and_then(|r| r.strip_suffix(".toString()"));
        eprintln!("after_toString: {after_ts:?}");
        assert!(after_ts.is_some(), "toString strip should work");
    }
}

#[cfg(test)]
mod boxing_tests {
    use super::*;

    #[test]
    fn removes_string_value_of_identifier() {
        let input = "v1 = (\"text\").concat((String.valueOf(p1)));";
        let out = apply_boxing_cleanup(input);
        eprintln!("in:  {input}");
        eprintln!("out: {out}");
        assert!(!out.contains("String.valueOf(p1)"), "{out}");
    }

    #[test]
    fn removes_string_value_of_literal() {
        let input = "v1 = String.valueOf(\"hello\");";
        let out = apply_boxing_cleanup(input);
        eprintln!("out: {out}");
        assert!(!out.contains("String.valueOf"), "{out}");
    }
}
