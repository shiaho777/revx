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
                let l = self.operand_text(lhs);
                let r = self.operand_text(rhs);
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
        let class_part = expr.trim_start_matches("new ").trim_end_matches("()");
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
                && m_expr.starts_with("new ")
                && m_expr.contains(class_part)
            {
                let args = m_expr
                    .trim_start_matches("new ")
                    .trim_start_matches(class_part)
                    .trim_start_matches('(')
                    .trim_end_matches(')')
                    .to_string();
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
        // The goto must be inside a simple if (no else clause).
        // Find the closing } after the goto, then check it's not followed by else {
        let mut close = i + 1;
        while close < lines.len() && lines[close].trim().is_empty() {
            close += 1;
        }
        if close >= lines.len() {
            i += 1;
            continue;
        }
        let after_close = lines[close].trim();
        if after_close == "} else {" || after_close == "else {" || after_close.starts_with("else ")
        {
            i += 1;
            continue;
        }
        // The if line must not already have an else in the condition area
        // (between the if and the goto, at the same indent, no "} else {")
        let if_indent = lines[if_line].len() - lines[if_line].trim_start().len();
        for (j, line_ref) in lines.iter().enumerate().take(i).skip(if_line + 1) {
            let lt = line_ref.trim().to_string();
            let li = line_ref.len() - line_ref.trim_start().len();
            if lt == "} else {" && li == if_indent {
                let goto_i = lines[i].len() - lines[i].trim_start().len();
                if goto_i > li {
                    continue;
                }
                let mut not_loop = true;
                for k2 in lines.iter().take(i).skip(j) {
                    let lk = k2.len() - k2.trim_start().len();
                    if lk <= if_indent && k2.trim() == "}" {
                        not_loop = false;
                        break;
                    }
                }
                if not_loop {
                    i += 1;
                    continue;
                }
            }
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
        for line_ref in lines.iter_mut().take(i).skip(if_line + 1) {
            if line_ref.trim() == format!("goto {goto_target};") {
                *line_ref = String::new();
            }
        }
        i += 1;
    }
    lines.join("\n")
}

fn apply_switch_break(text: &str) -> String {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    // Find "goto L{N};" that appears right before "}" inside switch cases
    // and the target L{N} is AFTER the switch. These should be break;
    let mut i = 0usize;
    while i < lines.len() {
        let t = lines[i].trim().to_string();
        let Some(_target) = t.strip_prefix("goto L").and_then(|r| r.strip_suffix(';')) else {
            i += 1;
            continue;
        };
        // Check if next non-empty line is "}" (end of case)
        let mut j = i + 1;
        while j < lines.len() && lines[j].trim().is_empty() {
            j += 1;
        }
        if j >= lines.len() || lines[j].trim() != "}" {
            i += 1;
            continue;
        }
        // Check if we're inside a switch (look back for "case " or "switch (")
        let mut in_switch = false;
        for k in (0..i).rev() {
            let lt = lines[k].trim();
            if lt.starts_with("case ") || lt.starts_with("switch (") {
                in_switch = true;
                break;
            }
            if lt == "}" && !lt.starts_with("case") {
                break;
            }
        }
        if in_switch {
            lines[i] = "break;".to_string();
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
        // Next non-empty line must be "}" (empty then arm)
        let mut j = i + 1;
        while j < lines.len() && lines[j].trim().is_empty() {
            j += 1;
        }
        if j >= lines.len() || lines[j].trim() != "}" {
            i += 1;
            continue;
        }
        // Next non-empty line must be "else {"
        let mut k = j + 1;
        while k < lines.len() && lines[k].trim().is_empty() {
            k += 1;
        }
        if k >= lines.len() || lines[k].trim() != "else {" {
            i += 1;
            continue;
        }
        // Invert: replace if-line, remove } and else {
        let indent = lines[i].len() - lines[i].trim_start().len();
        let negated = negate_condition_text(&cond);
        lines[i] = format!("{}if ({negated}) {{", " ".repeat(indent));
        lines[j] = String::new();
        lines[k] = String::new();
        i = k + 1;
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

fn apply_cast_paren_cleanup(text: &str) -> String {
    let mut out = text.to_string();
    // ((Type) (expr)) → (Type) expr
    loop {
        let before = out.clone();
        if let Some(pos) = out.find("((")
            && let Some(mid) = out[pos..].find(") (")
        {
            let inner_start = pos + 2;
            let cast_end = pos + mid + 1;
            let expr_start = cast_end + 2;
            if let Some(close) = out[expr_start..].find(')') {
                let expr_end = expr_start + close;
                let cast_type = &out[inner_start..cast_end - 1];
                let expr = &out[expr_start..expr_end];
                let replacement = format!("({cast_type}) {expr}");
                out = format!("{}{}{}", &out[..pos], replacement, &out[expr_end + 1..]);
            }
        }
        if out == before {
            break;
        }
    }
    out
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
    let mut i = 0usize;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.starts_with("goto L") && trimmed.ends_with(';') {
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
}

pub fn build_try_info(dex: &DexFile, tries: &[crate::TryItem]) -> TryInfo {
    let mut handler_types: HashMap<u32, Vec<String>> = HashMap::new();
    let mut catch_all_addrs = Vec::new();
    let mut try_regions = Vec::new();
    for t in tries {
        try_regions.push((t.start_addr, t.start_addr + t.insn_count as u32));
        for h in &t.handlers {
            let type_desc = dex
                .types
                .get(h.type_idx as usize)
                .cloned()
                .unwrap_or_default();
            handler_types
                .entry(h.addr)
                .or_default()
                .push(crate::types::java_type(&type_desc));
        }
        if let Some(addr) = t.catch_all_addr {
            catch_all_addrs.push(addr);
        }
    }
    TryInfo {
        handler_types,
        catch_all_addrs,
        try_regions,
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

    let handler_types = &try_info.handler_types;
    let catch_all_addrs = &try_info.catch_all_addrs;
    let try_regions = &try_info.try_regions;

    let order = reverse_post_order(func);
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
        let block_addr = block.start_addr as u32;
        let mut prefix: Vec<String> = Vec::new();
        if let Some(types) = handler_types.get(&block_addr) {
            for ty in types {
                prefix.push(format!("catch ({ty} e) {{"));
            }
        }
        if catch_all_addrs.contains(&block_addr) {
            prefix.push("catch (Throwable e) {".to_string());
        }
        if try_regions.iter().any(|(s, _)| block_addr == *s) {
            prefix.push("try {".to_string());
        }
        let _ = &try_regions;
        let mut all_lines = prefix;
        all_lines.extend(lines);
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
    let text = apply_switch_break(&text);
    let text = apply_dead_assign(&text);
    let name_to_id: HashMap<String, SsaValueId> = ctx
        .value_names
        .iter()
        .map(|(id, name)| (name.clone(), *id))
        .collect();
    apply_typed_declarations(&text, value_types, &name_to_id)
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
