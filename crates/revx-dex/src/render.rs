//! Java-style pseudocode rendering for lifted Dalvik SSA.

use crate::lift::lift_method_to_ssa;
use crate::{CodeItem, DexFile};
use revx_analysis::ssa::{BlockId, Operand, SsaFunction, SsaOp, SsaValueId};
use std::collections::{HashMap, HashSet};

struct RenderCtx<'a> {
    func: &'a SsaFunction,
    value_names: HashMap<SsaValueId, String>,
    emitted_defs: HashSet<SsaValueId>,
}

impl<'a> RenderCtx<'a> {
    fn new(func: &'a SsaFunction) -> Self {
        Self {
            func,
            value_names: HashMap::new(),
            emitted_defs: HashSet::new(),
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

    fn render_inst(&mut self, id: SsaValueId) -> Option<String> {
        let inst = self.func.values.get(id.0 as usize)?;
        let line = match &inst.op {
            SsaOp::Copy { src } => {
                let src_text = self.operand_text(src);
                if self.emitted_defs.contains(&id) {
                    return None;
                }
                self.emitted_defs.insert(id);
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
                    let fname = field.rsplit('.').next().unwrap_or(field);
                    let name = self.name_of(id);
                    format!("{name} = {obj}.{fname};")
                } else if t.starts_with("__iput:") {
                    let field = t.strip_prefix("__iput:").unwrap_or("");
                    let obj = arg_texts.first().cloned().unwrap_or_default();
                    let val = arg_texts.get(1).cloned().unwrap_or_default();
                    let fname = field.rsplit('.').next().unwrap_or(field);
                    format!("{obj}.{fname} = {val};")
                } else if t.starts_with("__sget:") {
                    let field = t.strip_prefix("__sget:").unwrap_or("");
                    let fname = field.rsplit('.').next().unwrap_or(field);
                    let name = self.name_of(id);
                    format!("{name} = {fname};")
                } else if t.starts_with("__sput:") {
                    let field = t.strip_prefix("__sput:").unwrap_or("");
                    let val = arg_texts.first().cloned().unwrap_or_default();
                    let fname = field.rsplit('.').next().unwrap_or(field);
                    format!("{fname} = {val};")
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

pub fn render_method_pseudocode(func: &SsaFunction) -> String {
    let mut ctx = RenderCtx::new(func);
    let mut lines = Vec::new();
    let mut visited = HashSet::new();
    let mut queue: Vec<BlockId> = vec![func.cfg.entry];

    while let Some(bid) = queue.pop() {
        if !visited.insert(bid) {
            continue;
        }
        if bid != func.cfg.entry {
            lines.push(format!("L{}:", bid.0));
        }
        let block = &func.cfg.blocks[bid.0 as usize];
        for &iid in &block.insts {
            if let Some(line) = ctx.render_inst(iid)
                && !line.starts_with("// phi()")
            {
                lines.push(format!("    {line}"));
            }
        }
        for &succ in &func.cfg.succs[bid.0 as usize] {
            if !visited.contains(&succ) {
                queue.push(succ);
            }
        }
    }

    if lines.is_empty() {
        lines.push("    <empty>".to_string());
    }
    let text = lines.join("\n");
    let text = fuse_new_init(&text);
    apply_copy_chain_collapse(&text)
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
                lines[i] = format!("    {var} = new {class_part}({args});");
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
    while changed && rounds < 8 {
        changed = false;
        rounds += 1;
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i].trim().to_string();
            let Some((var, src)) = line.strip_suffix(';').and_then(|l| l.split_once(" = ")) else {
                i += 1;
                continue;
            };
            if !src.chars().all(|c| c.is_alphanumeric() || c == '_') || src.parse::<i64>().is_ok() {
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
                lines[j] = replace_token(&lines[j], var, src);
                lines.remove(i);
                changed = true;
            } else {
                i += 1;
            }
        }
    }
    lines.join("\n")
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
    let func = lift_method_to_ssa(dex, code);
    let sig = dex.method_signature(method_idx);
    let text = render_method_pseudocode(&func);
    MethodPseudocode {
        signature: sig,
        pseudocode: text,
        registers: code.registers_size,
        insn_units: code.insns.len(),
    }
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
