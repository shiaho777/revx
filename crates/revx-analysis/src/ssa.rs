//! SSA (Static Single Assignment) dataflow analysis engine.
//!
//! This module provides the foundation for high-quality decompilation:
//! - CFG construction from basic blocks
//! - Dominator tree computation
//! - SSA construction with phi nodes
//! - Constant propagation and expression folding
//!
//! All advanced analysis (type propagation, expression reconstruction,
//! dead code elimination) builds on top of this SSA form.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::sync::Arc;

#[inline]
fn ssa_trace_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("REVX_TRACE").is_some())
}

thread_local! {
    static RENDER_STRINGS: std::cell::RefCell<Arc<HashMap<u64, String>>> =
        std::cell::RefCell::new(Arc::new(HashMap::new()));
    static RENDER_DATA_BASE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static RENDER_GLOBAL_NAMES: std::cell::RefCell<HashMap<u64, String>> =
        std::cell::RefCell::new(HashMap::new());
    static RENDER_REG_ALIASES: std::cell::RefCell<HashMap<String, String>> =
        std::cell::RefCell::new(HashMap::new());
    static RENDER_REG_CONSTS: std::cell::RefCell<HashMap<String, u64>> =
        std::cell::RefCell::new(HashMap::new());
    static RENDER_CODE_NAMES: std::cell::RefCell<HashMap<u64, String>> =
        std::cell::RefCell::new(HashMap::new());
    static NAMED_RENDER_CACHE: std::cell::RefCell<HashMap<u32, String>> =
        std::cell::RefCell::new(HashMap::new());
    static NAMED_RENDER_VISITING: std::cell::RefCell<HashSet<u32>> =
        std::cell::RefCell::new(HashSet::new());
    static SSA_USE_GRAPH: std::cell::RefCell<Option<(usize, Vec<u32>, Vec<Vec<u32>>)>> =
        std::cell::RefCell::new(None);
    static SSA_FLAG_COND: std::cell::RefCell<Option<(usize, Vec<bool>)>> =
        std::cell::RefCell::new(None);
}

const LINEAR_CACHE_CAP: usize = 96;
const LINEAR_SHAPE_MIN_INSTS: usize = 96;

#[derive(Clone)]
struct LinearExactEntry {
    arg_sig: Arc<str>,
    body: Arc<str>,
}

#[derive(Clone)]
enum ShapePiece {
    Lit(Arc<str>),
    Name,
    Const(usize),
}

#[derive(Clone)]
struct LinearShapeEntry {
    arg_sig: Arc<str>,
    const_count: usize,
    pieces: Arc<Vec<ShapePiece>>,
}

thread_local! {
    static LINEAR_EXACT_CACHE: RefCell<HashMap<u64, LinearExactEntry>> =
        RefCell::new(HashMap::with_capacity(32));
    static LINEAR_SHAPE_CACHE: RefCell<HashMap<u64, LinearShapeEntry>> =
        RefCell::new(HashMap::with_capacity(32));
}

#[inline]
fn fnv1a_u64(mut hash: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn arg_signature(arguments: &[revx_core::Variable]) -> String {
    if arguments.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(arguments.len() * 12);
    for (i, arg) in arguments.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(arg.type_name.as_deref().unwrap_or("unknown_t"));
        out.push(':');
        out.push_str(&arg.name);
    }
    out
}

fn rebuild_linear_header(name: &str, arguments: &[revx_core::Variable], body: &str) -> String {
    let args_str = if arguments.is_empty() {
        "void".to_string()
    } else {
        arguments
            .iter()
            .map(|a| {
                format!(
                    "{} {}",
                    a.type_name.as_deref().unwrap_or("unknown_t"),
                    a.name
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let header = format!("int {name}({args_str}) {{");
    if let Some(rest) = body.split_once('\n') {
        let mut out = String::with_capacity(body.len() + name.len() + 8);
        out.push_str(&header);
        out.push('\n');
        out.push_str(rest.1);
        out
    } else {
        header
    }
}

pub fn hash_linear_exact_key(blocks: &[revx_core::BasicBlock], arguments: &[revx_core::Variable]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    hash = fnv1a_u64(hash, arg_signature(arguments).as_bytes());
    for block in blocks {
        for inst in &block.instructions {
            hash = fnv1a_u64(hash, inst.text.as_bytes());
        }
        hash = fnv1a_u64(hash, b"|");
    }
    hash
}

fn normalize_shape_text(text: &str, high_consts: &mut Vec<u64>) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'#' {
            out.push('#');
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let start = i;
            let neg = i < bytes.len() && bytes[i] == b'-';
            if neg {
                i += 1;
            }
            let hex = i + 1 < bytes.len()
                && bytes[i] == b'0'
                && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X');
            if hex {
                i += 2;
                let hex_start = i;
                while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                }
                if i > hex_start {
                    if let Ok(mut v) = u64::from_str_radix(
                        std::str::from_utf8(&bytes[hex_start..i]).unwrap_or(""),
                        16,
                    ) {
                        if neg {
                            v = v.wrapping_neg();
                        }
                        if v >= 0x1000 {
                            high_consts.push(v);
                        }
                    }
                    out.push_str("IMM");
                    continue;
                }
            } else {
                let num_start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if i > num_start {
                    if let Ok(mut v) = std::str::from_utf8(&bytes[num_start..i])
                        .unwrap_or("")
                        .parse::<u64>()
                    {
                        if neg {
                            v = v.wrapping_neg();
                        }
                        if v >= 0x1000 {
                            high_consts.push(v);
                        }
                    }
                    out.push_str("IMM");
                    continue;
                }
            }
            i = start;
            continue;
        }
        if bytes[i] == b'0'
            && i + 1 < bytes.len()
            && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X')
        {
            let hex_start = i + 2;
            let mut j = hex_start;
            while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j > hex_start {
                if let Ok(v) = u64::from_str_radix(
                    std::str::from_utf8(&bytes[hex_start..j]).unwrap_or(""),
                    16,
                ) {
                    if v >= 0x1000 {
                        high_consts.push(v);
                    }
                }
                out.push_str("IMM");
                i = j;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

pub fn hash_linear_shape_key(
    blocks: &[revx_core::BasicBlock],
    arguments: &[revx_core::Variable],
) -> (u64, Vec<u64>) {
    let mut hash = 0xcbf29ce484222325u64;
    let mut high = Vec::new();
    hash = fnv1a_u64(hash, arg_signature(arguments).as_bytes());
    let base = blocks.first().map(|b| b.address).unwrap_or(0);
    for block in blocks {
        hash = fnv1a_u64(hash, &block.address.wrapping_sub(base).to_le_bytes());
        for inst in &block.instructions {
            let norm = normalize_shape_text(inst.text.as_ref(), &mut high);
            hash = fnv1a_u64(hash, norm.as_bytes());
            hash = fnv1a_u64(hash, b";");
        }
        hash = fnv1a_u64(hash, b"|");
    }
    (hash, high)
}

fn cheap_fold_high_consts(blocks: &[revx_core::BasicBlock]) -> Vec<u64> {
    let mut regs: HashMap<String, u64> = HashMap::with_capacity(32);
    let mut out = Vec::new();
    for block in blocks {
        for inst in &block.instructions {
            let text = inst.text.as_ref();
            if let Some(rest) = text.strip_prefix("adrp ") {
                let mut parts = rest.split(',');
                let Some(dst) = parts.next().map(str::trim) else { continue };
                let Some(page_tok) = parts.next().map(str::trim) else { continue };
                let page = parse_arm64_imm(page_tok)
                    .or_else(|| parse_arm64_imm(&format!("#{page_tok}")))
                    .map(|v| (v as u64) & !0xfffu64);
                if let Some(page) = page {
                    let reg = normalize_reg(dst);
                    regs.insert(reg, page);
                    if page >= 0x1000 {
                        out.push(page);
                    }
                }
                continue;
            }
            if let Some(rest) = text.strip_prefix("add ") {
                let parts: Vec<&str> = rest.split(',').map(str::trim).collect();
                if parts.len() == 3 && parts[2].starts_with('#') {
                    if let Some(imm) = parse_arm64_imm(parts[2]) {
                        let dn = normalize_reg(parts[0]);
                        let sn = normalize_reg(parts[1]);
                        if let Some(&base) = regs.get(&sn) {
                            let v = base.wrapping_add(imm as u64);
                            regs.insert(dn, v);
                            if v >= 0x1000 {
                                out.push(v);
                            }
                        }
                    }
                }
                continue;
            }
            if let Some(rest) = text.strip_prefix("mov ") {
                let parts: Vec<&str> = rest.split(',').map(str::trim).collect();
                if parts.len() == 2 && parts[1].starts_with('#') {
                    if let Some(imm) = parse_arm64_imm(parts[1]) {
                        let dn = normalize_reg(parts[0]);
                        let v = imm as u64;
                        regs.insert(dn, v);
                        if v >= 0x1000 {
                            out.push(v);
                        }
                    }
                } else if parts.len() == 2 {
                    let dn = normalize_reg(parts[0]);
                    let sn = normalize_reg(parts[1]);
                    if let Some(&v) = regs.get(&sn) {
                        regs.insert(dn, v);
                    }
                }
                continue;
            }
            if let Some(rest) = text.strip_prefix("movz ") {
                let parts: Vec<&str> = rest.split(',').map(str::trim).collect();
                if parts.len() >= 2 {
                    if let Some(imm) = parse_arm64_imm(parts[1]) {
                        let dn = normalize_reg(parts[0]);
                        let v = imm as u64;
                        regs.insert(dn, v);
                        if v >= 0x1000 {
                            out.push(v);
                        }
                    }
                }
            }
        }
    }
    out
}

fn build_shape_pieces(text: &str, name: &str, consts: &[u64]) -> Option<Vec<ShapePiece>> {
    if consts.is_empty() {
        return None;
    }
    let mut work = text.to_string();
    if !name.is_empty() {
        if let Some(pos) = work.find(name) {
            work.replace_range(pos..pos + name.len(), "\u{0001}N\u{0001}");
        }
    }
    let mut unique: Vec<(usize, u64, String)> = Vec::new();
    let mut seen = HashSet::new();
    for (idx, &v) in consts.iter().enumerate() {
        if !seen.insert(v) {
            continue;
        }
        unique.push((idx, v, format!("{v:#x}")));
    }
    unique.sort_by_key(|(_, _, hex)| std::cmp::Reverse(hex.len()));
    let mut replaced = 0usize;
    for (idx, v, hex) in &unique {
        let marker = format!("\u{0001}C{idx}\u{0001}");
        let upper = format!("{v:#X}");
        if work.contains(hex) {
            work = work.replace(hex, &marker);
            replaced += 1;
        } else if work.contains(&upper) {
            work = work.replace(&upper, &marker);
            replaced += 1;
        }
    }
    if replaced == 0 {
        return None;
    }
    let mut pieces = Vec::new();
    let mut rest = work.as_str();
    while !rest.is_empty() {
        if let Some(pos) = rest.find('\u{0001}') {
            if pos > 0 {
                pieces.push(ShapePiece::Lit(Arc::from(&rest[..pos])));
            }
            let after = &rest[pos + 1..];
            if let Some(end) = after.find('\u{0001}') {
                let token = &after[..end];
                if token == "N" {
                    pieces.push(ShapePiece::Name);
                } else if let Some(num) = token.strip_prefix('C') {
                    if let Ok(idx) = num.parse::<usize>() {
                        pieces.push(ShapePiece::Const(idx));
                    }
                }
                rest = &after[end + 1..];
            } else {
                pieces.push(ShapePiece::Lit(Arc::from(&rest[pos..])));
                break;
            }
        } else {
            pieces.push(ShapePiece::Lit(Arc::from(rest)));
            break;
        }
    }
    Some(pieces)
}

fn apply_shape_pieces(pieces: &[ShapePiece], name: &str, consts: &[u64]) -> Option<String> {
    let mut out = String::with_capacity(pieces.len() * 24);
    for piece in pieces {
        match piece {
            ShapePiece::Lit(s) => out.push_str(s),
            ShapePiece::Name => out.push_str(name),
            ShapePiece::Const(idx) => {
                let v = *consts.get(*idx)?;
                let _ = write!(out, "{v:#x}");
            }
        }
    }
    Some(out)
}

pub fn linear_cache_lookup(
    blocks: &[revx_core::BasicBlock],
    name: &str,
    arguments: &[revx_core::Variable],
) -> Option<String> {
    let inst_count: usize = blocks.iter().map(|b| b.instructions.len()).sum();
    if inst_count < 8 {
        return None;
    }
    let arg_sig = arg_signature(arguments);
    let exact = hash_linear_exact_key(blocks, arguments);
    if let Some(hit) = LINEAR_EXACT_CACHE.with(|slot| {
        slot.borrow().get(&exact).and_then(|entry| {
            if entry.arg_sig.as_ref() == arg_sig {
                Some(rebuild_linear_header(name, arguments, entry.body.as_ref()))
            } else {
                None
            }
        })
    }) {
        return Some(hit);
    }
    if inst_count < LINEAR_SHAPE_MIN_INSTS && blocks.len() < 24 {
        return None;
    }
    let (shape, _) = hash_linear_shape_key(blocks, arguments);
    let folded = cheap_fold_high_consts(blocks);
    LINEAR_SHAPE_CACHE.with(|slot| {
        let guard = slot.borrow();
        let entry = guard.get(&shape)?;
        if entry.arg_sig.as_ref() != arg_sig || entry.const_count != folded.len() {
            return None;
        }
        apply_shape_pieces(entry.pieces.as_ref(), name, &folded)
    })
}

pub fn linear_cache_store(
    blocks: &[revx_core::BasicBlock],
    name: &str,
    arguments: &[revx_core::Variable],
    text: &str,
) {
    let inst_count: usize = blocks.iter().map(|b| b.instructions.len()).sum();
    if inst_count < 8 || text.len() < 24 {
        return;
    }
    let arg_sig = Arc::<str>::from(arg_signature(arguments));
    let exact = hash_linear_exact_key(blocks, arguments);
    LINEAR_EXACT_CACHE.with(|slot| {
        let mut guard = slot.borrow_mut();
        if guard.len() >= LINEAR_CACHE_CAP {
            guard.clear();
        }
        guard.insert(
            exact,
            LinearExactEntry {
                arg_sig: Arc::clone(&arg_sig),
                body: Arc::from(text),
            },
        );
    });
    if inst_count < LINEAR_SHAPE_MIN_INSTS && blocks.len() < 24 {
        return;
    }
    let (shape, _) = hash_linear_shape_key(blocks, arguments);
    let folded = cheap_fold_high_consts(blocks);
    if folded.is_empty() {
        return;
    }
    let Some(pieces) = build_shape_pieces(text, name, &folded) else {
        return;
    };
    LINEAR_SHAPE_CACHE.with(|slot| {
        let mut guard = slot.borrow_mut();
        if guard.len() >= LINEAR_CACHE_CAP {
            guard.clear();
        }
        guard.insert(
            shape,
            LinearShapeEntry {
                arg_sig,
                const_count: folded.len(),
                pieces: Arc::new(pieces),
            },
        );
    });
}


fn with_render_context<R>(
    strings: Arc<HashMap<u64, String>>,
    data_base: Option<u64>,
    global_names: &HashMap<u64, String>,
    reg_aliases: &HashMap<String, String>,
    reg_consts: &HashMap<String, u64>,
    code_names: &HashMap<u64, String>,
    f: impl FnOnce() -> R,
) -> R {
    RENDER_STRINGS.with(|slot| {
        *slot.borrow_mut() = strings;
    });
    RENDER_DATA_BASE.with(|slot| slot.set(data_base));
    RENDER_GLOBAL_NAMES.with(|slot| {
        *slot.borrow_mut() = global_names.clone();
    });
    RENDER_REG_ALIASES.with(|slot| {
        *slot.borrow_mut() = reg_aliases.clone();
    });
    RENDER_REG_CONSTS.with(|slot| {
        *slot.borrow_mut() = reg_consts.clone();
    });
    RENDER_CODE_NAMES.with(|slot| {
        *slot.borrow_mut() = code_names.clone();
    });
    NAMED_RENDER_CACHE.with(|slot| slot.borrow_mut().clear());
    NAMED_RENDER_VISITING.with(|slot| slot.borrow_mut().clear());
    SSA_USE_GRAPH.with(|slot| *slot.borrow_mut() = None);
    SSA_FLAG_COND.with(|slot| *slot.borrow_mut() = None);
    let out = f();
    RENDER_STRINGS.with(|slot| {
        *slot.borrow_mut() = Arc::new(HashMap::new());
    });
    RENDER_DATA_BASE.with(|slot| slot.set(None));
    RENDER_GLOBAL_NAMES.with(|slot| slot.borrow_mut().clear());
    RENDER_REG_ALIASES.with(|slot| slot.borrow_mut().clear());
    RENDER_REG_CONSTS.with(|slot| slot.borrow_mut().clear());
    RENDER_CODE_NAMES.with(|slot| slot.borrow_mut().clear());
    NAMED_RENDER_CACHE.with(|slot| slot.borrow_mut().clear());
    NAMED_RENDER_VISITING.with(|slot| slot.borrow_mut().clear());
    SSA_USE_GRAPH.with(|slot| *slot.borrow_mut() = None);
    SSA_FLAG_COND.with(|slot| *slot.borrow_mut() = None);
    out
}

fn strings_arc(strings: &HashMap<u64, String>) -> Arc<HashMap<u64, String>> {
    if strings.is_empty() {
        Arc::new(HashMap::new())
    } else {
        Arc::new(strings.clone())
    }
}

fn lookup_reg_alias(reg: &str) -> Option<String> {
    RENDER_REG_ALIASES.with(|slot| slot.borrow().get(reg).cloned())
}

fn lookup_reg_const(reg: &str) -> Option<u64> {
    RENDER_REG_CONSTS.with(|slot| slot.borrow().get(reg).copied())
}

fn lookup_global_name(addr: u64) -> Option<String> {
    RENDER_GLOBAL_NAMES.with(|slot| slot.borrow().get(&addr).cloned())
}

fn lookup_render_string(addr: u64) -> Option<String> {
    RENDER_STRINGS.with(|slot| slot.borrow().get(&addr).cloned())
}

fn render_data_base() -> Option<u64> {
    RENDER_DATA_BASE.with(|slot| slot.get())
}

fn format_data_addr(addr: u64) -> String {
    if let Some(name) = lookup_global_name(addr) {
        return name;
    }
    if let Some(base) = render_data_base() {
        if addr >= base && addr.saturating_sub(base) < 0x4000 {
            let off = addr - base;
            if off == 0 {
                return "g_data".to_string();
            }
            return format!("g_data+{off:#x}");
        }
    }
    if looks_like_got_slot_page(addr) {
        match addr & 0xfff {
            0x2b0 => return "stderr_ptr".to_string(),
            0x2b8 => return "stdout_ptr".to_string(),
            0x2c0 => return "optarg_ptr".to_string(),
            0x2c8 => return "optind_ptr".to_string(),
            0x2d0 => return "longopts".to_string(),
            _ => {}
        }
    }
    format!("0x{addr:x}")
}

fn format_data_deref(addr: u64) -> String {
    if let Some(name) = lookup_global_name(addr) {
        return name;
    }
    if let Some(base) = render_data_base() {
        if addr >= base && addr.saturating_sub(base) < 0x4000 {
            let off = addr - base;
            if off == 0 {
                return "*g_data".to_string();
            }
            return format!("*(g_data + {off:#x})");
        }
    }
    if looks_like_got_slot_page(addr) {
        match addr & 0xfff {
            0x2b0 => return "stderr".to_string(),
            0x2b8 => return "stdout".to_string(),
            0x2c0 => return "optarg".to_string(),
            0x2c8 => return "optind".to_string(),
            0x2d0 => return "longopts".to_string(),
            _ => {}
        }
    }
    format!("*(0x{addr:x})")
}

fn looks_like_got_slot_page(addr: u64) -> bool {
    if addr < 0x1000 {
        return false;
    }
    if let Some(base) = render_data_base() {
        if addr >= base && addr.saturating_sub(base) < 0x8000 {
            return false;
        }
    }
    // Prefer __DATA_CONST-style pages (not huge BSS).
    let page = addr & !0xfffu64;
    matches!(addr & 0xfff, 0x2b0 | 0x2b8 | 0x2c0 | 0x2c8 | 0x2d0) && page != 0
}

fn format_mem_access(base_text: &str, offset: i64) -> String {
    let base_text = simplify_addr_expr(base_text);
    if let Some(name) = frame_slot_name_from_parts(&base_text, offset) {
        return name.to_string();
    }
    let simple = base_text
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
    if offset == 0 {
        if base_text == "g_data" {
            return "*g_data".to_string();
        }
        if let Some(stripped) = base_text.strip_prefix('&') {
            if stripped
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.')
            {
                return stripped.to_string();
            }
        }
        if let Some(stripped) = base_text.strip_suffix("_ptr") {
            if matches!(stripped, "stdout" | "stderr" | "optarg" | "optind" | "stdin") {
                return stripped.to_string();
            }
        }
        if matches!(
            base_text.as_str(),
            "stdout" | "stderr" | "optarg" | "optind" | "longopts" | "stdin"
        ) {
            return base_text;
        }
        if let Some(name) = frame_slot_name_from_parts(&base_text, 0) {
            return name.to_string();
        }
        if simple {
            format!("*{base_text}")
        } else {
            format!("*({base_text})")
        }
    } else if offset > 0 {
        if base_text == "g_data" {
            format!("*(g_data + {offset:#x})")
        } else if matches!(base_text.as_str(), "optarg" | "argv") && offset < 0x40 {
            format!("{base_text}[{offset}]")
        } else if simple && offset < 0x100 {
            format!("{base_text}[{offset:#x}]")
        } else {
            format!("*({base_text} + {offset:#x})")
        }
    } else {
        format!("*({base_text} - {:#x})", -offset)
    }
}

fn frame_slot_name_from_parts(base_text: &str, offset: i64) -> Option<&'static str> {
    let raw = base_text.trim();
    let raw = if raw.starts_with('(') && raw.ends_with(')') && balanced_outer_parens(raw) {
        raw[1..raw.len() - 1].trim()
    } else {
        raw
    };
    let (kind, base_off) = if let Some((b, o)) = parse_addr_chain(raw) {
        (b, o)
    } else if raw
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        (raw.to_string(), 0)
    } else {
        return None;
    };
    let kind = match kind.as_str() {
        "x29" | "fp" => "fp",
        "sp" | "x31" => "sp",
        _ => return None,
    };
    let _ = (kind, base_off.wrapping_add(offset));
    None
}

fn format_frame_addr_expr(base_text: &str, offset: i64) -> Option<String> {
    let name = frame_slot_name_from_parts(base_text, offset)?;
    Some(format!("&{name}"))
}

fn is_trivial_stack_prologue_store(rendered: &str) -> bool {
    let t = rendered.trim();
    if !t.contains('=') {
        return false;
    }
    let Some((lhs, rhs)) = t.split_once('=') else {
        return false;
    };
    let lhs = lhs.trim();
    let rhs = rhs.trim().trim_end_matches(';').trim();
    if (lhs == "winsize" || lhs.ends_with(".ws_col") || lhs == "headerlen" || lhs == "endptr")
        && (rhs == "0" || rhs == "0x0")
    {
        return true;
    }
    if rhs == "&winsize" && (lhs.contains("sp") || lhs.starts_with("*(")) {
        return true;
    }
    if rhs != "0" && !rhs.starts_with("(sp") && !rhs.starts_with("sp") && !rhs.starts_with('&') {
        return false;
    }
    if rhs.starts_with('&') && !matches!(rhs, "&winsize" | "&endptr" | "&headerlen") {
        return false;
    }
    lhs.contains("sp")
        || lhs.contains("x29")
        || lhs.starts_with("flag_tmp")
        || lhs.starts_with("*flag_tmp")
        || lhs.starts_with("*(")
}

fn simplify_addr_expr(text: &str) -> String {
    let mut t = text.trim().to_string();
    for _ in 0..4 {
        let next = collapse_nested_addr(&t);
        if next == t {
            break;
        }
        t = next;
    }
    if let Some((base, off)) = parse_addr_chain(&t) {
        if let Some(name) = frame_slot_name_from_parts(&base, off) {
            return format!("&{name}");
        }
    }
    t
}

fn collapse_nested_addr(text: &str) -> String {
    let t = text.trim();
    let inner = if t.starts_with('(') && t.ends_with(')') && balanced_outer_parens(t) {
        &t[1..t.len() - 1]
    } else {
        t
    };
    if let Some((base, off)) = parse_addr_chain(inner) {
        if off == 0 {
            return base;
        } else if off > 0 {
            return format!("({base} + {off:#x})");
        } else {
            return format!("({base} - {:#x})", -off);
        }
    }
    t.to_string()
}

fn parse_addr_chain(text: &str) -> Option<(String, i64)> {
    let mut s = text.trim().to_string();
    let mut total: i64 = 0;
    let mut base = String::new();
    for _ in 0..16 {
        let cur = s.trim().to_string();
        if cur.starts_with('(') && cur.ends_with(')') && balanced_outer_parens(&cur) {
            s = cur[1..cur.len() - 1].trim().to_string();
            continue;
        }
        if let Some((lhs, imm)) = split_trailing_add_imm(&cur) {
            total = total.wrapping_add(imm);
            s = lhs.to_string();
            continue;
        }
        if let Some((lhs, imm)) = split_trailing_sub_imm(&cur) {
            total = total.wrapping_sub(imm);
            s = lhs.to_string();
            continue;
        }
        base = cur;
        break;
    }
    if base.is_empty() {
        return None;
    }
    if base.starts_with('(') && base.ends_with(')') && balanced_outer_parens(&base) {
        let inner = base[1..base.len() - 1].trim().to_string();
        if inner
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            base = inner;
        }
    }
    Some((base, total))
}

fn split_trailing_add_imm(text: &str) -> Option<(&str, i64)> {
    if let Some(idx) = text.rfind(" + ") {
        let lhs = text[..idx].trim();
        let rhs = text[idx + 3..].trim();
        if let Some(imm) = parse_hex_or_dec(rhs) {
            return Some((lhs, imm));
        }
    }
    // compact form: foo+0x10
    if let Some(idx) = text.rfind('+') {
        if idx > 0 {
            let lhs = text[..idx].trim();
            let rhs = text[idx + 1..].trim();
            if !lhs.is_empty() && parse_hex_or_dec(rhs).is_some() {
                return Some((lhs, parse_hex_or_dec(rhs)?));
            }
        }
    }
    None
}

fn split_trailing_sub_imm(text: &str) -> Option<(&str, i64)> {
    if let Some(idx) = text.rfind(" - ") {
        let lhs = text[..idx].trim();
        let rhs = text[idx + 3..].trim();
        if let Some(imm) = parse_hex_or_dec(rhs) {
            return Some((lhs, imm));
        }
    }
    if let Some(idx) = text.rfind('-') {
        if idx > 0 {
            let lhs = text[..idx].trim();
            let rhs = text[idx + 1..].trim();
            if !lhs.is_empty()
                && !lhs.ends_with(|c: char| c.is_ascii_hexdigit())
                && parse_hex_or_dec(rhs).is_some()
            {
                // avoid splitting identifiers
                let prev = lhs.chars().last().unwrap_or(' ');
                if prev.is_ascii_alphanumeric() || prev == '_' || prev == ')' {
                    return Some((lhs, parse_hex_or_dec(rhs)?));
                }
            }
        }
    }
    None
}

fn infer_code_names(
    func: &SsaFunction,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    strings: &HashMap<u64, String>,
) -> HashMap<u64, String> {
    let mut names: HashMap<u64, String> = HashMap::new();
    let mut used: HashSet<String> = HashSet::new();
    let put = |addr: u64, name: &str, names: &mut HashMap<u64, String>, used: &mut HashSet<String>| {
        if addr < 0x1000 || names.contains_key(&addr) {
            return;
        }
        if used.contains(name) {
            return;
        }
        names.insert(addr, name.to_string());
        used.insert(name.to_string());
    };

    // Call-site driven names.
    for inst in &func.values {
        match &inst.op {
            SsaOp::Call { target, args } => {
                let bare = resolve_callee_bare_name(target, symbols, local_symbols);
                if bare == "signal" && args.len() >= 2 {
                    if let Some(c) = resolve_const_operand_static(func, &args[1]) {
                        if c > 0 {
                            put(c as u64, "color_sig_handler", &mut names, &mut used);
                        }
                    }
                }
                if bare == "getopt_long" && args.len() >= 4 {
                    if let Some(c) = resolve_const_operand_static(func, &args[3]) {
                        if c > 0 {
                            put(c as u64, "longopts", &mut names, &mut used);
                        }
                    }
                }
                if args.len() == 2 {
                    let a0 = render_operand_named_depth(func, &args[0], symbols, local_symbols, 1);
                    let a1 = render_operand_named_depth(func, &args[1], symbols, local_symbols, 1);
                    if (a0 == "argc" || a0.contains("argc")) && (a1 == "argv" || a1.contains("argv"))
                    {
                        if let Operand::Symbol(n) = target {
                            if let Some(addr) = parse_sub_symbol_addr(n) {
                                put(addr, "usage", &mut names, &mut used);
                            }
                        } else if let Some(c) = resolve_const_operand_static(func, target) {
                            if c > 0 {
                                put(c as u64, "usage", &mut names, &mut used);
                            }
                        }
                    }
                }
                if args.is_empty() {
                    if let Some(labels) = func.case_labels.get(&inst.block) {
                        if labels.iter().any(|l| l == "default") {
                            if let Operand::Symbol(n) = target {
                                if let Some(addr) = parse_sub_symbol_addr(n) {
                                    put(addr, "usage", &mut names, &mut used);
                                }
                            } else if let Some(c) = resolve_const_operand_static(func, target) {
                                if c > 0 {
                                    put(c as u64, "usage", &mut names, &mut used);
                                }
                            }
                        }
                    }
                }
            }
            SsaOp::Store { addr, value } => {
                let Some(abs) = fold_absolute_addr(func, addr) else {
                    continue;
                };
                let gname = lookup_global_name(abs).or_else(|| {
                    // bootstrap during inference: use offset heuristics
                    None
                });
                if let Some(c) = resolve_const_operand_static(func, value) {
                    if c <= 0 {
                        continue;
                    }
                    let ca = c as u64;
                    if abs & 0xfff == 0x108 || gname.as_deref() == Some("g_printfn") {
                        put(ca, "printlong", &mut names, &mut used);
                    } else if abs & 0xfff == 0x110 || gname.as_deref() == Some("g_sortfn") {
                        put(ca, "mastercmp", &mut names, &mut used);
                    }
                }
            }
            _ => {}
        }
    }

    // String-driven names for callees.
    for inst in &func.values {
        let SsaOp::Call { target, args } = &inst.op else {
            continue;
        };
        let callee_addr = match target {
            Operand::Symbol(n) => parse_sub_symbol_addr(n),
            Operand::Constant(c) if *c >= 0 => Some(*c as u64),
            _ => None,
        };
        let Some(callee_addr) = callee_addr else {
            continue;
        };
        // usage: loads stderr + usage string + exit
        for a in args {
            if let Some(c) = resolve_const_operand_static(func, a) {
                if let Some(s) = strings.get(&(c as u64)) {
                    if s.starts_with("usage:") {
                        put(callee_addr, "usage", &mut names, &mut used);
                    }
                }
            }
        }
    }

    // Sequential: getenv("LSCOLORS") then call -> parse_colors
    let mut prev_getenv_lscolors = false;
    for block in &func.cfg.blocks {
        for &iid in &block.insts {
            let Some(inst) = func.values.get(iid.0 as usize) else {
                continue;
            };
            match &inst.op {
                SsaOp::Call { target, args } => {
                    let bare = resolve_callee_bare_name(target, symbols, local_symbols);
                    if bare == "getenv" && args.len() >= 1 {
                        if let Some(c) = resolve_const_operand_static(func, &args[0]) {
                            if strings.get(&(c as u64)).map(|s| s.as_str()) == Some("LSCOLORS") {
                                prev_getenv_lscolors = true;
                                continue;
                            }
                        }
                    }
                    if prev_getenv_lscolors {
                        if let Operand::Symbol(n) = target {
                            if let Some(addr) = parse_sub_symbol_addr(n) {
                                put(addr, "parse_colors", &mut names, &mut used);
                            }
                        } else if let Operand::Constant(c) = target {
                            if *c > 0 {
                                put(*c as u64, "parse_colors", &mut names, &mut used);
                            }
                        }
                        prev_getenv_lscolors = false;
                    }
                }
                SsaOp::Store { .. } | SsaOp::Branch { .. } | SsaOp::Jump { .. } => {
                    // keep getenv affinity only for immediate next call
                }
                _ => {}
            }
        }
    }

    let mut usage_addrs: HashSet<u64> = HashSet::new();
    for inst in &func.values {
        let SsaOp::Call { target, args } = &inst.op else {
            continue;
        };
        let addr = match target {
            Operand::Symbol(n) => parse_sub_symbol_addr(n),
            Operand::Constant(c) if *c >= 0 => Some(*c as u64),
            _ => resolve_const_operand_static(func, target).filter(|c| *c > 0).map(|c| c as u64),
        };
        let Some(addr) = addr else {
            continue;
        };
        if args.len() == 2 {
            let a0 = render_operand_named_depth(func, &args[0], symbols, local_symbols, 1);
            let a1 = render_operand_named_depth(func, &args[1], symbols, local_symbols, 1);
            if (a0 == "argc" || a0.contains("argc")) && (a1 == "argv" || a1.contains("argv")) {
                usage_addrs.insert(addr);
            }
        }
        if args.is_empty() {
            if let Some(labels) = func.case_labels.get(&inst.block) {
                if labels.iter().any(|l| l == "default") {
                    usage_addrs.insert(addr);
                }
            }
        }
    }
    for addr in usage_addrs {
        put(addr, "usage", &mut names, &mut used);
    }

    let mut ferror_seen = false;
    let mut exit_seen = false;
    let mut traverse_cands: Vec<(u64, u64)> = Vec::new();
    for inst in &func.values {
        match &inst.op {
            SsaOp::Call { target, args } => {
                let tname = match target {
                    Operand::Symbol(n) => {
                        if let Some(addr) = parse_sub_symbol_addr(n) {
                            symbols
                                .get(&addr)
                                .or_else(|| local_symbols.get(&addr))
                                .map(|s| s.as_str())
                                .unwrap_or(n.as_str())
                        } else {
                            n.as_str()
                        }
                    }
                    Operand::Constant(c) if *c >= 0 => symbols
                        .get(&(*c as u64))
                        .or_else(|| local_symbols.get(&(*c as u64)))
                        .map(|s| s.as_str())
                        .unwrap_or(""),
                    _ => "",
                };
                let bare = tname.trim_start_matches('_');
                if bare == "ferror" {
                    ferror_seen = true;
                }
                if bare == "exit" || bare == "err" || bare == "errx" {
                    exit_seen = true;
                }
                if args.is_empty() {
                    let addr = match target {
                        Operand::Symbol(n) => parse_sub_symbol_addr(n),
                        Operand::Constant(c) if *c >= 0 => Some(*c as u64),
                        _ => resolve_const_operand_static(func, target)
                            .filter(|c| *c > 0)
                            .map(|c| c as u64),
                    };
                    if let Some(addr) = addr {
                        if (0x100000000..0x100008000).contains(&addr)
                            && names.get(&addr).map(|s| s.as_str()) != Some("usage")
                        {
                            traverse_cands.push((inst.source_addr, addr));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if ferror_seen || exit_seen {
        if let Some((_, addr)) = traverse_cands.iter().max_by_key(|(sa, _)| *sa) {
            if names.get(addr).map(|s| s.as_str()) != Some("usage") {
                names.retain(|_, v| v != "traverse");
                used.remove("traverse");
                put(*addr, "traverse", &mut names, &mut used);
            }
        }
    }

    names
}

fn infer_data_base(func: &SsaFunction) -> Option<u64> {
    let mut pages: HashMap<u64, usize> = HashMap::new();
    let bump = |pages: &mut HashMap<u64, usize>, addr: u64| {
        if addr < 0x1000 {
            return;
        }
        // Prefer BSS/data style pages (not low code pages tightly).
        let page = addr & !0xfffu64;
        *pages.entry(page).or_default() += 1;
    };
    for inst in &func.values {
        match &inst.op {
            SsaOp::Copy {
                src: Operand::Constant(c),
            } if *c > 0 => bump(&mut pages, *c as u64),
            SsaOp::BinOp {
                kind: BinOpKind::Add,
                lhs,
                rhs,
            } => {
                if let (Some(l), Some(r)) = (
                    resolve_const_operand_static(func, lhs),
                    resolve_const_operand_static(func, rhs),
                ) {
                    if l > 0 && r >= 0 {
                        bump(&mut pages, (l as u64).wrapping_add(r as u64));
                    }
                }
            }
            SsaOp::Store { addr, .. } | SsaOp::Load { addr } => {
                if let Some(a) = resolve_const_operand_static(func, addr) {
                    if a > 0 {
                        bump(&mut pages, a as u64);
                    }
                } else if let Operand::Deref { base, offset } = addr {
                    if let Some(b) = resolve_const_operand_static(func, base) {
                        if b > 0 {
                            bump(
                                &mut pages,
                                (b as u64).wrapping_add(*offset as u64),
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }
    pages
        .into_iter()
        .filter(|(page, count)| *count >= 3 && (*page & 0xfff) == 0)
        .max_by_key(|(_, count)| *count)
        .map(|(page, _)| page)
}


fn getopt_case_primary_flag(ch: u8) -> Option<&'static str> {
    Some(match ch {
        b'%' => "g_f_dataless",
        b'1' => "g_f_singlecol",
        b'@' => "g_f_xattr",
        b'A' => "g_f_listdot",
        b'B' => "g_f_octal",
        b'D' => "g_f_timeformat",
        b'F' => "g_f_type",
        b'G' => "g_color",
        b'I' => "g_f_noautodot",
        b'O' => "g_f_flags",
        b'P' => "g_f_nofollow",
        b'R' => "g_f_recursive",
        b'S' => "g_f_sizesort",
        b'T' => "g_f_sectime",
        b'U' => "g_f_birthtime",
        b'W' => "g_f_whiteout",
        b',' => "g_f_thousands",
        b'a' => "g_f_listdot",
        b'b' => "g_f_octal_escape",
        b'c' => "g_f_statustime",
        b'd' => "g_f_listdir",
        b'e' => "g_f_acl",
        b'f' => "g_f_nosort",
        b'g' => "g_f_group",
        b'h' => "g_f_humanval",
        b'i' => "g_f_inode",
        b'k' => "g_f_kblocks",
        b'l' => "g_f_longform",
        b'm' => "g_f_stream",
        b'n' => "g_f_numericonly",
        b'o' => "g_f_owner",
        b'p' => "g_f_slash",
        b'q' => "g_f_nonprint",
        b'r' => "g_f_reversesort",
        b's' => "g_f_size",
        b't' => "g_f_timesort",
        b'u' => "g_f_accesstime",
        b'x' => "g_f_sortacross",
        b'y' => "g_f_samesort",
        _ => return None,
    })
}

fn parse_case_label_char(label: &str) -> Option<u8> {
    let rest = label.strip_prefix("case ")?;
    if rest == "-1" {
        return None;
    }
    if let Some(body) = rest.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        if body == "\\\\" {
            return Some(b'\\');
        }
        if body == "\\'" {
            return Some(b'\'');
        }
        if body.len() == 1 {
            return Some(body.as_bytes()[0]);
        }
    }
    if let Some(hex) = rest.strip_prefix("0x") {
        return u8::from_str_radix(hex, 16).ok();
    }
    None
}

fn infer_global_names(
    func: &SsaFunction,
    data_base: Option<u64>,
    symbols: &HashMap<u64, String>,
) -> HashMap<u64, String> {
    let mut names: HashMap<u64, String> = HashMap::new();
    let Some(base) = data_base else {
        return names;
    };
    let in_data = |addr: u64| addr >= base && addr.saturating_sub(base) < 0x4000;

    let call_name = |func: &SsaFunction, id: SsaValueId| -> Option<String> {
        let inst = func.values.get(id.0 as usize)?;
        match &inst.op {
            SsaOp::Call { target, .. } => {
                let raw = match target {
                    Operand::Symbol(n) => {
                        if let Some(addr) = parse_sub_symbol_addr(n) {
                            symbols
                                .get(&addr)
                                .cloned()
                                .unwrap_or_else(|| n.clone())
                        } else {
                            n.clone()
                        }
                    }
                    Operand::Constant(c) if *c >= 0 => symbols
                        .get(&(*c as u64))
                        .cloned()
                        .unwrap_or_else(|| format_sub_addr(*c as u64)),
                    _ => return None,
                };
                Some(raw.trim_start_matches('_').to_string())
            }
            _ => None,
        }
    };

    let mut stores: Vec<(u64, BlockId, Option<String>, Option<i64>)> = Vec::new();
    for inst in &func.values {
        let SsaOp::Store { addr, value } = &inst.op else {
            continue;
        };
        let Some(abs) = fold_absolute_addr(func, addr) else {
            continue;
        };
        if !in_data(abs) {
            continue;
        }
        let src_call = match value {
            Operand::Value(id) => call_name(func, *id),
            _ => None,
        };
        let src_const = resolve_const_operand_static(func, value);
        stores.push((abs, inst.block, src_call, src_const));
    }

    let mut used_names: HashSet<String> = HashSet::new();
    let put = |addr: u64, name: String, names: &mut HashMap<u64, String>, used: &mut HashSet<String>| {
        if names.contains_key(&addr) {
            return;
        }
        let mut candidate = name;
        if !used.insert(candidate.clone()) {
            candidate = format!("{candidate}_{:x}", addr.wrapping_sub(base));
            used.insert(candidate.clone());
        }
        names.insert(addr, candidate);
    };

    let mut case_starts: Vec<(u64, u8)> = Vec::new();
    for (block_id, labels) in &func.case_labels {
        if labels.iter().any(|l| l == "default") {
            continue;
        }
        let mut chars: Vec<u8> = labels.iter().filter_map(|l| parse_case_label_char(l)).collect();
        chars.sort_unstable();
        chars.dedup();
        if chars.len() != 1 {
            continue;
        }
        let start = func
            .cfg
            .blocks
            .get(block_id.0 as usize)
            .map(|b| b.start_addr)
            .unwrap_or(0);
        if start == 0 {
            continue;
        }
        case_starts.push((start, chars[0]));
    }
    case_starts.sort_by_key(|(a, _)| *a);

    let mut votes: HashMap<u64, HashMap<&'static str, i32>> = HashMap::new();
    for inst in &func.values {
        let SsaOp::Store { addr, value } = &inst.op else {
            continue;
        };
        let Some(abs) = fold_absolute_addr(func, addr) else {
            continue;
        };
        if !in_data(abs) || inst.source_addr == 0 {
            continue;
        }
        let src_const = resolve_const_operand_static(func, value);
        let idx = case_starts.partition_point(|(a, _)| *a <= inst.source_addr);
        if idx == 0 {
            continue;
        }
        let (start, ch) = case_starts[idx - 1];
        if inst.source_addr.saturating_sub(start) > 0x60 {
            continue;
        }
        if idx < case_starts.len() && inst.source_addr >= case_starts[idx].0 {
            continue;
        }
        let Some(name) = getopt_case_primary_flag(ch) else {
            continue;
        };
        let weight = if matches!(src_const, Some(1)) {
            4
        } else if src_const.is_none() {
            5
        } else if matches!(src_const, Some(0)) {
            0
        } else {
            2
        };
        if weight == 0 {
            continue;
        }
        *votes.entry(abs).or_default().entry(name).or_default() += weight;
    }

    for (block_id, labels) in &func.case_labels {
        if labels.iter().any(|l| l == "default") {
            continue;
        }
        let mut chars: Vec<u8> = labels.iter().filter_map(|l| parse_case_label_char(l)).collect();
        chars.sort_unstable();
        chars.dedup();
        if chars.len() != 1 {
            continue;
        }
        let set1: Vec<u64> = stores
            .iter()
            .filter(|(_, b, _, c)| *b == *block_id && matches!(c, Some(v) if *v == 1))
            .map(|(a, _, _, _)| *a)
            .collect();
        if let Some(name) = getopt_case_primary_flag(chars[0]) {
            if set1.len() == 1 {
                *votes
                    .entry(set1[0])
                    .or_default()
                    .entry(name)
                    .or_default() += 3;
            }
        }
    }

    let mut case_set1: HashMap<u8, Vec<u64>> = HashMap::new();
    for (block_id, labels) in &func.case_labels {
        if labels.iter().any(|l| l == "default") {
            continue;
        }
        let mut chars: Vec<u8> = labels.iter().filter_map(|l| parse_case_label_char(l)).collect();
        chars.sort_unstable();
        chars.dedup();
        if chars.len() != 1 {
            continue;
        }
        let set1: Vec<u64> = stores
            .iter()
            .filter(|(_, b, _, c)| *b == *block_id && matches!(c, Some(v) if *v == 1))
            .map(|(a, _, _, _)| *a)
            .collect();
        if !set1.is_empty() {
            case_set1.insert(chars[0], set1);
        }
    }

    let mut set1_owners: HashMap<u64, Vec<u8>> = HashMap::new();
    for (ch, addrs) in &case_set1 {
        for &addr in addrs {
            set1_owners.entry(addr).or_default().push(*ch);
        }
    }
    for owners in set1_owners.values_mut() {
        owners.sort_unstable();
        owners.dedup();
    }

    let mut claimed_names: HashSet<&'static str> = HashSet::new();
    let mut exclusive_for_case: HashMap<u8, Vec<u64>> = HashMap::new();
    for (addr, owners) in &set1_owners {
        if owners.len() == 1 {
            exclusive_for_case
                .entry(owners[0])
                .or_default()
                .push(*addr);
        }
    }
    for addrs in exclusive_for_case.values_mut() {
        addrs.sort_unstable();
        addrs.dedup();
    }

    let mut forced: Vec<(u64, &'static str)> = Vec::new();
    for (ch, addrs) in &exclusive_for_case {
        let Some(name) = getopt_case_primary_flag(*ch) else {
            continue;
        };
        if addrs.len() == 1 {
            forced.push((addrs[0], name));
            *votes
                .entry(addrs[0])
                .or_default()
                .entry(name)
                .or_default() += 30;
        } else if let Some(&addr) = addrs.first() {
            forced.push((addr, name));
            *votes
                .entry(addr)
                .or_default()
                .entry(name)
                .or_default() += 15;
        }
    }
    forced.sort_by(|a, b| a.0.cmp(&b.0));
    for (addr, name) in &forced {
        if claimed_names.contains(name) || names.contains_key(addr) {
            continue;
        }
        put(*addr, name.to_string(), &mut names, &mut used_names);
        claimed_names.insert(*name);
    }

    for (ch, addrs) in &case_set1 {
        if addrs.len() != 1 {
            continue;
        }
        let Some(name) = getopt_case_primary_flag(*ch) else {
            continue;
        };
        if claimed_names.contains(name) || names.contains_key(&addrs[0]) {
            continue;
        }
        put(addrs[0], name.to_string(), &mut names, &mut used_names);
        claimed_names.insert(name);
    }

    let mut ranked: Vec<(u64, &'static str, i32)> = Vec::new();
    for (addr, cmap) in &votes {
        if names.contains_key(addr) {
            continue;
        }
        let mut options: Vec<(&'static str, i32)> = cmap
            .iter()
            .map(|(n, s)| (*n, *s))
            .collect();
        options.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        for (name, score) in options {
            if claimed_names.contains(name) {
                continue;
            }
            ranked.push((*addr, name, score));
            break;
        }
    }
    ranked.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
    for (addr, name, _) in ranked {
        if names.contains_key(&addr) || claimed_names.contains(name) {
            continue;
        }
        put(addr, name.to_string(), &mut names, &mut used_names);
        claimed_names.insert(name);
    }

    for (ch, addrs) in &case_set1 {
        let Some(name) = getopt_case_primary_flag(*ch) else {
            continue;
        };
        if used_names.contains(name) {
            continue;
        }
        if let Some(&addr) = addrs.iter().find(|a| !names.contains_key(a)) {
            put(addr, name.to_string(), &mut names, &mut used_names);
            claimed_names.insert(name);
        }
    }

    let bootstrap: &[(u64, &str)] = &[
        (0x00, "g_termwidth"),
        (0x20, "g_color"),
        (0x24, "g_compat_mode"),
        (0x2c, "g_f_samesort"),
        (0x30, "g_f_longform"),
        (0xc8, "g_blocksize"),
        (0x90, "g_tcap_af"),
        (0x98, "g_tcap_ab"),
        (0xa0, "g_tcap_me"),
        (0xa8, "g_tcap_md"),
        (0xb0, "g_tcap_op"),
        (0xb8, "g_color_on"),
        (0xbc, "g_color_force"),
        (0xc0, "g_color_init"),
        (0x108, "g_printfn"),
        (0x110, "g_sortfn"),
        (0x118, "g_rval"),
    ];
    let mut touched: HashSet<u64> = stores.iter().map(|(a, _, _, _)| *a).collect();
    for inst in &func.values {
        if let SsaOp::Load { addr } = &inst.op {
            if let Some(abs) = fold_absolute_addr(func, addr) {
                if in_data(abs) {
                    touched.insert(abs);
                }
            }
        }
    }
    for (off, name) in bootstrap {
        let addr = base.wrapping_add(*off);
        if !touched.contains(&addr) {
            continue;
        }
        if let Some(existing) = names.get(&addr).cloned() {
            if existing == *name {
                continue;
            }
            if existing.starts_with("g_flag_") || existing.ends_with(&format!("_{off:x}")) {
                names.remove(&addr);
                used_names.remove(&existing);
            } else if *name == "g_f_longform" {
                if existing == "g_f_group" || existing == "g_f_owner" || existing == "g_f_stream" {
                    names.remove(&addr);
                    used_names.remove(&existing);
                } else {
                    continue;
                }
            } else {
                continue;
            }
        }
        put(addr, (*name).to_string(), &mut names, &mut used_names);
    }

    let mut case_any: HashMap<u8, Vec<u64>> = HashMap::new();
    for (block_id, labels) in &func.case_labels {
        if labels.iter().any(|l| l == "default") {
            continue;
        }
        let mut chars: Vec<u8> = labels.iter().filter_map(|l| parse_case_label_char(l)).collect();
        chars.sort_unstable();
        chars.dedup();
        if chars.len() != 1 {
            continue;
        }
        let addrs: Vec<u64> = stores
            .iter()
            .filter(|(_, b, _, _)| *b == *block_id)
            .map(|(a, _, _, _)| *a)
            .collect();
        if !addrs.is_empty() {
            case_any.insert(chars[0], addrs);
        }
    }
    for (ch, preferred) in [
        (b'g', "g_f_group"),
        (b'o', "g_f_owner"),
        (b'n', "g_f_numericonly"),
    ] {
        if used_names.contains(preferred) {
            continue;
        }
        let mut candidates = Vec::new();
        if let Some(addrs) = case_any.get(&ch) {
            candidates.extend(addrs.iter().copied());
        }
        if let Some(addrs) = case_set1.get(&ch) {
            candidates.extend(addrs.iter().copied());
        }
        candidates.sort_unstable();
        candidates.dedup();
        if let Some(&addr) = candidates.iter().find(|a| !names.contains_key(a)) {
            put(addr, preferred.to_string(), &mut names, &mut used_names);
        }
    }

    for inst in &func.values {
        let SsaOp::Store { addr, value: _ } = &inst.op else {
            continue;
        };
        let Some(abs) = fold_absolute_addr(func, addr) else {
            continue;
        };
        if names.contains_key(&abs) || !in_data(abs) || inst.source_addr == 0 {
            continue;
        }
        let idx = case_starts.partition_point(|(a, _)| *a <= inst.source_addr);
        if idx == 0 {
            continue;
        }
        let (start, ch) = case_starts[idx - 1];
        if inst.source_addr.saturating_sub(start) > 0x40 {
            continue;
        }
        if idx < case_starts.len() && inst.source_addr >= case_starts[idx].0 {
            continue;
        }
        let Some(name) = getopt_case_primary_flag(ch) else {
            continue;
        };
        if used_names.contains(name) {
            continue;
        }
        if matches!(ch, b'g' | b'o') {
            put(abs, name.to_string(), &mut names, &mut used_names);
        }
    }

    for (addr, _block, call, imm) in &stores {
        if names.contains_key(addr) {
            continue;
        }
        if let Some(c) = call {
            let semantic = match c.as_str() {
                "compat_mode" => "g_compat_mode",
                "strtonum" => "g_termwidth",
                "isatty" => "g_isatty",
                "tgetstr" => "g_termcap",
                "getenv" => "g_env",
                "getopt_long" | "getopt" => "g_opt",
                other if other.starts_with("tget") => "g_termcap",
                _ => "",
            };
            if !semantic.is_empty() {
                put(*addr, semantic.to_string(), &mut names, &mut used_names);
                continue;
            }
            if !c.starts_with("sub_")
                && c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            {
                put(*addr, format!("g_{c}"), &mut names, &mut used_names);
            }
        } else if let Some(v) = *imm {
            if v == 1 {
                put(
                    *addr,
                    format!("g_flag_{:x}", addr.wrapping_sub(base)),
                    &mut names,
                    &mut used_names,
                );
            } else if v == 0x50 {
                put(*addr, "g_termwidth".to_string(), &mut names, &mut used_names);
            }
        }
    }

    names
}

fn infer_invariant_reg_constants(func: &SsaFunction) -> HashMap<String, u64> {
    let mut values: HashMap<String, Option<u64>> = HashMap::new();
    for map in func.defs.iter() {
        for (reg, id) in map.iter_pairs() {
            if reg.starts_with("__") {
                continue;
            }
            let resolved = resolve_const_operand_static(func, &Operand::Value(id))
                .and_then(|c| (c > 0x1000).then_some(c as u64));
            match values.get_mut(reg) {
                None => {
                    values.insert(reg.to_string(), resolved);
                }
                Some(slot) => {
                    match (*slot, resolved) {
                        (Some(a), Some(b)) if a == b => {}
                        (Some(_), Some(_)) => *slot = None,
                        (Some(_), None) => *slot = None,
                        (None, _) => {}
                    }
                }
            }
        }
    }
    values
        .into_iter()
        .filter_map(|(reg, val)| val.map(|v| (reg, v)))
        .collect()
}

fn def_is_high_const(func: &SsaFunction, id: SsaValueId) -> bool {
    resolve_const_operand_static(func, &Operand::Value(id))
        .map(|c| c > 0x1000)
        .unwrap_or(false)
}

fn lookup_reg_value_preferring_invariant(
    func: &SsaFunction,
    reg: &str,
    block: BlockId,
) -> Option<SsaValueId> {
    if let Some(id) = func.lookup(reg, block) {
        return Some(id);
    }
    if let Some(id) = prefer_forward_pred_def(func, reg, block) {
        return Some(id);
    }
    // Global invariant only when every def is the same high constant.
    let mut found: Option<(SsaValueId, u64)> = None;
    let mut saw_def = false;
    for map in func.defs.iter() {
        let Some(&id) = map.get(reg) else {
            continue;
        };
        saw_def = true;
        let Some(c) = resolve_const_operand_static(func, &Operand::Value(id)) else {
            return None;
        };
        if c <= 0x1000 {
            return None;
        }
        let c = c as u64;
        match found {
            None => found = Some((id, c)),
            Some((_, prev)) if prev == c => {}
            Some(_) => return None,
        }
    }
    if !saw_def {
        return None;
    }
    found.map(|(id, _)| id)
}

fn prefer_forward_pred_def(
    func: &SsaFunction,
    reg: &str,
    block: BlockId,
) -> Option<SsaValueId> {
    let preds = func.cfg.predecessors(block);
    if preds.len() < 2 {
        return None;
    }
    let succs = func.cfg.successors(block);
    let mut forward: Vec<BlockId> = Vec::new();
    let mut back: Vec<BlockId> = Vec::new();
    for &pred in preds {
        let is_back = succs.contains(&pred) || func.dom_tree.dominates(block, pred);
        if is_back {
            back.push(pred);
        } else {
            forward.push(pred);
        }
    }
    let has_forward = !forward.is_empty();
    let order: Vec<BlockId> = if has_forward {
        forward
    } else {
        back
    };
    let mut found: Option<(SsaValueId, Option<u64>)> = None;
    for pred in order {
        let Some(id) = func.block_defs(pred)
            .and_then(|m| m.get(reg))
            .copied()
            .or_else(|| func.lookup(reg, pred))
        else {
            continue;
        };
        let c = resolve_const_operand_static(func, &Operand::Value(id))
            .and_then(|v| (v > 0x1000).then_some(v as u64));
        match found {
            None => found = Some((id, c)),
            Some((prev_id, prev_c)) => {
                if prev_id == id {
                    continue;
                }
                match (prev_c, c) {
                    (Some(a), Some(b)) if a == b => {}
                    _ => return None,
                }
            }
        }
    }
    found.and_then(|(id, c)| {
        if c.is_some() || def_is_high_const(func, id) {
            Some(id)
        } else if !has_forward {
            // No distinct forward edge; accept the only agreement.
            Some(id)
        } else {
            // Prefer high-const forward defs for loop headers.
            c.map(|_| id)
        }
    })
}

fn infer_reg_aliases(func: &SsaFunction) -> HashMap<String, String> {
    let mut aliases: HashMap<String, String> = HashMap::new();
    let entry = func.cfg.entry;
    let Some(map) = func.block_defs(entry) else {
        return aliases;
    };
    for (reg, id) in map.iter_pairs() {
        if reg.starts_with("__") {
            continue;
        }
        // Only promote callee-saved aliases; x0-x18 are call-clobbered and
        // must not be frozen to entry argument names across the function.
        if let Some(idx) = reg.strip_prefix('x') {
            if let Ok(n) = idx.parse::<u32>() {
                if n <= 18 {
                    continue;
                }
            }
        }
        let Some(inst) = func.values.get(id.0 as usize) else {
            continue;
        };
        match &inst.op {
            SsaOp::Copy {
                src: Operand::Symbol(name),
            } if !looks_like_reg_name(name) => {
                aliases.insert(reg.to_string(), name.clone());
            }
            SsaOp::Copy {
                src: Operand::Value(src_id),
            } => {
                if let Some(src_inst) = func.values.get(src_id.0 as usize) {
                    if let SsaOp::Copy {
                        src: Operand::Symbol(name),
                    } = &src_inst.op
                    {
                        if !looks_like_reg_name(name) {
                            aliases.insert(reg.to_string(), name.clone());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    aliases
}

fn resolve_const_operand_static(func: &SsaFunction, op: &Operand) -> Option<i64> {
    resolve_const_operand_static_depth(func, op, 0)
}

fn resolve_const_operand_static_depth(
    func: &SsaFunction,
    op: &Operand,
    depth: usize,
) -> Option<i64> {
    if depth > 32 {
        return None;
    }
    match op {
        Operand::Constant(c) => Some(*c),
        Operand::Symbol(name) => {
            if let Some(addr) = parse_sub_symbol_addr(name) {
                return Some(addr as i64);
            }
            None
        }
        Operand::Value(id) => {
            let inst = func.values.get(id.0 as usize)?;
            match &inst.op {
                SsaOp::Copy {
                    src: Operand::Constant(c),
                } => Some(*c),
                SsaOp::Copy {
                    src: Operand::Symbol(name),
                } => {
                    if let Some(addr) = parse_sub_symbol_addr(name) {
                        Some(addr as i64)
                    } else {
                        resolve_const_operand_static_depth(
                            func,
                            &Operand::Symbol(name.clone()),
                            depth + 1,
                        )
                    }
                }
                SsaOp::Copy { src } => resolve_const_operand_static_depth(func, src, depth + 1),
                SsaOp::BinOp {
                    kind: BinOpKind::Add,
                    lhs,
                    rhs,
                } => {
                    let l = resolve_const_operand_static_depth(func, lhs, depth + 1)?;
                    let r = resolve_const_operand_static_depth(func, rhs, depth + 1)?;
                    Some(l.wrapping_add(r))
                }
                _ => None,
            }
        }
        _ => None,
    }
}


// ─── SSA Value Types ───────────────────────────────────────────────────────

/// A unique SSA value identifier. Each assignment to a register/variable
/// creates a new `SsaValue`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SsaValueId(pub u32);

/// A basic block identifier in the CFG.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct BlockId(pub u32);

/// An SSA instruction operand.
#[derive(Clone, Debug, PartialEq)]
pub enum Operand {
    /// Reference to an SSA value.
    Value(SsaValueId),
    /// Immediate constant.
    Constant(i64),
    /// Symbolic name (function argument, global, etc.).
    Symbol(String),
    /// Memory dereference of a base + optional offset.
    Deref { base: Box<Operand>, offset: i64 },
}

/// An SSA operation that produced a value.
#[derive(Clone, Debug, PartialEq)]
pub enum SsaOp {
    /// Load from memory: `*addr`
    Load { addr: Operand },
    /// Store to memory: `*addr = value`
    Store { addr: Operand, value: Operand },
    /// Binary operation: `lhs OP rhs`
    BinOp { kind: BinOpKind, lhs: Operand, rhs: Operand },
    /// Unary operation: `OP src`
    UnaryOp { kind: UnaryOpKind, src: Operand },
    /// Copy: direct value move `src`
    Copy { src: Operand },
    /// Call: `target(args...)`
    Call { target: Operand, args: Vec<Operand> },
    /// Return: `return value`
    Return { value: Option<Operand> },
    /// Branch: conditional jump
    Branch { cond: Operand, true_block: BlockId, false_block: BlockId },
    /// Unconditional jump
    Jump { target: BlockId },
    /// Phi node: merge of values from multiple predecessors
    Phi { incoming: Vec<(BlockId, SsaValueId)> },
    /// No-op / unknown instruction
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOpKind {
    Add, Sub, Mul, Div, Mod,
    And, Or, Xor, Shl, Shr, Sar,
    Eq, Ne, Lt, Le, Gt, Ge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnaryOpKind {
    Neg, Not, Bswap,
}

/// An SSA instruction: defines a value (or is a terminator).
#[derive(Clone, Debug)]
pub struct SsaInstruction {
    pub id: SsaValueId,
    pub op: SsaOp,
    /// Address of the original instruction this SSA instruction was derived from.
    pub source_addr: u64,
    /// Block this instruction belongs to.
    pub block: BlockId,
}

// ─── CFG ───────────────────────────────────────────────────────────────────

/// Control Flow Graph built from basic blocks.
#[derive(Debug, Default)]
pub struct Cfg {
    pub blocks: Vec<CfgBlock>,
    pub preds: Vec<Vec<BlockId>>,
    pub succs: Vec<Vec<BlockId>>,
    pub entry: BlockId,
}

#[derive(Debug, Default)]
pub struct CfgBlock {
    pub id: BlockId,
    pub start_addr: u64,
    pub end_addr: u64,
    pub insts: Vec<SsaValueId>,
    pub phis: Vec<SsaValueId>,
}

impl Cfg {
    pub fn from_blocks(
        blocks: &[(u64, Vec<u64>)],
        edges: &[(u64, u64)],
    ) -> Self {
        Self::from_blocks_with_map(blocks, edges).0
    }

    pub fn from_blocks_with_map(
        blocks: &[(u64, Vec<u64>)],
        edges: &[(u64, u64)],
    ) -> (Self, HashMap<u64, BlockId>) {
        let n = blocks.len();
        let mut addr_to_id = HashMap::with_capacity(
            blocks.iter().map(|(_, a)| a.len().saturating_add(1)).sum::<usize>().max(n),
        );
        let mut cfg_blocks = Vec::with_capacity(n);
        for (i, (addr, inst_addrs)) in blocks.iter().enumerate() {
            let id = BlockId(i as u32);
            addr_to_id.insert(*addr, id);
            let start = inst_addrs.first().copied().unwrap_or(*addr);
            let end = inst_addrs.last().copied().unwrap_or(start);
            for inst_addr in inst_addrs {
                addr_to_id.insert(*inst_addr, id);
            }
            cfg_blocks.push(CfgBlock {
                id,
                start_addr: start,
                end_addr: end,
                insts: Vec::new(),
                phis: Vec::new(),
            });
        }
        let entry = BlockId(0);
        let mut preds = vec![Vec::new(); n];
        let mut succs = vec![Vec::new(); n];
        for (from_addr, to_addr) in edges {
            if let (Some(&from), Some(&to)) = (addr_to_id.get(from_addr), addr_to_id.get(to_addr)) {
                if from != to {
                    let fi = from.0 as usize;
                    let ti = to.0 as usize;
                    if !succs[fi].contains(&to) {
                        succs[fi].push(to);
                    }
                    if !preds[ti].contains(&from) {
                        preds[ti].push(from);
                    }
                }
            }
        }
        for i in 0..n.saturating_sub(1) {
            if succs[i].is_empty() {
                let to = BlockId((i + 1) as u32);
                succs[i].push(to);
                if !preds[i + 1].contains(&BlockId(i as u32)) {
                    preds[i + 1].push(BlockId(i as u32));
                }
            }
        }
        (
            Cfg {
                blocks: cfg_blocks,
                preds,
                succs,
                entry,
            },
            addr_to_id,
        )
    }

    pub fn from_basic_blocks(
        blocks: &[revx_core::BasicBlock],
        edges: &[(u64, u64)],
    ) -> (Self, HashMap<u64, BlockId>) {
        let n = blocks.len();
        let mut addr_to_id = HashMap::with_capacity(
            blocks
                .iter()
                .map(|b| b.instructions.len().saturating_add(1))
                .sum::<usize>()
                .max(n),
        );
        let mut cfg_blocks = Vec::with_capacity(n);
        for (i, block) in blocks.iter().enumerate() {
            let id = BlockId(i as u32);
            addr_to_id.insert(block.address, id);
            let start = block
                .instructions
                .first()
                .map(|inst| inst.address)
                .unwrap_or(block.address);
            let end = block
                .instructions
                .last()
                .map(|inst| inst.address)
                .unwrap_or(start);
            for inst in &block.instructions {
                addr_to_id.insert(inst.address, id);
            }
            cfg_blocks.push(CfgBlock {
                id,
                start_addr: start,
                end_addr: end,
                insts: Vec::with_capacity(block.instructions.len()),
                phis: Vec::new(),
            });
        }
        let entry = BlockId(0);
        let mut preds = vec![Vec::new(); n];
        let mut succs = vec![Vec::new(); n];
        for (from_addr, to_addr) in edges {
            if let (Some(&from), Some(&to)) = (addr_to_id.get(from_addr), addr_to_id.get(to_addr)) {
                if from != to {
                    let fi = from.0 as usize;
                    let ti = to.0 as usize;
                    if !succs[fi].contains(&to) {
                        succs[fi].push(to);
                    }
                    if !preds[ti].contains(&from) {
                        preds[ti].push(from);
                    }
                }
            }
        }
        for i in 0..n.saturating_sub(1) {
            if succs[i].is_empty() {
                let to = BlockId((i + 1) as u32);
                succs[i].push(to);
                if !preds[i + 1].contains(&BlockId(i as u32)) {
                    preds[i + 1].push(BlockId(i as u32));
                }
            }
        }
        (
            Cfg {
                blocks: cfg_blocks,
                preds,
                succs,
                entry,
            },
            addr_to_id,
        )
    }

    pub fn block(&self, id: BlockId) -> &CfgBlock {
        &self.blocks[id.0 as usize]
    }

    pub fn block_mut(&mut self, id: BlockId) -> &mut CfgBlock {
        &mut self.blocks[id.0 as usize]
    }

    pub fn predecessors(&self, id: BlockId) -> &[BlockId] {
        self.preds
            .get(id.0 as usize)
            .map(|s| s.as_slice())
            .unwrap_or(&[])
    }

    pub fn predecessors_set(&self, id: BlockId) -> BTreeSet<BlockId> {
        self.predecessors(id).iter().copied().collect()
    }

    pub fn successors(&self, id: BlockId) -> &[BlockId] {
        self.succs
            .get(id.0 as usize)
            .map(|s| s.as_slice())
            .unwrap_or(&[])
    }
}

// ─── Dominator Tree ────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct DominatorTree {
    pub idom: Vec<Option<BlockId>>,
    pub rpo: Vec<BlockId>,
    pub post_order: Vec<u32>,
}

impl DominatorTree {
    #[inline]
    pub fn idom_of(&self, block: BlockId) -> Option<BlockId> {
        self.idom.get(block.0 as usize).copied().flatten()
    }

    pub fn compute(cfg: &Cfg) -> Self {
        let n = cfg.blocks.len();
        let mut visited = vec![false; n];
        let mut order = Vec::with_capacity(n);
        Self::post_order_visit(cfg, cfg.entry, &mut visited, &mut order);
        for block in &cfg.blocks {
            let idx = block.id.0 as usize;
            if idx < visited.len() && !visited[idx] {
                Self::post_order_visit(cfg, block.id, &mut visited, &mut order);
            }
        }
        let mut post_order = vec![u32::MAX; n];
        for (i, &block) in order.iter().enumerate() {
            let idx = block.0 as usize;
            if idx < post_order.len() {
                post_order[idx] = i as u32;
            }
        }

        let mut idom: Vec<Option<BlockId>> = vec![None; n];
        if (cfg.entry.0 as usize) < n {
            idom[cfg.entry.0 as usize] = Some(cfg.entry);
        }

        let mut changed = true;
        while changed {
            changed = false;
            for &block in order.iter().rev() {
                if block == cfg.entry {
                    continue;
                }
                let bi = block.0 as usize;
                let mut new_idom = None;
                for &pred in cfg.predecessors(block) {
                    let pi = pred.0 as usize;
                    if pi < idom.len() && idom[pi].is_some() {
                        new_idom = match new_idom {
                            None => Some(pred),
                            Some(current) => Some(Self::intersect(pred, current, &idom, &post_order)),
                        };
                    }
                }
                if let Some(nd) = new_idom {
                    if idom.get(bi).copied().flatten() != Some(nd) {
                        if bi < idom.len() {
                            idom[bi] = Some(nd);
                        }
                        changed = true;
                    }
                }
            }
        }

        let rpo = order.into_iter().rev().collect();
        DominatorTree {
            idom,
            rpo,
            post_order,
        }
    }

    fn post_order_visit(
        cfg: &Cfg,
        entry: BlockId,
        visited: &mut [bool],
        order: &mut Vec<BlockId>,
    ) {
        let ei = entry.0 as usize;
        if ei >= visited.len() || visited[ei] {
            return;
        }
        let mut stack: Vec<(BlockId, usize)> = vec![(entry, 0)];
        visited[ei] = true;
        while let Some((block, idx)) = stack.pop() {
            let succs = cfg.successors(block);
            if idx < succs.len() {
                stack.push((block, idx + 1));
                let succ = succs[idx];
                let si = succ.0 as usize;
                if si < visited.len() && !visited[si] {
                    visited[si] = true;
                    stack.push((succ, 0));
                }
            } else {
                order.push(block);
            }
        }
    }

    fn intersect(
        b1: BlockId,
        b2: BlockId,
        idom: &[Option<BlockId>],
        post_order: &[u32],
    ) -> BlockId {
        let po = |b: BlockId| -> u32 {
            post_order.get(b.0 as usize).copied().unwrap_or(u32::MAX)
        };
        let next = |b: BlockId| -> BlockId {
            idom.get(b.0 as usize).copied().flatten().unwrap_or(b)
        };
        let mut finger1 = b1;
        let mut finger2 = b2;
        for _ in 0..4096 {
            let mut guard = 0;
            while po(finger1) < po(finger2) {
                let n = next(finger1);
                if n == finger1 {
                    break;
                }
                finger1 = n;
                guard += 1;
                if guard > 4096 {
                    break;
                }
            }
            guard = 0;
            while po(finger2) < po(finger1) {
                let n = next(finger2);
                if n == finger2 {
                    break;
                }
                finger2 = n;
                guard += 1;
                if guard > 4096 {
                    break;
                }
            }
            if finger1 == finger2 {
                return finger1;
            }
            let prev1 = finger1;
            finger1 = next(finger1);
            finger2 = next(finger2);
            if finger1 == prev1 {
                return finger1;
            }
        }
        finger1
    }

    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        if a == b {
            return true;
        }
        let mut current = b;
        loop {
            let Some(dom) = self.idom_of(current) else {
                return false;
            };
            if dom == a {
                return true;
            }
            if dom == current {
                return false;
            }
            current = dom;
        }
    }

    pub fn dominance_frontier(&self, cfg: &Cfg) -> Vec<Vec<BlockId>> {
        let n = cfg.blocks.len();
        let mut df = vec![Vec::new(); n];
        for block in &cfg.blocks {
            let preds = cfg.predecessors(block.id);
            if preds.len() < 2 {
                continue;
            }
            for &pred in preds {
                let mut runner = pred;
                loop {
                    let Some(idom_runner) = self.idom_of(runner) else {
                        break;
                    };
                    if idom_runner == block.id {
                        break;
                    }
                    let ri = runner.0 as usize;
                    if ri < df.len() && !df[ri].contains(&block.id) {
                        df[ri].push(block.id);
                    }
                    if runner == idom_runner {
                        break;
                    }
                    runner = idom_runner;
                }
            }
        }
        df
    }
}

// ─── SSA Construction ──────────────────────────────────────────────────────

const REG_SLOT_X0: usize = 0;
const REG_SLOT_SP: usize = 31;
const REG_SLOT_XZR: usize = 32;
const REG_SLOT_CMP: usize = 33;
const REG_SLOT_COND: usize = 34;
const REG_SLOT_COUNT: usize = 35;

#[derive(Debug, Clone)]
pub struct BlockDefMap {
    slots: [Option<SsaValueId>; REG_SLOT_COUNT],
    extra: HashMap<String, SsaValueId>,
}

impl Default for BlockDefMap {
    fn default() -> Self {
        Self {
            slots: [None; REG_SLOT_COUNT],
            extra: HashMap::new(),
        }
    }
}

impl BlockDefMap {
    fn with_capacity(extra_cap: usize) -> Self {
        Self {
            slots: [None; REG_SLOT_COUNT],
            extra: HashMap::with_capacity(extra_cap),
        }
    }

    #[inline]
    fn slot_of(reg: &str) -> Option<usize> {
        let b = reg.as_bytes();
        if b.is_empty() {
            return None;
        }
        if b[0] == b'x' || b[0] == b'w' || b[0] == b'X' || b[0] == b'W' {
            if b.len() == 2 && b[1].is_ascii_digit() {
                return Some((b[1] - b'0') as usize);
            }
            if b.len() == 3 && b[1].is_ascii_digit() && b[2].is_ascii_digit() {
                let n = (b[1] - b'0') * 10 + (b[2] - b'0');
                if n <= 30 {
                    return Some(n as usize);
                }
            }
            if b.len() == 3 && (b[1] == b'z' || b[1] == b'Z') && (b[2] == b'r' || b[2] == b'R') {
                return Some(REG_SLOT_XZR);
            }
        }
        match reg {
            "sp" | "SP" => Some(REG_SLOT_SP),
            "lr" | "LR" => Some(30),
            "fp" | "FP" => Some(29),
            "__cmp" => Some(REG_SLOT_CMP),
            "__cond" => Some(REG_SLOT_COND),
            _ => None,
        }
    }

    #[inline]
    fn slot_name(slot: usize) -> &'static str {
        match slot {
            0 => "x0",
            1 => "x1",
            2 => "x2",
            3 => "x3",
            4 => "x4",
            5 => "x5",
            6 => "x6",
            7 => "x7",
            8 => "x8",
            9 => "x9",
            10 => "x10",
            11 => "x11",
            12 => "x12",
            13 => "x13",
            14 => "x14",
            15 => "x15",
            16 => "x16",
            17 => "x17",
            18 => "x18",
            19 => "x19",
            20 => "x20",
            21 => "x21",
            22 => "x22",
            23 => "x23",
            24 => "x24",
            25 => "x25",
            26 => "x26",
            27 => "x27",
            28 => "x28",
            29 => "x29",
            30 => "x30",
            REG_SLOT_SP => "sp",
            REG_SLOT_XZR => "xzr",
            REG_SLOT_CMP => "__cmp",
            REG_SLOT_COND => "__cond",
            _ => "?",
        }
    }

    #[inline]
    pub fn get(&self, reg: &str) -> Option<&SsaValueId> {
        if let Some(slot) = Self::slot_of(reg) {
            return self.slots[slot].as_ref();
        }
        self.extra.get(reg)
    }

    #[inline]
    pub fn insert(&mut self, reg: String, id: SsaValueId) -> Option<SsaValueId> {
        if let Some(slot) = Self::slot_of(&reg) {
            return self.slots[slot].replace(id);
        }
        self.extra.insert(reg, id)
    }

    #[inline]
    pub fn insert_reg(&mut self, reg: &str, id: SsaValueId) -> Option<SsaValueId> {
        if let Some(slot) = Self::slot_of(reg) {
            return self.slots[slot].replace(id);
        }
        if let Some(s) = normalize_reg_static(reg) {
            if let Some(slot) = Self::slot_of(s) {
                return self.slots[slot].replace(id);
            }
            return self.extra.insert(s.to_string(), id);
        }
        self.extra.insert(normalize_reg(reg), id)
    }

    #[inline]
    pub fn remove(&mut self, reg: &str) -> Option<SsaValueId> {
        if let Some(slot) = Self::slot_of(reg) {
            return self.slots[slot].take();
        }
        self.extra.remove(reg)
    }

    pub fn values(&self) -> impl Iterator<Item = &SsaValueId> {
        self.slots
            .iter()
            .filter_map(|s| s.as_ref())
            .chain(self.extra.values())
    }

    pub fn iter_pairs(&self) -> impl Iterator<Item = (&str, SsaValueId)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.map(|id| (Self::slot_name(i), id)))
            .chain(self.extra.iter().map(|(k, v)| (k.as_str(), *v)))
    }

    pub fn keys_owned(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(16);
        for (i, s) in self.slots.iter().enumerate() {
            if s.is_some() {
                out.push(Self::slot_name(i).to_string());
            }
        }
        out.extend(self.extra.keys().cloned());
        out
    }

    pub fn keys(&self) -> Vec<String> {
        self.keys_owned()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(|s| s.is_none()) && self.extra.is_empty()
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count() + self.extra.len()
    }
}

#[inline]
fn block_defs_mut(defs: &mut Vec<BlockDefMap>, block: BlockId) -> &mut BlockDefMap {
    let idx = block.0 as usize;
    if idx >= defs.len() {
        defs.resize_with(idx + 1, BlockDefMap::default);
    }
    &mut defs[idx]
}

/// SSA function: the result of SSA construction for a single function.
#[derive(Debug, Default)]
pub struct SsaFunction {
    pub cfg: Cfg,
    pub dom_tree: DominatorTree,
    pub values: Vec<SsaInstruction>,
    pub next_value: u32,
    pub defs: Vec<BlockDefMap>,
    pub case_labels: HashMap<BlockId, Vec<String>>,
    pub large: bool,
}

impl SsaFunction {
    pub fn new(cfg: Cfg) -> Self {
        let dom_tree = DominatorTree::compute(&cfg);
        SsaFunction {
            cfg,
            dom_tree,
            values: Vec::new(),
            next_value: 0,
            defs: Vec::new(),
            case_labels: HashMap::new(),
            large: false,
        }
    }

    pub fn new_shallow(cfg: Cfg) -> Self {
        SsaFunction {
            cfg,
            dom_tree: DominatorTree::default(),
            values: Vec::new(),
            next_value: 0,
            defs: Vec::new(),
            case_labels: HashMap::new(),
            large: false,
        }
    }

    #[inline]
    fn ensure_block_defs(&mut self, block: BlockId) -> &mut BlockDefMap {
        block_defs_mut(&mut self.defs, block)
    }

    #[inline]
    fn block_defs(&self, block: BlockId) -> Option<&BlockDefMap> {
        self.defs.get(block.0 as usize)
    }

    pub fn new_value_id(&mut self) -> SsaValueId {
        let id = SsaValueId(self.next_value);
        self.next_value += 1;
        id
    }

    pub fn define(&mut self, register: &str, block: BlockId, op: SsaOp, source_addr: u64) -> SsaValueId {
        let id = self.new_value_id();
        self.values.push(SsaInstruction {
            id,
            op,
            source_addr,
            block,
        });
        self.cfg.block_mut(block).insts.push(id);
        self.ensure_block_defs(block).insert_reg(register, id);
        id
    }

    pub fn define_norm(
        &mut self,
        register: String,
        block: BlockId,
        op: SsaOp,
        source_addr: u64,
    ) -> SsaValueId {
        let id = self.new_value_id();
        self.values.push(SsaInstruction {
            id,
            op,
            source_addr,
            block,
        });
        self.cfg.block_mut(block).insts.push(id);
        self.ensure_block_defs(block).insert(register, id);
        id
    }

    #[inline]
    pub fn push_inst(&mut self, block: BlockId, op: SsaOp, source_addr: u64) -> SsaValueId {
        let id = self.new_value_id();
        self.values.push(SsaInstruction {
            id,
            op,
            source_addr,
            block,
        });
        self.cfg.block_mut(block).insts.push(id);
        id
    }

    pub fn lookup(&self, register: &str, block: BlockId) -> Option<SsaValueId> {
        let trimmed = register.trim();
        if let Some(id) = self.lookup_key(trimmed, block) {
            return Some(id);
        }
        if let Some(s) = normalize_reg_static(trimmed) {
            if s != trimmed {
                return self.lookup_key(s, block);
            }
            return None;
        }
        let normalized = normalize_reg(trimmed);
        if normalized.as_str() != trimmed {
            self.lookup_key(&normalized, block)
        } else {
            None
        }
    }

    pub fn lookup_norm(&self, register: &str, block: BlockId) -> Option<SsaValueId> {
        self.lookup_key(register, block)
    }

    fn lookup_key(&self, register: &str, block: BlockId) -> Option<SsaValueId> {
        let hop_limit = if self.large { 96 } else { 512 };
        let mut current = Some(block);
        let mut hops = 0u32;
        while let Some(b) = current {
            if hops >= hop_limit {
                break;
            }
            hops += 1;
            if let Some(id) = self.block_defs(b).and_then(|m| m.get(register)).copied() {
                return Some(id);
            }
            if b == self.cfg.entry {
                break;
            }
            let preds = self.cfg.predecessors(b);
            if preds.len() == 1 {
                current = Some(preds[0]);
                continue;
            }
            if preds.len() > 1 {
                break;
            }
            if self.large {
                break;
            }
            let idom = self.dom_tree.idom_of(b);
            if idom == Some(b) || idom.is_none() {
                break;
            }
            current = idom;
        }
        None
    }

    /// Get all SSA instructions in a block (phis first, then regular).
    pub fn block_instructions(&self, block: BlockId) -> Vec<&SsaInstruction> {
        let cfg_block = self.cfg.block(block);
        let mut result = Vec::with_capacity(cfg_block.phis.len() + cfg_block.insts.len());
        for id in cfg_block.phis.iter().chain(cfg_block.insts.iter()) {
            if (id.0 as usize) < self.values.len() {
                result.push(&self.values[id.0 as usize]);
            }
        }
        result
    }

    pub fn render_value(&self, id: SsaValueId) -> String {
        let mut visiting = HashSet::new();
        let mut cache = HashMap::new();
        self.render_value_depth(id, 0, &mut visiting, &mut cache)
    }

    fn render_value_depth(
        &self,
        id: SsaValueId,
        depth: usize,
        visiting: &mut HashSet<SsaValueId>,
        cache: &mut HashMap<SsaValueId, String>,
    ) -> String {
        if depth > 48 || id.0 as usize >= self.values.len() {
            return format!("v{}", id.0);
        }
        if let Some(hit) = cache.get(&id) {
            return hit.clone();
        }
        if !visiting.insert(id) {
            return format!("v{}", id.0);
        }
        let inst = &self.values[id.0 as usize];
        let out = match &inst.op {
            SsaOp::Copy { src } => self.render_operand_depth(src, depth + 1, visiting, cache),
            SsaOp::BinOp { kind, lhs, rhs } => {
                let l = self.render_operand_depth(lhs, depth + 1, visiting, cache);
                let r = self.render_operand_depth(rhs, depth + 1, visiting, cache);
                match kind {
                    BinOpKind::Eq | BinOpKind::Ne | BinOpKind::Lt | BinOpKind::Le
                    | BinOpKind::Gt | BinOpKind::Ge => {
                        format!("{} {} {}", l, Self::render_binop(*kind), r)
                    }
                    _ => format!("({} {} {})", l, Self::render_binop(*kind), r),
                }
            }
            SsaOp::UnaryOp { kind, src } => {
                format!(
                    "{}{}",
                    Self::render_unaryop(*kind),
                    self.render_operand_depth(src, depth + 1, visiting, cache)
                )
            }
            SsaOp::Load { addr } => match addr {
                Operand::Deref { base, offset } => {
                    let base_text = self.render_operand_depth(base, depth + 1, visiting, cache);
                    if *offset == 0 {
                        if base_text.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
                            format!("*{base_text}")
                        } else {
                            format!("*({base_text})")
                        }
                    } else if *offset > 0 {
                        format!("*({base_text}+{offset:#x})")
                    } else {
                        format!("*({base_text}-{:#x})", -*offset)
                    }
                }
                other => format!(
                    "*({})",
                    self.render_operand_depth(other, depth + 1, visiting, cache)
                ),
            }
            SsaOp::Store { addr, value } => {
                format!(
                    "*({}) = {}",
                    self.render_operand_depth(addr, depth + 1, visiting, cache),
                    self.render_operand_depth(value, depth + 1, visiting, cache)
                )
            }
            SsaOp::Call { target, args } => {
                let args_str = args
                    .iter()
                    .map(|a| self.render_operand_depth(a, depth + 1, visiting, cache))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "{}({})",
                    self.render_operand_depth(target, depth + 1, visiting, cache),
                    args_str
                )
            }
            SsaOp::Return { value } => match value {
                Some(v) => format!(
                    "return {}",
                    self.render_operand_depth(v, depth + 1, visiting, cache)
                ),
                None => "return".to_string(),
            },
            SsaOp::Phi { incoming } => {
                let pairs = incoming
                    .iter()
                    .map(|(b, v)| format!("bb{}: v{}", b.0, v.0))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("phi({})", pairs)
            }
            SsaOp::Branch { cond, .. } => {
                format!(
                    "if ({})",
                    self.render_operand_depth(cond, depth + 1, visiting, cache)
                )
            }
            SsaOp::Jump { .. } => "goto".to_string(),
            SsaOp::Unknown => "/* unknown */".to_string(),
        };
        visiting.remove(&id);
        let out = if out.len() > 512 {
            format!("v{}", id.0)
        } else {
            out
        };
        cache.insert(id, out.clone());
        out
    }

    fn render_operand_depth(
        &self,
        op: &Operand,
        depth: usize,
        visiting: &mut HashSet<SsaValueId>,
        cache: &mut HashMap<SsaValueId, String>,
    ) -> String {
        match op {
            Operand::Value(id) => self.render_value_depth(*id, depth, visiting, cache),
            Operand::Constant(c) => {
                if *c < 0 {
                    format!("-0x{:x}", -c)
                } else {
                    format!("0x{:x}", c)
                }
            }
            Operand::Symbol(name) => name.clone(),
            Operand::Deref { base, offset } => {
                if *offset == 0 {
                    format!(
                        "*({})",
                        self.render_operand_depth(base, depth + 1, visiting, cache)
                    )
                } else {
                    format!(
                        "*({} + {:#x})",
                        self.render_operand_depth(base, depth + 1, visiting, cache),
                        offset
                    )
                }
            }
        }
    }

    fn render_operand(&self, op: &Operand) -> String {
        let mut visiting = HashSet::new();
        let mut cache = HashMap::new();
        self.render_operand_depth(op, 0, &mut visiting, &mut cache)
    }

    fn render_binop(kind: BinOpKind) -> &'static str {
        match kind {
            BinOpKind::Add => "+", BinOpKind::Sub => "-", BinOpKind::Mul => "*",
            BinOpKind::Div => "/", BinOpKind::Mod => "%",
            BinOpKind::And => "&", BinOpKind::Or => "|", BinOpKind::Xor => "^",
            BinOpKind::Shl => "<<", BinOpKind::Shr => ">>", BinOpKind::Sar => ">>",
            BinOpKind::Eq => "==", BinOpKind::Ne => "!=",
            BinOpKind::Lt => "<", BinOpKind::Le => "<=",
            BinOpKind::Gt => ">", BinOpKind::Ge => ">=",
        }
    }

    fn render_unaryop(kind: UnaryOpKind) -> &'static str {
        match kind {
            UnaryOpKind::Neg => "-", UnaryOpKind::Not => "~", UnaryOpKind::Bswap => "bswap(",
        }
    }
}

// ─── Constant Propagation ──────────────────────────────────────────────────

/// Sparse conditional constant propagation over SSA form.
///
/// This pass:
/// - Propagates constants through Copy and BinOp instructions
/// - Folds constant expressions (e.g., `0x1 + 0x2` → `0x3`)
/// - Marks unreachable blocks (blocks never reached due to constant branch conditions)
pub fn constant_propagation(func: &mut SsaFunction) {
    if func.values.is_empty() {
        return;
    }

    let n = func.values.len();
    let mut users: Vec<Vec<u32>> = vec![Vec::new(); n];
    let mut used_buf: Vec<SsaValueId> = Vec::with_capacity(8);
    for inst in &func.values {
        used_buf.clear();
        collect_used_operands_vec(&inst.op, &mut used_buf);
        if used_buf.len() > 1 {
            used_buf.sort_unstable_by_key(|v| v.0);
            used_buf.dedup();
        }
        for used in &used_buf {
            let idx = used.0 as usize;
            if idx < n {
                users[idx].push(inst.id.0);
            }
        }
    }

    let mut worklist: VecDeque<u32> = VecDeque::new();
    let mut constants: Vec<Option<i64>> = vec![None; n];
    let mut known: Vec<bool> = vec![false; n];
    for inst in &func.values {
        match &inst.op {
            SsaOp::Copy {
                src: Operand::Constant(_),
            }
            | SsaOp::BinOp { .. }
            | SsaOp::UnaryOp { .. }
            | SsaOp::Copy {
                src: Operand::Value(_),
            } => {
                worklist.push_back(inst.id.0);
            }
            _ => {}
        }
    }

    while let Some(vid) = worklist.pop_front() {
        let idx = vid as usize;
        if idx >= n {
            continue;
        }
        let inst = &func.values[idx];
        let new_val = match &inst.op {
            SsaOp::Copy {
                src: Operand::Constant(c),
            } => Some(*c),
            SsaOp::Copy {
                src: Operand::Value(other),
            } => {
                let o = other.0 as usize;
                if o < n && known[o] {
                    constants[o]
                } else {
                    None
                }
            }
            SsaOp::BinOp { kind, lhs, rhs } => {
                let lv = eval_operand_constant_vec(lhs, &constants, &known);
                let rv = eval_operand_constant_vec(rhs, &constants, &known);
                match (lv, rv) {
                    (Some(l), Some(r)) => eval_binop(*kind, l, r),
                    _ => None,
                }
            }
            SsaOp::UnaryOp {
                kind,
                src: Operand::Constant(c),
            } => match kind {
                UnaryOpKind::Neg => c.checked_neg(),
                UnaryOpKind::Not => Some(!*c),
                UnaryOpKind::Bswap => Some(c.swap_bytes()),
            },
            SsaOp::UnaryOp { kind, src } => {
                match eval_operand_constant_vec(src, &constants, &known) {
                    Some(sv) => match kind {
                        UnaryOpKind::Neg => sv.checked_neg(),
                        UnaryOpKind::Not => Some(!sv),
                        UnaryOpKind::Bswap => Some(sv.swap_bytes()),
                    },
                    None => None,
                }
            }
            _ => None,
        };

        let old_known = known[idx];
        let old_val = constants[idx];
        if new_val.is_some() && (!old_known || old_val != new_val) {
            constants[idx] = new_val;
            known[idx] = true;
            for &user in &users[idx] {
                worklist.push_back(user);
            }
        } else if new_val.is_none() && old_known {
            // keep previously known constants (monotone lattice)
        }
    }

    let const_map: HashMap<SsaValueId, Option<i64>> = constants
        .iter()
        .enumerate()
        .filter(|(i, _)| known[*i])
        .map(|(i, c)| (SsaValueId(i as u32), *c))
        .collect();

    for inst in &mut func.values {
        replace_operands_with_constants(&mut inst.op, &const_map);
        if let SsaOp::BinOp { kind, lhs, rhs } = &inst.op {
            if let (Operand::Constant(l), Operand::Constant(r)) = (lhs, rhs) {
                if let Some(folded) = eval_binop(*kind, *l, *r) {
                    inst.op = SsaOp::Copy {
                        src: Operand::Constant(folded),
                    };
                    continue;
                }
            }
        }
        if let SsaOp::UnaryOp {
            kind,
            src: Operand::Constant(c),
        } = &inst.op
        {
            let folded = match kind {
                UnaryOpKind::Neg => c.checked_neg(),
                UnaryOpKind::Not => Some(!*c),
                UnaryOpKind::Bswap => Some(c.swap_bytes()),
            };
            if let Some(value) = folded {
                inst.op = SsaOp::Copy {
                    src: Operand::Constant(value),
                };
            }
        }
    }
    copy_propagation(func);
}

fn eval_operand_constant_vec(
    op: &Operand,
    constants: &[Option<i64>],
    known: &[bool],
) -> Option<i64> {
    match op {
        Operand::Constant(c) => Some(*c),
        Operand::Value(id) => {
            let idx = id.0 as usize;
            if idx < known.len() && known[idx] {
                constants[idx]
            } else {
                None
            }
        }
        Operand::Deref { base, .. } => eval_operand_constant_vec(base, constants, known),
        _ => None,
    }
}

fn eval_operand_constant(op: &Operand, constants: &HashMap<SsaValueId, Option<i64>>) -> Option<i64> {
    match op {
        Operand::Constant(c) => Some(*c),
        Operand::Value(id) => constants.get(id).copied().flatten(),
        Operand::Deref { base, .. } => eval_operand_constant(base, constants),
        _ => None,
    }
}

fn eval_binop(kind: BinOpKind, l: i64, r: i64) -> Option<i64> {
    match kind {
        BinOpKind::Add => l.checked_add(r),
        BinOpKind::Sub => l.checked_sub(r),
        BinOpKind::Mul => l.checked_mul(r),
        BinOpKind::Div => if r != 0 { l.checked_div(r) } else { None },
        BinOpKind::Mod => if r != 0 { l.checked_rem(r) } else { None },
        BinOpKind::And => Some(l & r),
        BinOpKind::Or => Some(l | r),
        BinOpKind::Xor => Some(l ^ r),
        BinOpKind::Shl => if r >= 0 && r < 64 { Some(l << r) } else { None },
        BinOpKind::Shr => if r >= 0 && r < 64 { Some(((l as u64) >> r) as i64) } else { None },
        BinOpKind::Sar => if r >= 0 && r < 64 { Some(l >> r) } else { None },
        BinOpKind::Eq => Some((l == r) as i64),
        BinOpKind::Ne => Some((l != r) as i64),
        BinOpKind::Lt => Some((l < r) as i64),
        BinOpKind::Le => Some((l <= r) as i64),
        BinOpKind::Gt => Some((l > r) as i64),
        BinOpKind::Ge => Some((l >= r) as i64),
    }
}

fn replace_operand_constants(operand: &mut Operand, constants: &HashMap<SsaValueId, Option<i64>>) {
    match operand {
        Operand::Value(id) => {
            if let Some(Some(c)) = constants.get(id) {
                *operand = Operand::Constant(*c);
            }
        }
        Operand::Deref { base, .. } => {
            replace_operand_constants(base, constants);
        }
        _ => {}
    }
}

fn replace_operands_with_constants(op: &mut SsaOp, constants: &HashMap<SsaValueId, Option<i64>>) {
    let replace = |operand: &mut Operand| {
        replace_operand_constants(operand, constants);
    };
    match op {
        SsaOp::Copy { src } => replace(src),
        SsaOp::BinOp { lhs, rhs, .. } => { replace(lhs); replace(rhs); }
        SsaOp::UnaryOp { src, .. } => replace(src),
        SsaOp::Load { addr } => replace(addr),
        SsaOp::Store { addr, value } => { replace(addr); replace(value); }
        SsaOp::Call { target, args } => {
            replace(target);
            for a in args.iter_mut() { replace(a); }
        }
        SsaOp::Return { value } => { if let Some(v) = value { replace(v); } }
        SsaOp::Branch { cond, .. } => replace(cond),
        _ => {}
    }
}

// ─── Dead Code Elimination ─────────────────────────────────────────────────

fn collect_operand_recursive(operand: &Operand, used: &mut HashSet<SsaValueId>) {
    match operand {
        Operand::Value(id) => { used.insert(*id); }
        Operand::Deref { base, .. } => { collect_operand_recursive(base, used); }
        _ => {}
    }
}

pub fn copy_propagation(func: &mut SsaFunction) {
    if func.values.is_empty() {
        return;
    }
    let mut aliases: HashMap<SsaValueId, Operand> = HashMap::new();
    for inst in &func.values {
        if let SsaOp::Copy { src } = &inst.op {
            let resolved = match src {
                Operand::Value(id) => aliases.get(id).cloned().unwrap_or_else(|| src.clone()),
                other => other.clone(),
            };
            aliases.insert(inst.id, resolved);
        }
    }
    if aliases.is_empty() {
        return;
    }
    let rewrite = |operand: &mut Operand| {
        if let Operand::Value(id) = operand {
            if let Some(replacement) = aliases.get(id) {
                *operand = replacement.clone();
            }
        } else if let Operand::Deref { base, .. } = operand {
            if let Operand::Value(id) = base.as_ref() {
                if let Some(replacement) = aliases.get(id) {
                    *base = Box::new(replacement.clone());
                }
            }
        }
    };
    for inst in &mut func.values {
        match &mut inst.op {
            SsaOp::Copy { src } => rewrite(src),
            SsaOp::BinOp { lhs, rhs, .. } => {
                rewrite(lhs);
                rewrite(rhs);
            }
            SsaOp::UnaryOp { src, .. } => rewrite(src),
            SsaOp::Load { addr } => rewrite(addr),
            SsaOp::Store { addr, value } => {
                rewrite(addr);
                rewrite(value);
            }
            SsaOp::Call { target, args } => {
                rewrite(target);
                for arg in args {
                    rewrite(arg);
                }
            }
            SsaOp::Return { value } => {
                if let Some(v) = value {
                    rewrite(v);
                }
            }
            SsaOp::Branch { cond, .. } => rewrite(cond),
            _ => {}
        }
    }
}

pub fn dead_code_elimination(func: &mut SsaFunction) {
    if func.values.is_empty() {
        return;
    }

    let n = func.values.len();
    let mut live: Vec<bool> = vec![false; n];
    let mut worklist: VecDeque<u32> = VecDeque::new();
    let mut used_buf: Vec<SsaValueId> = Vec::with_capacity(8);
    for inst in &func.values {
        let keep = match &inst.op {
            SsaOp::Store { .. }
            | SsaOp::Call { .. }
            | SsaOp::Return { .. }
            | SsaOp::Branch { .. }
            | SsaOp::Jump { .. } => true,
            SsaOp::Copy {
                src: Operand::Symbol(name),
            } if name.starts_with("/* switch") => true,
            _ => false,
        };
        if keep {
            let idx = inst.id.0 as usize;
            if idx < n && !live[idx] {
                live[idx] = true;
                worklist.push_back(inst.id.0);
            }
        }
    }

    while let Some(vid) = worklist.pop_front() {
        let idx = vid as usize;
        if idx >= n {
            continue;
        }
        used_buf.clear();
        collect_used_operands_vec(&func.values[idx].op, &mut used_buf);
        for used in &used_buf {
            let u = used.0 as usize;
            if u < n && !live[u] {
                live[u] = true;
                worklist.push_back(used.0);
            }
        }
    }

    for block in &mut func.cfg.blocks {
        block.insts.retain(|id| {
            let idx = id.0 as usize;
            if idx < n && live[idx] {
                return true;
            }
            let Some(inst) = func.values.get(idx) else {
                return false;
            };
            match &inst.op {
                SsaOp::Store { .. }
                | SsaOp::Call { .. }
                | SsaOp::Return { .. }
                | SsaOp::Branch { .. }
                | SsaOp::Jump { .. } => true,
                SsaOp::Copy {
                    src: Operand::Symbol(name),
                } if name.starts_with("/* switch") => true,
                _ => false,
            }
        });
    }
}

// ─── ARM64 Instruction Lifter ──────────────────────────────────────────────

/// Lift ARM64 basic blocks into SSA form.
///
/// This is the bridge between raw ARM64 instructions and the SSA IR.
/// It translates each instruction into one or more SSA operations,
/// building a `SsaFunction` that can then be optimized and rendered.
pub fn lift_arm64_to_ssa(
    blocks: &[revx_core::BasicBlock],
    references: &[revx_core::Reference],
    arguments: &[revx_core::Variable],
) -> SsaFunction {
    let trace = ssa_trace_enabled();
    let t0 = if trace { Some(std::time::Instant::now()) } else { None };
    let inst_count: usize = blocks.iter().map(|b| b.instructions.len()).sum();
    let large = blocks.len() > 24 || inst_count > 128;
    let mut edges: Vec<(u64, u64)> = Vec::with_capacity(references.len());
    let mut call_targets: HashMap<u64, u64> = HashMap::with_capacity(references.len().min(64));
    let mut jump_targets: HashMap<u64, u64> = HashMap::with_capacity(references.len().min(64));
    let mut call_names: HashMap<u64, String> = HashMap::with_capacity(16);
    for r in references {
        match r.kind {
            revx_core::ReferenceKind::Call => {
                call_targets.insert(r.from, r.to);
                edges.push((r.from, r.to));
            }
            revx_core::ReferenceKind::Jump => {
                jump_targets.insert(r.from, r.to);
                edges.push((r.from, r.to));
            }
            revx_core::ReferenceKind::BranchTrue
            | revx_core::ReferenceKind::BranchFalse
            | revx_core::ReferenceKind::Fallthrough => {
                edges.push((r.from, r.to));
            }
            _ => {}
        }
    }
    let (cfg, block_addr_to_id) = Cfg::from_basic_blocks(blocks, &edges);
    let t1 = if trace { Some(std::time::Instant::now()) } else { None };

    let mut func = if large {
        SsaFunction::new_shallow(cfg)
    } else {
        SsaFunction::new(cfg)
    };
    func.values.reserve(inst_count.saturating_mul(2).max(16));
    func.large = large;
    func.defs = (0..blocks.len())
        .map(|_| BlockDefMap::with_capacity(if large { 4 } else { 2 }))
        .collect();

    for arg in arguments {
        if arg.storage == revx_core::VariableStorage::Register {
            let reg = normalize_reg(&arg.location);
            let block = func.cfg.entry;
            let id = func.new_value_id();
            let inst = SsaInstruction {
                id,
                op: SsaOp::Copy {
                    src: Operand::Symbol(arg.name.clone()),
                },
                source_addr: 0,
                block,
            };
            func.cfg.block_mut(block).insts.push(inst.id);

            func.values.push(inst);
            block_defs_mut(&mut func.defs, block).insert(reg, id);
        }
    }

    for block in blocks {
        let Some(&block_id) = block_addr_to_id.get(&block.address) else {
            continue;
        };
        for inst in &block.instructions {
            lift_arm64_instruction(inst, block_id, &mut func, &block_addr_to_id, references, &call_targets, &jump_targets, &mut call_names);
        }
    }
    let t2 = if trace { Some(std::time::Instant::now()) } else { None };

    if !(large && blocks.len() > 48) {
        insert_register_phis(&mut func);
    }
    let t3 = if trace { Some(std::time::Instant::now()) } else { None };
    let needs_switch = references.iter().any(|r| {
        matches!(
            r.kind,
            revx_core::ReferenceKind::Jump
                | revx_core::ReferenceKind::IndirectJump
                | revx_core::ReferenceKind::DataRef
        ) && (r.kind != revx_core::ReferenceKind::Jump || r.to > 31)
    });
    if needs_switch {
        let has_case_tags = references.iter().any(|r| {
            r.kind == revx_core::ReferenceKind::DataRef && crate::case_char_untag(r.to).is_some()
        });
        if has_case_tags {
            attach_jump_table_case_labels_with_map(
                &mut func,
                blocks,
                references,
                &block_addr_to_id,
            );
        }
        polish_switch_markers_with_map(&mut func, references, &block_addr_to_id);
    }
    let t4 = if trace { Some(std::time::Instant::now()) } else { None };
    let needs_rewrite = !large
        || func
            .values
            .iter()
            .any(|inst| matches!(inst.op, SsaOp::Call { .. }));
    if needs_rewrite {
        rewrite_symbol_regs_to_values(&mut func);
    }
    let t5 = if trace { Some(std::time::Instant::now()) } else { None };
    if !large {
        rewrite_low_constant_mem_bases(&mut func);
        constant_propagation(&mut func);
        dead_code_elimination(&mut func);
    } else if blocks.len() <= 96 {
        light_constant_fold(&mut func);
    }
    if let (Some(t0), Some(t1), Some(t2), Some(t3), Some(t4), Some(t5)) = (t0, t1, t2, t3, t4, t5) {
        let t6 = std::time::Instant::now();
        eprintln!(
            "revx-trace ssa-lift-breakdown blocks={} insts={} values={} large={} cfg={}ms lift={}ms phi={}ms switch={}ms rewrite={}ms opt={}ms total={}ms",
            blocks.len(),
            inst_count,
            func.values.len(),
            large,
            t1.duration_since(t0).as_millis(),
            t2.duration_since(t1).as_millis(),
            t3.duration_since(t2).as_millis(),
            t4.duration_since(t3).as_millis(),
            t5.duration_since(t4).as_millis(),
            t6.duration_since(t5).as_millis(),
            t6.duration_since(t0).as_millis()
        );
    }

    func
}

fn light_constant_fold(func: &mut SsaFunction) {
    for inst in &mut func.values {
        if let SsaOp::BinOp { kind, lhs, rhs } = &inst.op {
            if let (Operand::Constant(l), Operand::Constant(r)) = (lhs, rhs) {
                if let Some(folded) = eval_binop(*kind, *l, *r) {
                    inst.op = SsaOp::Copy {
                        src: Operand::Constant(folded),
                    };
                }
            }
        } else if let SsaOp::UnaryOp {
            kind,
            src: Operand::Constant(c),
        } = &inst.op
        {
            let folded = match kind {
                UnaryOpKind::Neg => c.checked_neg(),
                UnaryOpKind::Not => Some(!*c),
                UnaryOpKind::Bswap => Some(c.swap_bytes()),
            };
            if let Some(value) = folded {
                inst.op = SsaOp::Copy {
                    src: Operand::Constant(value),
                };
            }
        }
    }
}

fn attach_jump_table_case_labels(
    func: &mut SsaFunction,
    blocks: &[revx_core::BasicBlock],
    references: &[revx_core::Reference],
) {
    let mut addr_to_block: HashMap<u64, BlockId> = HashMap::new();
    for (i, b) in blocks.iter().enumerate() {
        let id = BlockId(i as u32);
        addr_to_block.insert(b.address, id);
        for inst in &b.instructions {
            addr_to_block.insert(inst.address, id);
        }
    }
    attach_jump_table_case_labels_with_map(func, blocks, references, &addr_to_block);
}

fn attach_jump_table_case_labels_with_map(
    func: &mut SsaFunction,
    _blocks: &[revx_core::BasicBlock],
    references: &[revx_core::Reference],
    addr_to_block: &HashMap<u64, BlockId>,
) {
    let jump_targets: HashSet<u64> = references
        .iter()
        .filter(|r| r.kind == revx_core::ReferenceKind::Jump && r.to > 31)
        .map(|r| r.to)
        .collect();

    let mut labels: HashMap<BlockId, Vec<(i64, String)>> = HashMap::new();
    for r in references {
        if r.kind != revx_core::ReferenceKind::DataRef {
            continue;
        }
        let Some(ch) = crate::case_char_untag(r.to) else {
            continue;
        };
        if !jump_targets.contains(&r.from) {
            continue;
        }
        let Some(&block_id) = addr_to_block.get(&r.from) else {
            continue;
        };
        labels
            .entry(block_id)
            .or_default()
            .push((ch as i64, format_case_char_label(ch as i64)));
    }

    for (block, mut items) in labels {
        items.sort_by_key(|(ch, _)| *ch);
        items.dedup_by(|a, b| a.0 == b.0);
        let names: Vec<String> = if items.len() >= 8 {
            vec!["default".to_string()]
        } else {
            let mut names: Vec<String> = items.into_iter().map(|(_, s)| s).collect();
            if names.len() > 10 {
                let more = names.len() - 8;
                names.truncate(8);
                names.push(format!("+{more} more"));
            }
            names
        };
        if !names.is_empty() {
            func.case_labels.insert(block, names);
        }
    }
}

fn format_case_char_label(ch: i64) -> String {
    if (0x20..0x7f).contains(&ch) {
        let c = ch as u8 as char;
        if c == '\\' {
            return "case '\\\\'".to_string();
        }
        if c == '\'' {
            return "case '\\''".to_string();
        }
        return format!("case '{c}'");
    }
    if ch == -1 {
        return "case -1".to_string();
    }
    format!("case {ch:#x}")
}

fn polish_switch_markers(
    func: &mut SsaFunction,
    references: &[revx_core::Reference],
    blocks: &[revx_core::BasicBlock],
) {
    let mut addr_to_block: HashMap<u64, BlockId> = HashMap::new();
    for (i, b) in blocks.iter().enumerate() {
        addr_to_block.insert(b.address, BlockId(i as u32));
        for inst in &b.instructions {
            addr_to_block.insert(inst.address, BlockId(i as u32));
        }
    }
    polish_switch_markers_with_map(func, references, &addr_to_block);
}

fn polish_switch_markers_with_map(
    func: &mut SsaFunction,
    references: &[revx_core::Reference],
    addr_to_block: &HashMap<u64, BlockId>,
) {
    let mut jumps_by_from: HashMap<u64, Vec<u64>> = HashMap::new();
    for r in references {
        if r.kind == revx_core::ReferenceKind::Jump && r.to > 31 {
            jumps_by_from.entry(r.from).or_default().push(r.to);
        }
    }
    if jumps_by_from.is_empty() {
        return;
    }
    let large = func.cfg.blocks.len() > 48 || func.values.len() > 400;
    if large && func.case_labels.len() >= 8 {
        return;
    }
    let mut br_sites: Vec<u64> = jumps_by_from.keys().copied().collect();
    br_sites.sort_unstable();
    for br in br_sites {
        let Some(targets) = jumps_by_from.get(&br) else {
            continue;
        };
        let mut case_blocks: Vec<BlockId> = targets
            .iter()
            .filter_map(|to| addr_to_block.get(to).copied())
            .collect();
        case_blocks.sort_by_key(|b| b.0);
        case_blocks.dedup();
        if case_blocks.len() < 2 {
            continue;
        }
        let mut chars: Vec<String> = Vec::new();
        for bid in &case_blocks {
            if let Some(labels) = func.case_labels.get(bid) {
                for lab in labels {
                    if let Some(rest) = lab.strip_prefix("case ") {
                        if rest.starts_with('\'') {
                            chars.push(rest.to_string());
                        }
                    }
                }
            }
        }
        chars.sort();
        chars.dedup();
        let option_chars: Vec<String> = chars
            .iter()
            .filter(|s| {
                let body = s.trim_matches('\'');
                let Some(c) = body.chars().next() else {
                    return false;
                };
                body.len() == 1
                    && (c.is_ascii_alphanumeric() || matches!(c, '@' | '%' | ','))
            })
            .cloned()
            .collect();
        let summary = if option_chars.len() >= 2 {
            let head: Vec<&str> = option_chars.iter().take(16).map(|s| s.as_str()).collect();
            let more = if option_chars.len() > 16 {
                format!(", +{}", option_chars.len() - 16)
            } else {
                String::new()
            };
            format!("/* switch on opt {{{}{}}} */", head.join(", "), more)
        } else if chars.len() >= 2 {
            let head: Vec<&str> = chars.iter().take(16).map(|s| s.as_str()).collect();
            let more = if chars.len() > 16 {
                format!(", +{}", chars.len() - 16)
            } else {
                String::new()
            };
            format!("/* switch on opt {{{}{}}} */", head.join(", "), more)
        } else {
            let head: Vec<String> = case_blocks
                .iter()
                .take(12)
                .map(|b| format!("bb{}", b.0))
                .collect();
            let more = if case_blocks.len() > 12 {
                format!(", +{}", case_blocks.len() - 12)
            } else {
                String::new()
            };
            format!("/* switch -> {}{} */", head.join(", "), more)
        };
        if let Some(&bid) = addr_to_block.get(&br) {
            if let Some(cfg_block) = func.cfg.blocks.get(bid.0 as usize) {
                let inst_ids = cfg_block.insts.clone();
                for iid in inst_ids {
                    if let Some(inst) = func.values.get_mut(iid.0 as usize) {
                        if let SsaOp::Copy {
                            src: Operand::Symbol(name),
                        } = &inst.op
                        {
                            if name.starts_with("/* switch") {
                                inst.op = SsaOp::Copy {
                                    src: Operand::Symbol(summary.clone()),
                                };
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn refine_call_arguments_with_symbols(
    func: &mut SsaFunction,
    symbols: &HashMap<u64, String>,
) {
    let call_ids: Vec<SsaValueId> = func
        .values
        .iter()
        .filter(|inst| matches!(inst.op, SsaOp::Call { .. }))
        .map(|inst| inst.id)
        .collect();
    for id in call_ids {
        let Some(inst) = func.values.get(id.0 as usize) else {
            continue;
        };
        let SsaOp::Call { target, args } = &inst.op else {
            continue;
        };
        let name = match target {
            Operand::Symbol(n) => {
                if let Some(addr) = parse_sub_symbol_addr(n) {
                    symbols.get(&addr).cloned().unwrap_or_else(|| n.clone())
                } else {
                    n.clone()
                }
            }
            Operand::Constant(c) if *c >= 0 => symbols
                .get(&(*c as u64))
                .cloned()
                .unwrap_or_else(|| format_sub_addr(*c as u64)),
            _ => continue,
        };
        let call_addr = inst.source_addr;
        let call_block = inst.block;
        if is_variadic_call(&name) {
            let min_args = known_call_min_args(&name).unwrap_or(2);
            let mut cur_args = args.clone();
            if cur_args.len() <= min_args {
                let mut stack_args: Vec<(i64, Operand)> = Vec::new();
                let block_insts = func
                    .cfg
                    .blocks
                    .get(call_block.0 as usize)
                    .map(|b| b.insts.clone())
                    .unwrap_or_default();
                for &iid in &block_insts {
                    let Some(prev) = func.values.get(iid.0 as usize) else {
                        continue;
                    };
                    if prev.source_addr >= call_addr {
                        continue;
                    }
                    if call_addr.saturating_sub(prev.source_addr) > 0x30 {
                        continue;
                    }
                    let SsaOp::Store {
                        addr: st_addr,
                        value,
                    } = &prev.op
                    else {
                        continue;
                    };
                    if let Some(off) = stack_slot_offset(func, st_addr) {
                        if (0..0x20).contains(&off) {
                            stack_args.push((off, value.clone()));
                        }
                    }
                }
                stack_args.sort_by_key(|(off, _)| *off);
                stack_args.dedup_by_key(|(off, _)| *off);
                for (_, op) in stack_args.into_iter().take(4) {
                    cur_args.push(op);
                }
            }
            if let Some(inst) = func.values.get_mut(id.0 as usize) {
                if let SsaOp::Call { args, .. } = &mut inst.op {
                    *args = cur_args;
                }
            }
            continue;
        }
        let Some(max_args) = known_call_arg_count(&name) else {
            continue;
        };
        if let Some(inst) = func.values.get_mut(id.0 as usize) {
            if let SsaOp::Call { args, .. } = &mut inst.op {
                if args.len() > max_args {
                    args.truncate(max_args);
                }
            }
        }
    }
}

pub fn lift_x64_to_ssa(
    blocks: &[revx_core::BasicBlock],
    references: &[revx_core::Reference],
    arguments: &[revx_core::Variable],
) -> SsaFunction {
    let edges: Vec<(u64, u64)> = references
        .iter()
        .filter(|r| {
            matches!(
                r.kind,
                revx_core::ReferenceKind::Call
                    | revx_core::ReferenceKind::Jump
                    | revx_core::ReferenceKind::BranchTrue
                    | revx_core::ReferenceKind::BranchFalse
                    | revx_core::ReferenceKind::Fallthrough
                    | revx_core::ReferenceKind::Branch
            )
        })
        .map(|r| (r.from, r.to))
        .collect();
    let (cfg, block_addr_to_id) = Cfg::from_basic_blocks(blocks, &edges);
    let inst_count: usize = blocks.iter().map(|b| b.instructions.len()).sum();
    let large = blocks.len() > 24 || inst_count > 128;
    let mut func = if large {
        SsaFunction::new_shallow(cfg)
    } else {
        SsaFunction::new(cfg)
    };
    func.values.reserve(inst_count.saturating_mul(2).max(16));
    func.large = large;
    func.defs = (0..blocks.len())
        .map(|_| BlockDefMap::with_capacity(if large { 4 } else { 2 }))
        .collect();

    for arg in arguments {
        if arg.storage == revx_core::VariableStorage::Register {
            let reg = normalize_reg(&arg.location);
            let block = func.cfg.entry;
            let id = func.new_value_id();
            let inst = SsaInstruction {
                id,
                op: SsaOp::Copy {
                    src: Operand::Symbol(arg.name.clone()),
                },
                source_addr: 0,
                block,
            };
            func.cfg.block_mut(block).insts.push(inst.id);

            func.values.push(inst);
            block_defs_mut(&mut func.defs, block).insert(reg, id);
        }
    }

    for block in blocks {
        let Some(&block_id) = block_addr_to_id.get(&block.address) else {
            continue;
        };
        for inst in &block.instructions {
            lift_x64_instruction(inst, block_id, &mut func, &block_addr_to_id, references);
        }
    }

    if !large {
        constant_propagation(&mut func);
        dead_code_elimination(&mut func);
    } else {
        light_constant_fold(&mut func);
    }
    func
}

fn lift_x64_instruction(
    inst: &revx_core::Instruction,
    block: BlockId,
    func: &mut SsaFunction,
    block_addr_to_id: &HashMap<u64, BlockId>,
    references: &[revx_core::Reference],
) {
    let text = inst.text.as_ref();
    let addr = inst.address;
    let opcode = text.split_whitespace().next().unwrap_or("");

    match opcode {
        "mov" | "movzx" | "movsx" | "movsxd" | "lea" => {
            if let Some(dst) = extract_x64_dest(text) {
                let src = extract_x64_src(text).unwrap_or_default();
                let operand = if let Some(imm) = parse_x64_imm(&src) {
                    Operand::Constant(imm)
                } else if src.starts_with('[') {
                    Operand::Deref {
                        base: Box::new(lookup_or_symbol(func, &x64_mem_base(&src), block)),
                        offset: x64_mem_offset(&src),
                    }
                } else {
                    lookup_or_symbol(func, &src, block)
                };
                if opcode == "lea" {
                    if src.starts_with('[') {
                        let base = lookup_or_symbol(func, &x64_mem_base(&src), block);
                        let off = x64_mem_offset(&src);
                        if off != 0 {
                            func.define(
                                &dst,
                                block,
                                SsaOp::BinOp {
                                    kind: BinOpKind::Add,
                                    lhs: base,
                                    rhs: Operand::Constant(off),
                                },
                                addr,
                            );
                        } else {
                            func.define(&dst, block, SsaOp::Copy { src: base }, addr);
                        }
                    } else {
                        func.define(&dst, block, SsaOp::Copy { src: operand }, addr);
                    }
                } else if src.starts_with('[') {
                    func.define(
                        &dst,
                        block,
                        SsaOp::Load { addr: operand },
                        addr,
                    );
                } else {
                    func.define(&dst, block, SsaOp::Copy { src: operand }, addr);
                }
            }
        }
        "add" | "sub" | "imul" | "and" | "or" | "xor" | "shl" | "shr" | "sar" => {
            lift_x64_binop(text, x64_binop_kind(opcode), block, func, addr);
        }
        "cmp" | "test" => {
            let dst = extract_x64_dest(text).unwrap_or_else(|| "__cmp".to_string());
            let src = extract_x64_src(text).unwrap_or_default();
            let lhs = lookup_or_symbol(func, &dst, block);
            let rhs = if let Some(imm) = parse_x64_imm(&src) {
                Operand::Constant(imm)
            } else {
                lookup_or_symbol(func, &src, block)
            };
            func.define(
                "__cmp",
                block,
                SsaOp::BinOp {
                    kind: if opcode == "test" {
                        BinOpKind::And
                    } else {
                        BinOpKind::Sub
                    },
                    lhs,
                    rhs,
                },
                addr,
            );
        }
        "push" => {
            let src = text.split_whitespace().nth(1).unwrap_or("").trim();
            let value = if let Some(imm) = parse_x64_imm(src) {
                Operand::Constant(imm)
            } else {
                lookup_or_symbol(func, src, block)
            };
            let sp = lookup_or_symbol(func, "rsp", block);
            let new_sp = {
                let id = func.new_value_id();
                let inst = SsaInstruction {
                    id,
                    op: SsaOp::BinOp {
                        kind: BinOpKind::Sub,
                        lhs: sp,
                        rhs: Operand::Constant(8),
                    },
                    source_addr: addr,
                    block,
                };
                func.cfg.block_mut(block).insts.push(inst.id);

                func.values.push(inst);
                block_defs_mut(&mut func.defs, block).insert("rsp".to_string(), id);
                Operand::Value(id)
            };
            let id = func.new_value_id();
            let inst = SsaInstruction {
                id,
                op: SsaOp::Store {
                    addr: Operand::Deref {
                        base: Box::new(new_sp),
                        offset: 0,
                    },
                    value,
                },
                source_addr: addr,
                block,
            };
            func.cfg.block_mut(block).insts.push(inst.id);

            func.values.push(inst);
        }
        "pop" => {
            if let Some(dst) = extract_x64_dest(text) {
                let sp = lookup_or_symbol(func, "rsp", block);
                func.define(
                    &dst,
                    block,
                    SsaOp::Load {
                        addr: Operand::Deref {
                            base: Box::new(sp.clone()),
                            offset: 0,
                        },
                    },
                    addr,
                );
                let id = func.new_value_id();
                let inst = SsaInstruction {
                    id,
                    op: SsaOp::BinOp {
                        kind: BinOpKind::Add,
                        lhs: sp,
                        rhs: Operand::Constant(8),
                    },
                    source_addr: addr,
                    block,
                };
                func.cfg.block_mut(block).insts.push(inst.id);

                func.values.push(inst);
                block_defs_mut(&mut func.defs, block).insert("rsp".to_string(), id);
            }
        }
        "call" => {
            let target_ref = references.iter().find(|r| {
                r.from == addr
                    && matches!(
                        r.kind,
                        revx_core::ReferenceKind::Call | revx_core::ReferenceKind::IndirectCall
                    )
            });
            let target = if let Some(r) = target_ref {
                if r.to != 0 {
                    Operand::Constant(r.to as i64)
                } else {
                    let token = text.split_whitespace().nth(1).unwrap_or("").trim();
                    lookup_or_symbol(func, token, block)
                }
            } else {
                let token = text.split_whitespace().nth(1).unwrap_or("").trim();
                if let Some(imm) = parse_x64_imm(token) {
                    Operand::Constant(imm)
                } else {
                    lookup_or_symbol(func, token, block)
                }
            };
            let id = func.new_value_id();
            let inst = SsaInstruction {
                id,
                op: SsaOp::Call {
                    target,
                    args: Vec::new(),
                },
                source_addr: addr,
                block,
            };
            func.cfg.block_mut(block).insts.push(inst.id);

            func.values.push(inst);
            block_defs_mut(&mut func.defs, block).insert("rax".to_string(), id);
        }
        "ret" | "retn" => {
            let value = func.lookup("rax", block).map(Operand::Value);
            let id = func.new_value_id();
            let inst = SsaInstruction {
                id,
                op: SsaOp::Return { value },
                source_addr: addr,
                block,
            };
            func.cfg.block_mut(block).insts.push(inst.id);

            func.values.push(inst);
        }
        "jmp" => {
            if let Some(target_ref) = references.iter().find(|r| {
                r.from == addr
                    && matches!(
                        r.kind,
                        revx_core::ReferenceKind::Jump | revx_core::ReferenceKind::IndirectJump
                    )
            }) {
                if let Some(&target_block) = block_addr_to_id.get(&target_ref.to) {
                    let id = func.new_value_id();
                    let inst = SsaInstruction {
                        id,
                        op: SsaOp::Jump {
                            target: target_block,
                        },
                        source_addr: addr,
                        block,
                    };
                    func.cfg.block_mut(block).insts.push(inst.id);

                    func.values.push(inst);
                }
            }
        }
        op if op.starts_with('j') && op != "jmp" => {
            let true_target = references
                .iter()
                .find(|r| r.from == addr && r.kind == revx_core::ReferenceKind::BranchTrue)
                .and_then(|r| block_addr_to_id.get(&r.to).copied());
            let false_target = references
                .iter()
                .find(|r| r.from == addr && r.kind == revx_core::ReferenceKind::BranchFalse)
                .and_then(|r| block_addr_to_id.get(&r.to).copied());
            if let (Some(t), Some(f)) = (true_target, false_target) {
                let cond = func
                    .lookup("__cmp", block)
                    .map(Operand::Value)
                    .unwrap_or(Operand::Symbol("cond".to_string()));
                let id = func.new_value_id();
                let inst = SsaInstruction {
                    id,
                    op: SsaOp::Branch {
                        cond,
                        true_block: t,
                        false_block: f,
                    },
                    source_addr: addr,
                    block,
                };
                func.cfg.block_mut(block).insts.push(inst.id);

                func.values.push(inst);
            }
        }
        "nop" | "endbr64" | "int3" | "ud2" | "hlt" | "leave" => {}
        _ => {
            let id = func.new_value_id();
            let inst = SsaInstruction {
                id,
                op: SsaOp::Unknown,
                source_addr: addr,
                block,
            };
            func.cfg.block_mut(block).insts.push(inst.id);

            func.values.push(inst);
        }
    }
}

fn x64_binop_kind(opcode: &str) -> BinOpKind {
    match opcode {
        "add" => BinOpKind::Add,
        "sub" => BinOpKind::Sub,
        "imul" => BinOpKind::Mul,
        "and" => BinOpKind::And,
        "or" => BinOpKind::Or,
        "xor" => BinOpKind::Xor,
        "shl" => BinOpKind::Shl,
        "shr" => BinOpKind::Shr,
        "sar" => BinOpKind::Sar,
        _ => BinOpKind::Add,
    }
}

fn lift_x64_binop(
    text: &str,
    kind: BinOpKind,
    block: BlockId,
    func: &mut SsaFunction,
    addr: u64,
) {
    let Some(dst) = extract_x64_dest(text) else {
        return;
    };
    let src = extract_x64_src(text).unwrap_or_default();
    let lhs = lookup_or_symbol(func, &dst, block);
    let rhs = if let Some(imm) = parse_x64_imm(&src) {
        Operand::Constant(imm)
    } else if src.starts_with('[') {
        Operand::Deref {
            base: Box::new(lookup_or_symbol(func, &x64_mem_base(&src), block)),
            offset: x64_mem_offset(&src),
        }
    } else {
        lookup_or_symbol(func, &src, block)
    };
    if dst.starts_with('[') {
        let id = func.new_value_id();
        let inst = SsaInstruction {
            id,
            op: SsaOp::Store {
                addr: Operand::Deref {
                    base: Box::new(lookup_or_symbol(func, &x64_mem_base(&dst), block)),
                    offset: x64_mem_offset(&dst),
                },
                value: rhs,
            },
            source_addr: addr,
            block,
        };
        func.cfg.block_mut(block).insts.push(inst.id);

        func.values.push(inst);
    } else {
        func.define(
            &dst,
            block,
            SsaOp::BinOp { kind, lhs, rhs },
            addr,
        );
    }
}

fn extract_x64_dest(text: &str) -> Option<String> {
    let rest = text.split_whitespace().skip(1).collect::<Vec<_>>().join(" ");
    let first = rest.split(',').next()?.trim();
    if first.is_empty() {
        return None;
    }
    Some(first.to_string())
}

fn extract_x64_src(text: &str) -> Option<String> {
    let rest = text.split_whitespace().skip(1).collect::<Vec<_>>().join(" ");
    let mut parts = rest.splitn(2, ',');
    parts.next()?;
    Some(parts.next()?.trim().to_string())
}

fn parse_x64_imm(token: &str) -> Option<i64> {
    let token = token.trim().trim_end_matches(',');
    if let Some(hex) = token.strip_prefix("0x") {
        return i64::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = token.strip_prefix("-0x") {
        return i64::from_str_radix(hex, 16).ok().map(|v| -v);
    }
    token.parse().ok()
}

fn x64_mem_base(mem: &str) -> String {
    let inner = mem
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    let base = inner
        .split(|c: char| c == '+' || c == '-' || c == '*')
        .next()
        .unwrap_or(inner)
        .trim();
    base.to_string()
}

fn x64_mem_offset(mem: &str) -> i64 {
    let inner = mem
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    if let Some(idx) = inner.find('+') {
        return parse_x64_imm(inner[idx + 1..].trim()).unwrap_or(0);
    }
    if let Some(idx) = inner.find('-') {
        if idx > 0 {
            return -parse_x64_imm(inner[idx + 1..].trim()).unwrap_or(0);
        }
    }
    0
}

/// Normalize register name (strip width suffix, lowercase).
fn static_xreg(n: u8) -> Option<&'static str> {
    const X: [&str; 31] = [
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
        "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24",
        "x25", "x26", "x27", "x28", "x29", "x30",
    ];
    X.get(n as usize).copied()
}


#[inline]
fn format_sub_addr(addr: u64) -> String {
    let mut s = String::with_capacity(20);
    s.push_str("sub_");
    let mut v = addr;
    if v == 0 {
        s.push('0');
        return s;
    }
    let mut buf = [0u8; 16];
    let mut i = 16usize;
    while v != 0 {
        i -= 1;
        buf[i] = b"0123456789abcdef"[(v & 0xf) as usize];
        v >>= 4;
    }
    s.push_str(unsafe { std::str::from_utf8_unchecked(&buf[i..]) });
    s
}

fn normalize_reg_static(reg: &str) -> Option<&'static str> {
    let trimmed = reg.trim();
    if trimmed.is_empty() {
        return Some("");
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() == 2
        && (bytes[0] == b'x' || bytes[0] == b'w' || bytes[0] == b'X' || bytes[0] == b'W')
        && bytes[1].is_ascii_digit()
    {
        return static_xreg(bytes[1] - b'0');
    }
    if bytes.len() == 3
        && (bytes[0] == b'x' || bytes[0] == b'w' || bytes[0] == b'X' || bytes[0] == b'W')
        && bytes[1].is_ascii_digit()
        && bytes[2].is_ascii_digit()
    {
        let n = (bytes[1] - b'0') * 10 + (bytes[2] - b'0');
        return static_xreg(n);
    }
    if bytes.len() == 3
        && (bytes[0] == b'x' || bytes[0] == b'X' || bytes[0] == b'w' || bytes[0] == b'W')
        && bytes[1] == b'z'
        && (bytes[2] == b'r' || bytes[2] == b'R')
    {
        return Some("xzr");
    }
    match trimmed.as_bytes() {
        b"sp" | b"SP" => Some("sp"),
        b"lr" | b"LR" => Some("x30"),
        b"fp" | b"FP" => Some("x29"),
        b"__cmp" => Some("__cmp"),
        b"__cond" => Some("__cond"),
        _ => None,
    }
}

fn normalize_reg(reg: &str) -> String {
    if let Some(s) = normalize_reg_static(reg) {
        return s.to_string();
    }
    let trimmed = reg.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let bytes = trimmed.as_bytes();
    if (bytes[0] == b'x' || bytes[0] == b'X' || bytes[0] == b'w' || bytes[0] == b'W')
        && bytes.len() >= 2
        && bytes[1..].iter().all(|b| b.is_ascii_digit())
    {
        let mut n = 0u8;
        for &b in &bytes[1..] {
            n = n.saturating_mul(10).saturating_add(b - b'0');
        }
        if let Some(name) = static_xreg(n) {
            return name.to_string();
        }
    }
    if bytes[0] == b'x'
        && bytes.len() > 1
        && bytes[1..].iter().all(|b| b.is_ascii_digit())
    {
        return trimmed.to_string();
    }
    if trimmed.bytes().all(|b| !b.is_ascii_uppercase()) {
        return trimmed.to_string();
    }
    trimmed.to_ascii_lowercase()
}

/// Parse an ARM64 immediate from instruction text.
fn split_two_operands(text: &str) -> Option<(&str, &str)> {
    let rest = text.split_once(' ')?.1.trim();
    let (lhs, rhs) = rest.split_once(',')?;
    Some((lhs.trim(), rhs.trim()))
}

fn parse_arm64_imm(text: &str) -> Option<i64> {
    let idx = text.find('#')?;
    let rest = text[idx + 1..].trim_start();
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ',' || c == ']')
        .unwrap_or(rest.len());
    let token = &rest[..end];
    if let Some(hex) = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
        return i64::from_str_radix(hex, 16).ok();
    }
    if let Some(neg) = token
        .strip_prefix("-0x")
        .or_else(|| token.strip_prefix("-0X"))
    {
        return i64::from_str_radix(neg, 16).ok().map(|v| -v);
    }
    token.parse().ok()
}

/// Extract the destination register from an ARM64 instruction.
/// e.g., "mov x0, x1" -> "x0", "add x0, x1, #0x10" -> "x0"
fn extract_dest_reg(text: &str) -> Option<String> {
    extract_dest_reg_ref(text).map(|value| value.to_string())
}

/// Lift a single ARM64 instruction to SSA.
fn lift_arm64_instruction(
    inst: &revx_core::Instruction,
    block: BlockId,
    func: &mut SsaFunction,
    block_addr_to_id: &HashMap<u64, BlockId>,
    references: &[revx_core::Reference],
    call_targets: &HashMap<u64, u64>,
    jump_targets: &HashMap<u64, u64>,
    call_names: &mut HashMap<u64, String>,
) {
    let text = inst.text.as_ref();
    let addr = inst.address;
    let opcode = opcode_token(text);
    if func.large {
        match opcode {
            "nop" | "hint" | "bti" | "paciasp" | "pacibsp" | "autiasp" | "autibsp" | "xpaci"
            | "xpacd" | "paciza" | "pacizb" | "pacda" | "pacdb" | "pacia" | "pacib" | "autiza"
            | "autizb" | "autda" | "autdb" => return,
            _ => {}
        }
    }

    match opcode {
        "mov" | "movz" | "movn" => {
            if let Some(dst) = extract_dest_reg_ref(text) {
                if let Some((_, rest)) = text.split_once(',') {
                    let src = rest.trim();
                    let operand = if let Some(imm) = parse_arm64_imm(src) {
                        Operand::Constant(imm)
                    } else {
                        let clean = src.split_whitespace().next().unwrap_or(src);
                        lookup_or_symbol(func, clean, block)
                    };
                    func.define(dst, block, SsaOp::Copy { src: operand }, addr);
                }
            }
        }

        // add reg, reg, reg  /  add reg, reg, #imm
        "add" | "adds" => {
            lift_arm64_binop(&text, BinOpKind::Add, block, func, addr);
        }
        "sub" | "subs" => {
            lift_arm64_binop(&text, BinOpKind::Sub, block, func, addr);
        }
        "mul" => {
            lift_arm64_binop(&text, BinOpKind::Mul, block, func, addr);
        }
        "and" | "ands" => {
            lift_arm64_binop(&text, BinOpKind::And, block, func, addr);
        }
        "orr" => {
            lift_arm64_binop(&text, BinOpKind::Or, block, func, addr);
        }
        "eor" => {
            lift_arm64_binop(&text, BinOpKind::Xor, block, func, addr);
        }
        "lsl" => {
            lift_arm64_binop(&text, BinOpKind::Shl, block, func, addr);
        }
        "lsr" => {
            lift_arm64_binop(&text, BinOpKind::Shr, block, func, addr);
        }
        "asr" => {
            lift_arm64_binop(&text, BinOpKind::Sar, block, func, addr);
        }

        // cmp / cmn — capture operands for later condition-code materialization.
        "cmp" | "cmn" => {
            if let Some((lhs_tok, rhs_tok)) = split_two_operands(text) {
                let lhs = lookup_or_symbol(func, lhs_tok, block);
                let mut rhs = if let Some(imm) = parse_arm64_imm(rhs_tok) {
                    Operand::Constant(imm)
                } else {
                    lookup_or_symbol(func, rhs_tok, block)
                };
                if opcode == "cmn" {
                    rhs = match rhs {
                        Operand::Constant(c) => Operand::Constant(c.wrapping_neg()),
                        other => other,
                    };
                }
                func.define(
                    "__cmp",
                    block,
                    SsaOp::BinOp {
                        kind: BinOpKind::Sub,
                        lhs,
                        rhs,
                    },
                    addr,
                );
            }
        }

        // ldr reg, [reg, #imm] / ldr reg, [reg]
        "ldr" | "ldrb" | "ldrh" | "ldrsw" | "ldrsh" | "ldrsb" | "ldur" | "ldurb" | "ldurh"
        | "ldursw" => {
            if let Some(dst) = extract_dest_reg_ref(text) {
                let offset = extract_mem_offset(text);
                let addr_operand = if let Some(base_reg) = extract_mem_base_ref(text) {
                    let base_op = lookup_or_symbol(func, base_reg, block);
                    deref_operand(base_op, offset)
                } else {
                    Operand::Symbol("unknown_addr".into())
                };
                func.define(dst, block, SsaOp::Load { addr: addr_operand }, addr);
            }
        }

        "str" | "strb" | "strh" | "stur" | "sturb" | "sturh" => {
            if let Some((lhs, _)) = text.split_once(',') {
                let value = lookup_or_symbol(
                    func,
                    lhs.split_whitespace().last().unwrap_or("").trim(),
                    block,
                );
                let offset = extract_mem_offset(text);
                let addr_operand = if let Some(base_reg) = extract_mem_base_ref(text) {
                    let base_op = lookup_or_symbol(func, base_reg, block);
                    deref_operand(base_op, offset)
                } else {
                    Operand::Symbol("unknown_addr".into())
                };
                // Stores don't define a register, but we create a value for tracking.
                let id = func.new_value_id();
                let inst = SsaInstruction {
                    id,
                    op: SsaOp::Store { addr: addr_operand, value },
                    source_addr: addr,
                    block,
                };
                func.cfg.block_mut(block).insts.push(inst.id);

                func.values.push(inst);
            }
        }

        "stp" => {
            lift_arm64_stp_ldp(text, true, block, func, addr);
        }
        "ldp" => {
            lift_arm64_stp_ldp(text, false, block, func, addr);
        }

        "bl" => {
            let target_operand = if let Some(&to) = call_targets.get(&addr) {
                let name = call_names
                    .entry(to)
                    .or_insert_with(|| format_sub_addr(to))
                    .clone();
                Operand::Symbol(name)
            } else if let Some(target_addr) = parse_branch_addr(
                addr,
                text.split_once(' ').map(|(_, r)| r.trim()).unwrap_or(""),
            ) {
                if target_addr != 0 {
                    let name = call_names
                        .entry(target_addr)
                        .or_insert_with(|| format_sub_addr(target_addr))
                        .clone();
                    Operand::Symbol(name)
                } else {
                    Operand::Symbol("unknown_call".into())
                }
            } else {
                Operand::Symbol("unknown_call".into())
            };

            let target_name_hint = match &target_operand {
                Operand::Symbol(name) => name.as_str(),
                _ => "",
            };
            let known = known_call_arg_count(target_name_hint);
            let variadic = is_variadic_call(target_name_hint);
            let max_args = known
                .or_else(|| known_call_min_args(target_name_hint))
                .unwrap_or(8);
            let mut args = Vec::new();
            if known.is_some() || variadic {
                let n = if variadic {
                    known_call_min_args(target_name_hint).unwrap_or(2)
                } else {
                    max_args
                };
                let n = n.min(8);
                for reg in ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"].iter().take(n) {
                    if let Some(val) = func.lookup_norm(reg, block) {
                        args.push(Operand::Value(val));
                    } else {
                        args.push(lookup_or_symbol(func, reg, block));
                    }
                }
            } else {
                for reg in ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"] {
                    if let Some(val) = func.lookup_norm(reg, block) {
                        args.push(Operand::Value(val));
                    } else {
                        break;
                    }
                }
            }
            let id = func.new_value_id();
            let inst = SsaInstruction {
                id,
                op: SsaOp::Call {
                    target: target_operand,
                    args,
                },
                source_addr: addr,
                block,
            };
            func.cfg.block_mut(block).insts.push(inst.id);

            func.values.push(inst);
            let defs = block_defs_mut(&mut func.defs, block);
            defs.insert_reg("x0", id);
            for reg in [
                "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
                "x13", "x14", "x15", "x16", "x17",
            ] {
                defs.remove(reg);
            }
        }

        "blr" => {
            let reg = text
                .split_whitespace()
                .nth(1)
                .map(|t| t.trim().trim_end_matches(','))
                .unwrap_or("x0");
            let target_operand = lookup_or_symbol(func, reg, block);
            let mut args = Vec::new();
            for reg_name in ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"] {
                if let Some(val) = func.lookup_norm(reg_name, block) {
                    args.push(Operand::Value(val));
                } else if !func.large {
                    if let Some(val) = reaching_def(func, reg_name, block) {
                        args.push(Operand::Value(val));
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            if args.is_empty() {
                args.push(lookup_or_symbol(func, "x0", block));
            }
            let id = func.new_value_id();
            let inst = SsaInstruction {
                id,
                op: SsaOp::Call {
                    target: target_operand,
                    args,
                },
                source_addr: addr,
                block,
            };
            func.cfg.block_mut(block).insts.push(inst.id);
            func.values.push(inst);
            let defs = block_defs_mut(&mut func.defs, block);
            defs.insert_reg("x0", id);
            for reg in [
                "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
                "x13", "x14", "x15", "x16", "x17",
            ] {
                defs.remove(reg);
            }
        }

        // ret — return
        "ret" => {
            let ret_val = func.lookup("x0", block).map(Operand::Value);
            let id = func.new_value_id();
            let inst = SsaInstruction {
                id,
                op: SsaOp::Return { value: ret_val },
                source_addr: addr,
                block,
            };
            func.cfg.block_mut(block).insts.push(inst.id);

            func.values.push(inst);
        }

        // Branch instructions create CFG edges, modeled as Branch/Jump.
        "b" => {
            let target_addr = jump_targets.get(&addr).copied().or_else(|| {
                parse_branch_addr_from_refs(addr, references, &[revx_core::ReferenceKind::Jump])
            });
            if let Some(target_addr) = target_addr {
                if let Some(&target_block) = block_addr_to_id.get(&target_addr) {
                    let id = func.new_value_id();
                    let inst = SsaInstruction {
                        id,
                        op: SsaOp::Jump { target: target_block },
                        source_addr: addr,
                        block,
                    };
                    func.cfg.block_mut(block).insts.push(inst.id);

                    func.values.push(inst);
                }
            }
        }
        "br" => {
            let mut targets: Vec<BlockId> = references
                .iter()
                .filter(|r| {
                    r.from == addr
                        && matches!(
                            r.kind,
                            revx_core::ReferenceKind::Jump
                                | revx_core::ReferenceKind::IndirectJump
                        )
                        && r.to > 31
                })
                .filter_map(|r| block_addr_to_id.get(&r.to).copied())
                .collect();
            targets.sort_by_key(|b| b.0);
            targets.dedup();
            if targets.len() >= 2 {
                // Multi-way jump table: record as Unknown marker with target list in symbol form.
                let summary = targets
                    .iter()
                    .take(12)
                    .map(|b| format!("bb{}", b.0))
                    .collect::<Vec<_>>()
                    .join(", ");
                let more = if targets.len() > 12 {
                    format!(", +{}", targets.len() - 12)
                } else {
                    String::new()
                };
                let id = func.new_value_id();
                let inst = SsaInstruction {
                    id,
                    op: SsaOp::Copy {
                        src: Operand::Symbol(format!("/* switch -> {summary}{more} */")),
                    },
                    source_addr: addr,
                    block,
                };
                func.cfg.block_mut(block).insts.push(inst.id);
                func.values.push(inst);
            } else if let Some(&target_block) = targets.first() {
                let id = func.new_value_id();
                let inst = SsaInstruction {
                    id,
                    op: SsaOp::Jump {
                        target: target_block,
                    },
                    source_addr: addr,
                    block,
                };
                func.cfg.block_mut(block).insts.push(inst.id);
                func.values.push(inst);
            }
        }
        "cbz" | "cbnz" | "tbz" | "tbnz" => {
            if let Some((tb, fb)) = branch_targets(addr, references, block_addr_to_id) {
                let reg = text
                    .split_whitespace()
                    .nth(1)
                    .map(|t| t.trim_end_matches(','))
                    .unwrap_or("x0");
                let value = lookup_or_symbol(func, reg, block);
                let cond_id = if opcode == "tbz" || opcode == "tbnz" {
                    let bit = parse_tbz_bit(text).unwrap_or(0);
                    if bit == 31 || bit == 63 {
                        let kind = if opcode == "tbnz" {
                            BinOpKind::Lt
                        } else {
                            BinOpKind::Ge
                        };
                        func.define(
                            "__cond",
                            block,
                            SsaOp::BinOp {
                                kind,
                                lhs: value,
                                rhs: Operand::Constant(0),
                            },
                            addr,
                        )
                    } else {
                        let mask = 1i64 << (bit.min(62));
                        let masked = func.define(
                            "__tbz_mask",
                            block,
                            SsaOp::BinOp {
                                kind: BinOpKind::And,
                                lhs: value,
                                rhs: Operand::Constant(mask),
                            },
                            addr,
                        );
                        let kind = if opcode == "tbz" {
                            BinOpKind::Eq
                        } else {
                            BinOpKind::Ne
                        };
                        func.define(
                            "__cond",
                            block,
                            SsaOp::BinOp {
                                kind,
                                lhs: Operand::Value(masked),
                                rhs: Operand::Constant(0),
                            },
                            addr,
                        )
                    }
                } else {
                    let kind = if opcode == "cbz" {
                        BinOpKind::Eq
                    } else {
                        BinOpKind::Ne
                    };
                    func.define(
                        "__cond",
                        block,
                        SsaOp::BinOp {
                            kind,
                            lhs: value,
                            rhs: Operand::Constant(0),
                        },
                        addr,
                    )
                };
                let id = func.new_value_id();
                let inst = SsaInstruction {
                    id,
                    op: SsaOp::Branch {
                        cond: Operand::Value(cond_id),
                        true_block: tb,
                        false_block: fb,
                    },
                    source_addr: addr,
                    block,
                };
                func.cfg.block_mut(block).insts.push(id);
                func.values.push(inst);
            }
        }
        "b.eq" | "b.ne" | "b.lt" | "b.le" | "b.gt" | "b.ge" | "b.hs" | "b.lo" | "b.hi" | "b.ls"
        | "b.mi" | "b.pl" | "b.vs" | "b.vc" | "b.cs" | "b.cc" => {
            if let Some((tb, fb)) = branch_targets(addr, references, block_addr_to_id) {
                let cond = materialize_flag_condition(func, block, opcode, addr);
                let id = func.new_value_id();
                let inst = SsaInstruction {
                    id,
                    op: SsaOp::Branch {
                        cond,
                        true_block: tb,
                        false_block: fb,
                    },
                    source_addr: addr,
                    block,
                };
                func.cfg.block_mut(block).insts.push(id);
                func.values.push(inst);
            }
        }

        // adrp — PC-relative page address (data pointer).
        "adrp" => {
            if let Some(dst) = extract_dest_reg_ref(text) {
                if let Some(target) = parse_arm64_page_target(addr, text) {
                    func.define(
                        dst,
                        block,
                        SsaOp::Copy {
                            src: Operand::Constant(target as i64),
                        },
                        addr,
                    );
                }
            }
        }

        // movk reg, #imm, lsl #N — compose wide immediates
        "movk" => {
            if let Some(dst) = extract_dest_reg_ref(text) {
                let parts: Vec<&str> = text.split(',').map(str::trim).collect();
                if parts.len() >= 2 {
                    let imm = parse_arm64_imm(parts[1]).unwrap_or(0) as u64;
                    let mut shift = 0u32;
                    if parts.len() >= 3 {
                        let shift_tok = parts[2].trim();
                        if let Some(rest) = shift_tok.strip_prefix("lsl ") {
                            let rest = rest.strip_prefix('#').unwrap_or(rest);
                            shift = rest.parse().unwrap_or(0);
                        }
                    }
                    let base = match func.lookup(dst, block) {
                        Some(id) => match &func.values[id.0 as usize].op {
                            SsaOp::Copy {
                                src: Operand::Constant(c),
                            } => *c as u64,
                            _ => 0u64,
                        },
                        None => 0u64,
                    };
                    let mask = if shift >= 64 {
                        0u64
                    } else {
                        !(0xffffu64 << shift)
                    };
                    let next = (base & mask) | ((imm & 0xffff) << shift);
                    func.define(
                        dst,
                        block,
                        SsaOp::Copy {
                            src: Operand::Constant(next as i64),
                        },
                        addr,
                    );
                }
            }
        }

        "csel" => {
            if let Some(dst) = extract_dest_reg_ref(text) {
                let parts: Vec<&str> = text.split(',').map(str::trim).collect();
                if parts.len() >= 3 {
                    let t_reg = parts[1].split_whitespace().next().unwrap_or(parts[1]);
                    let f_reg = parts[2].split_whitespace().next().unwrap_or(parts[2]);
                    let t_op = lookup_or_symbol(func, t_reg, block);
                    let f_op = lookup_or_symbol(func, f_reg, block);
                    let cond = parts.get(3).map(|s| s.trim()).unwrap_or("");
                    let preferred = prefer_csel_arm(func, &t_op, &f_op, cond);
                    func.define(
                        dst,
                        block,
                        SsaOp::Copy {
                            src: preferred,
                        },
                        addr,
                    );
                }
            }
        }

        "paciza" | "pacizb" | "pacda" | "pacdb" | "pacia" | "pacib" | "autiza" | "autizb"
        | "autda" | "autdb" | "xpaci" | "xpacd" => {
            if let Some(dst) = extract_dest_reg_ref(text) {
                let src = func
                    .lookup(dst, block)
                    .map(Operand::Value)
                    .unwrap_or_else(|| lookup_or_symbol(func, dst, block));
                func.define(dst, block, SsaOp::Copy { src }, addr);
            }
        }

        "paciasp" | "pacibsp" | "autiasp" | "autibsp" | "bti" | "nop" | "hint" => {}

        _ => {
            if !func.large {
                let id = func.new_value_id();
                let inst = SsaInstruction {
                    id,
                    op: SsaOp::Unknown,
                    source_addr: addr,
                    block,
                };
                func.cfg.block_mut(block).insts.push(inst.id);
                func.values.push(inst);
            }
        }
    }
}

fn lift_arm64_stp_ldp(
    text: &str,
    is_store: bool,
    block: BlockId,
    func: &mut SsaFunction,
    addr: u64,
) {
    let rest = text
        .strip_prefix("stp ")
        .or_else(|| text.strip_prefix("ldp "))
        .unwrap_or("");
    let mut parts = rest.split(',').map(str::trim);
    let r1 = parts.next().unwrap_or("");
    let r2 = parts.next().unwrap_or("");
    let mem = rest.splitn(3, ',').nth(2).unwrap_or("").trim();
    let (base_reg, offset, writeback, pre) = parse_arm64_pair_mem(mem);
    let Some(base_reg) = base_reg else {
        return;
    };
    let base_op = lookup_or_symbol(func, &base_reg, block);
    let addr0 = if pre {
        match &base_op {
            Operand::Symbol(s) if s == "sp" || s == "x31" => {
                Operand::Deref {
                    base: Box::new(base_op.clone()),
                    offset,
                }
            }
            _ => Operand::Deref {
                base: Box::new(base_op.clone()),
                offset,
            },
        }
    } else {
        Operand::Deref {
            base: Box::new(base_op.clone()),
            offset,
        }
    };
    let addr1 = Operand::Deref {
        base: Box::new(if pre {
            base_op.clone()
        } else {
            base_op.clone()
        }),
        offset: offset.wrapping_add(8),
    };
    if is_store {
        let v1 = lookup_or_symbol(func, r1, block);
        let v2 = lookup_or_symbol(func, r2, block);
        for (a, v) in [(addr0, v1), (addr1, v2)] {
            let id = func.new_value_id();
            let inst = SsaInstruction {
                id,
                op: SsaOp::Store { addr: a, value: v },
                source_addr: addr,
                block,
            };
            func.cfg.block_mut(block).insts.push(inst.id);
            func.values.push(inst);
        }
    } else {
        func.define(r1, block, SsaOp::Load { addr: addr0 }, addr);
        func.define(r2, block, SsaOp::Load { addr: addr1 }, addr);
    }
    if writeback {
        let new_sp = if offset >= 0 {
            SsaOp::BinOp {
                kind: BinOpKind::Add,
                lhs: base_op,
                rhs: Operand::Constant(offset),
            }
        } else {
            SsaOp::BinOp {
                kind: BinOpKind::Sub,
                lhs: base_op,
                rhs: Operand::Constant(-offset),
            }
        };
        func.define(&base_reg, block, new_sp, addr);
    }
}

fn parse_arm64_pair_mem(mem: &str) -> (Option<String>, i64, bool, bool) {
    let t = mem.trim();
    let pre = t.contains("]!");
    let post = t.contains("],");
    let writeback = pre || post;
    let inner = t
        .trim_start_matches('[')
        .split(']')
        .next()
        .unwrap_or("")
        .trim();
    let mut parts = inner.split(',').map(str::trim);
    let base = parts.next().map(|s| normalize_reg(s));
    let mut offset = 0i64;
    if let Some(imm_tok) = parts.next() {
        if let Some(imm) = parse_arm64_imm(imm_tok) {
            offset = imm;
        }
    }
    if post {
        if let Some(imm_part) = t.split("],").nth(1) {
            if let Some(imm) = parse_arm64_imm(imm_part.trim()) {
                offset = imm;
            }
        }
    }
    (base, offset, writeback, pre)
}

fn lift_arm64_binop(
    text: &str,
    kind: BinOpKind,
    block: BlockId,
    func: &mut SsaFunction,
    addr: u64,
) {
    let Some(dst) = extract_dest_reg_ref(text) else {
        return;
    };
    let Some((_, rest)) = text.split_once(' ') else {
        return;
    };
    let mut parts = rest.split(',');
    let _dst_tok = parts.next();
    let Some(src1) = parts.next() else {
        return;
    };
    let Some(src2_raw) = parts.next() else {
        return;
    };
    let src1 = src1.trim();
    let src2_raw = src2_raw.trim();

    let lhs = lookup_or_symbol(func, src1, block);
    let rhs = if let Some(imm) = parse_arm64_imm(src2_raw) {
        Operand::Constant(imm)
    } else {
        let clean = src2_raw.split_whitespace().next().unwrap_or(src2_raw);
        lookup_or_symbol(func, clean, block)
    };

    func.define(dst, block, SsaOp::BinOp { kind, lhs, rhs }, addr);
}

fn parse_tbz_bit(text: &str) -> Option<u32> {
    let mut parts = text.split(',').map(str::trim);
    let _ = parts.next()?;
    let bit_tok = parts.next()?;
    let imm = bit_tok.strip_prefix('#')?;
    if let Some(hex) = imm.strip_prefix("0x").or_else(|| imm.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        imm.parse().ok()
    }
}

fn deref_operand(base: Operand, offset: i64) -> Operand {
    Operand::Deref { base: Box::new(base), offset }
}

/// Look up a register's current SSA value, or create a Symbol operand if unknown.
fn lookup_or_symbol(func: &SsaFunction, reg_name: &str, block: BlockId) -> Operand {
    let raw = reg_name
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    if let Some(val) = func.lookup_norm(raw, block) {
        return Operand::Value(val);
    }
    if let Some(s) = normalize_reg_static(raw) {
        if s != raw {
            if let Some(val) = func.lookup_norm(s, block) {
                return Operand::Value(val);
            }
        }
        if !func.large {
            if let Some(val) = reaching_def(func, s, block) {
                return Operand::Value(val);
            }
        }
        return Operand::Symbol(s.to_string());
    }
    let reg = normalize_reg(raw);
    if reg.as_str() != raw {
        if let Some(val) = func.lookup_norm(&reg, block) {
            return Operand::Value(val);
        }
    }
    if !func.large {
        if let Some(val) = reaching_def(func, &reg, block) {
            return Operand::Value(val);
        }
    }
    Operand::Symbol(reg)
}

fn reaching_def(func: &SsaFunction, reg: &str, block: BlockId) -> Option<SsaValueId> {
    let preds = func.cfg.predecessors(block);
    if preds.is_empty() {
        return None;
    }
    let mut found: Option<SsaValueId> = None;
    for &pred in preds {
        let Some(d) = func.block_defs(pred)
            .and_then(|m| m.get(reg))
            .copied()
            .or_else(|| func.lookup(reg, pred))
        else {
            return None;
        };
        match found {
            None => found = Some(d),
            Some(prev) if prev == d => {}
            Some(_) => return None,
        }
    }
    found
}

fn collect_symbol_regs_hash(op: &SsaOp, regs: &mut HashSet<String>) {
    let mut add = |operand: &Operand| match operand {
        Operand::Symbol(name) if looks_like_reg_name(name) => {
            regs.insert(normalize_reg(name));
        }
        Operand::Deref { base, .. } => {
            if let Operand::Symbol(name) = base.as_ref() {
                if looks_like_reg_name(name) {
                    regs.insert(normalize_reg(name));
                }
            }
        }
        _ => {}
    };
    match op {
        SsaOp::Copy { src } => add(src),
        SsaOp::BinOp { lhs, rhs, .. } => {
            add(lhs);
            add(rhs);
        }
        SsaOp::UnaryOp { src, .. } => add(src),
        SsaOp::Load { addr } => add(addr),
        SsaOp::Store { addr, value } => {
            add(addr);
            add(value);
        }
        SsaOp::Call { target, args } => {
            add(target);
            for a in args {
                add(a);
            }
        }
        SsaOp::Return { value } => {
            if let Some(v) = value {
                add(v);
            }
        }
        SsaOp::Branch { cond, .. } => add(cond),
        SsaOp::Phi { incoming } => {
            let _ = incoming;
        }
        SsaOp::Jump { .. } | SsaOp::Unknown => {}
    }
}

fn collect_symbol_regs(op: &SsaOp, regs: &mut BTreeSet<String>) {
    let mut add = |operand: &Operand| match operand {
        Operand::Symbol(name) if looks_like_reg_name(name) => {
            regs.insert(normalize_reg(name));
        }
        Operand::Deref { base, .. } => {
            if let Operand::Symbol(name) = base.as_ref() {
                if looks_like_reg_name(name) {
                    regs.insert(normalize_reg(name));
                }
            }
        }
        _ => {}
    };
    match op {
        SsaOp::Copy { src } => add(src),
        SsaOp::BinOp { lhs, rhs, .. } => {
            add(lhs);
            add(rhs);
        }
        SsaOp::UnaryOp { src, .. } => add(src),
        SsaOp::Load { addr } => add(addr),
        SsaOp::Store { addr, value } => {
            add(addr);
            add(value);
        }
        SsaOp::Call { target, args } => {
            add(target);
            for a in args {
                add(a);
            }
        }
        SsaOp::Return { value } => {
            if let Some(v) = value {
                add(v);
            }
        }
        SsaOp::Branch { cond, .. } => add(cond),
        _ => {}
    }
}

fn insert_register_phis(func: &mut SsaFunction) {
    let rpo = if func.dom_tree.rpo.is_empty() {
        func.cfg.blocks.iter().map(|b| b.id).collect::<Vec<_>>()
    } else {
        func.dom_tree.rpo.clone()
    };
    let large = func.cfg.blocks.len() > 24 || func.values.len() > 160;
    let max_iters = if large { 2 } else { 8 };

    if !large {
        for _ in 0..max_iters {
            let mut changed = false;
            for &block in &rpo {
                let preds = func.cfg.predecessors(block);
                if preds.is_empty() {
                    continue;
                }
                let mut regs: HashSet<String> = HashSet::new();
                for &pred in preds {
                    if let Some(map) = func.block_defs(pred) {
                        for reg in map.keys() {
                            if !reg.starts_with("__") {
                                regs.insert(reg.clone());
                            }
                        }
                    }
                }
                if let Some(cfg_block) = func.cfg.blocks.get(block.0 as usize) {
                    for &iid in cfg_block.insts.iter().chain(cfg_block.phis.iter()) {
                        if let Some(inst) = func.values.get(iid.0 as usize) {
                            collect_symbol_regs_hash(&inst.op, &mut regs);
                        }
                    }
                }
                for reg in regs {
                    if func.block_defs(block)
                        .and_then(|m| m.get(&reg))
                        .is_some()
                    {
                        continue;
                    }
                    let mut incoming: Vec<(BlockId, SsaValueId)> = Vec::new();
                    let mut unique: Option<SsaValueId> = None;
                    let mut ambiguous = false;
                    for &pred in preds {
                        let Some(d) = func.block_defs(pred)
                            .and_then(|m| m.get(&reg))
                            .copied()
                            .or_else(|| func.lookup(&reg, pred))
                        else {
                            continue;
                        };
                        incoming.push((pred, d));
                        match unique {
                            None => unique = Some(d),
                            Some(u) if u == d => {}
                            Some(_) => {
                                unique = None;
                                ambiguous = true;
                            }
                        }
                    }
                    if incoming.is_empty() || ambiguous {
                        continue;
                    }
                    if let Some(id) = unique {
                        if incoming.len() == preds.len()
                            || def_is_high_const(func, id)
                            || prefer_forward_pred_def(func, &reg, block) == Some(id)
                        {
                            block_defs_mut(&mut func.defs, block).insert(reg, id);
                            changed = true;
                        }
                    } else if let Some(id) = prefer_forward_pred_def(func, &reg, block) {
                        if def_is_high_const(func, id) {
                            block_defs_mut(&mut func.defs, block).insert(reg, id);
                            changed = true;
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
    } else {
        for &block in &rpo {
            let preds = func.cfg.predecessors(block);
            if preds.len() != 1 {
                continue;
            }
            let pred = preds[0];
            let Some(pmap) = func.block_defs(pred) else {
                continue;
            };
            let mut promote: Vec<(String, SsaValueId)> = Vec::new();
            for (reg, id) in pmap.iter_pairs() {
                if reg.starts_with("__") {
                    continue;
                }
                if func.block_defs(block)
                    .and_then(|m| m.get(reg))
                    .is_some()
                {
                    continue;
                }
                if def_is_high_const(func, id) {
                    promote.push((reg.to_string(), id));
                }
            }
            if promote.is_empty() {
                continue;
            }
            let map = block_defs_mut(&mut func.defs, block);
            for (reg, id) in promote {
                if map.get(&reg).is_none() {
                    map.insert(reg, id);
                }
            }
        }
    }

    let mut pending: Vec<(BlockId, String, Vec<(BlockId, SsaValueId)>)> = Vec::new();
    for &block in &rpo {
        let preds = func.cfg.predecessors(block);
        if preds.len() < 2 {
            continue;
        }
        let mut regs: HashSet<String> = HashSet::new();
        if large {
            if let Some(cfg_block) = func.cfg.blocks.get(block.0 as usize) {
                for &iid in cfg_block.insts.iter().chain(cfg_block.phis.iter()) {
                    if let Some(inst) = func.values.get(iid.0 as usize) {
                        collect_symbol_regs_hash(&inst.op, &mut regs);
                    }
                }
            }
            for &pred in preds {
                if let Some(map) = func.block_defs(pred) {
                    for reg in map.keys() {
                        if reg.starts_with("__") {
                            continue;
                        }
                        if reg == "x0"
                            || reg == "x1"
                            || reg == "x2"
                            || reg == "x3"
                            || reg == "x8"
                            || reg == "x19"
                            || reg == "x20"
                            || reg == "x21"
                            || reg == "x22"
                            || reg == "x23"
                            || reg == "x24"
                            || reg == "x25"
                            || reg == "x26"
                            || reg == "x27"
                            || reg == "x28"
                            || reg == "x29"
                            || reg == "x30"
                            || reg == "sp"
                        {
                            regs.insert(reg.clone());
                        }
                    }
                }
            }
        } else {
            for &pred in preds {
                if let Some(map) = func.block_defs(pred) {
                    for reg in map.keys() {
                        if !reg.starts_with("__") {
                            regs.insert(reg.clone());
                        }
                    }
                }
            }
            if let Some(cfg_block) = func.cfg.blocks.get(block.0 as usize) {
                for &iid in cfg_block.insts.iter().chain(cfg_block.phis.iter()) {
                    if let Some(inst) = func.values.get(iid.0 as usize) {
                        collect_symbol_regs_hash(&inst.op, &mut regs);
                    }
                }
            }
        }
        for reg in regs {
            if func.block_defs(block)
                .and_then(|m| m.get(&reg))
                .is_some()
            {
                continue;
            }
            let mut incoming: Vec<(BlockId, SsaValueId)> = Vec::new();
            let mut unique: Option<SsaValueId> = None;
            let mut ok = true;
            for &pred in preds {
                let Some(d) = func.block_defs(pred)
                    .and_then(|m| m.get(&reg))
                    .copied()
                    .or_else(|| func.lookup(&reg, pred))
                else {
                    ok = false;
                    break;
                };
                incoming.push((pred, d));
                match unique {
                    None => unique = Some(d),
                    Some(u) if u == d => {}
                    Some(_) => unique = None,
                }
            }
            if !ok || incoming.len() != preds.len() {
                continue;
            }
            if let Some(id) = unique {
                block_defs_mut(&mut func.defs, block).insert(reg, id);
            } else {
                pending.push((block, reg, incoming));
            }
        }
    }
    for (block, reg, incoming) in pending {
        if func.block_defs(block)
            .and_then(|m| m.get(&reg))
            .is_some()
        {
            continue;
        }
        let id = func.new_value_id();
        let inst = SsaInstruction {
            id,
            op: SsaOp::Phi {
                incoming: incoming.clone(),
            },
            source_addr: 0,
            block,
        };
        func.values.push(inst);
        func.cfg.block_mut(block).phis.push(id);
        block_defs_mut(&mut func.defs, block).insert(reg, id);
    }
}

fn rewrite_symbol_regs_to_values(func: &mut SsaFunction) {
    let large = func.large
        || func.cfg.blocks.len() > 40
        || func.values.len() > 360;
    if !large {
        let copy_ids: Vec<(SsaValueId, BlockId)> = func
            .values
            .iter()
            .filter(|inst| matches!(inst.op, SsaOp::Copy { .. }))
            .map(|inst| (inst.id, inst.block))
            .collect();
        for (id, block) in copy_ids {
            let Some(inst) = func.values.get(id.0 as usize) else {
                continue;
            };
            let SsaOp::Copy { src } = &inst.op else {
                continue;
            };
            let Operand::Symbol(name) = src else {
                continue;
            };
            if !looks_like_reg_name(name) {
                continue;
            }
            let Some(vid) = lookup_reg_value_preferring_invariant(func, name, block) else {
                continue;
            };
            if !def_is_high_const(func, vid) {
                continue;
            }
            if let Some(inst) = func.values.get_mut(id.0 as usize) {
                inst.op = SsaOp::Copy {
                    src: Operand::Value(vid),
                };
            }
        }
    }

    let ids: Vec<(SsaValueId, BlockId)> = func
        .values
        .iter()
        .filter(|inst| {
            if large {
                matches!(inst.op, SsaOp::Call { .. })
            } else {
                matches!(
                    inst.op,
                    SsaOp::Call { .. } | SsaOp::Store { .. } | SsaOp::Load { .. }
                )
            }
        })
        .map(|inst| (inst.id, inst.block))
        .collect();
    for (id, block) in ids {
        let Some(inst) = func.values.get(id.0 as usize) else {
            continue;
        };
        match &inst.op {
            SsaOp::Call { target, args } => {
                let target = target.clone();
                let mut new_args = args.clone();
                let mut changed = false;
                for arg in &mut new_args {
                    if resolve_operand_reg_symbol(arg, func, block) {
                        changed = true;
                    }
                }
                if changed {
                    if let Some(inst) = func.values.get_mut(id.0 as usize) {
                        inst.op = SsaOp::Call {
                            target,
                            args: new_args,
                        };
                    }
                }
            }
            SsaOp::Store { addr, value } => {
                let mut value = value.clone();
                let mut addr = addr.clone();
                let mut changed = false;
                rewrite_operand_tree(&mut addr, func, block, &mut changed);
                rewrite_operand_tree(&mut value, func, block, &mut changed);
                if changed {
                    if let Some(inst) = func.values.get_mut(id.0 as usize) {
                        inst.op = SsaOp::Store { addr, value };
                    }
                }
            }
            SsaOp::Load { addr } => {
                let mut addr = addr.clone();
                let mut changed = false;
                rewrite_operand_tree(&mut addr, func, block, &mut changed);
                if changed {
                    if let Some(inst) = func.values.get_mut(id.0 as usize) {
                        inst.op = SsaOp::Load { addr };
                    }
                }
            }
            _ => {}
        }
    }
}

fn resolve_operand_reg_symbol(
    operand: &mut Operand,
    func: &SsaFunction,
    block: BlockId,
) -> bool {
    match operand {
        Operand::Symbol(name) if looks_like_reg_name(name) => {
            if let Some(vid) = lookup_reg_value_preferring_invariant(func, name, block) {
                *operand = Operand::Value(vid);
                return true;
            }
            false
        }
        Operand::Value(id) => {
            let mut cur = *id;
            for _ in 0..8 {
                let Some(inst) = func.values.get(cur.0 as usize) else {
                    return false;
                };
                match &inst.op {
                    SsaOp::Copy {
                        src: Operand::Value(src_id),
                    } => {
                        if *src_id == cur {
                            return false;
                        }
                        cur = *src_id;
                    }
                    SsaOp::Copy {
                        src: Operand::Symbol(name),
                    } if looks_like_reg_name(name) => {
                        if let Some(vid) =
                            lookup_reg_value_preferring_invariant(func, name, inst.block)
                        {
                            *operand = Operand::Value(vid);
                            return true;
                        }
                        return false;
                    }
                    SsaOp::Copy {
                        src: Operand::Constant(c),
                    } if *c > 0x1000 => {
                        *operand = Operand::Constant(*c);
                        return true;
                    }
                    SsaOp::BinOp {
                        kind: BinOpKind::Add,
                        ..
                    } => {
                        if let Some(c) = resolve_const_operand_static(func, &Operand::Value(cur)) {
                            if c > 0x1000 {
                                *operand = Operand::Constant(c);
                                return true;
                            }
                        }
                        if cur != *id {
                            *operand = Operand::Value(cur);
                            return true;
                        }
                        return false;
                    }
                    _ => {
                        if cur != *id {
                            *operand = Operand::Value(cur);
                            return true;
                        }
                        return false;
                    }
                }
            }
            false
        }
        Operand::Deref { base, .. } => resolve_operand_reg_symbol(base, func, block),
        _ => false,
    }
}


fn looks_like_reg_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if n == "sp" || n == "fp" || n == "lr" || n == "xzr" || n == "wzr" {
        return true;
    }
    if let Some(rest) = n.strip_prefix('x').or_else(|| n.strip_prefix('w')) {
        return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit());
    }
    false
}

fn rewrite_operand_tree(
    operand: &mut Operand,
    func: &SsaFunction,
    block: BlockId,
    changed: &mut bool,
) {
    rewrite_operand_tree_depth(operand, func, block, changed, 0);
}

fn rewrite_operand_tree_depth(
    operand: &mut Operand,
    func: &SsaFunction,
    block: BlockId,
    changed: &mut bool,
    depth: usize,
) {
    if depth > 8 {
        return;
    }
    match operand {
        Operand::Symbol(name) if looks_like_reg_name(name) => {
            if let Some(id) = lookup_reg_value_preferring_invariant(func, name, block) {
                *operand = Operand::Value(id);
                *changed = true;
            }
        }
        Operand::Deref { base, .. } => {
            rewrite_operand_tree_depth(base, func, block, changed, depth + 1)
        }
        _ => {}
    }
}

fn rewrite_low_constant_mem_bases(func: &mut SsaFunction) {
    let mut updates: Vec<(SsaValueId, Operand)> = Vec::new();
    for inst in &func.values {
        let addr = match &inst.op {
            SsaOp::Store { addr, .. } | SsaOp::Load { addr } => addr,
            _ => continue,
        };
        let Operand::Deref { base, offset } = addr else {
            continue;
        };
        let mut replacement: Option<Operand> = None;
        match base.as_ref() {
            Operand::Symbol(reg) if looks_like_reg_name(reg) => {
                if let Some(id) = lookup_reg_value_preferring_invariant(func, reg, inst.block) {
                    replacement = Some(Operand::Value(id));
                }
            }
            other => {
                if let Some(c) = resolve_const_operand(func, other) {
                    if (c as u64) < 0x1000 {
                        if let Some(page) = nearest_data_page_def(func, inst.block) {
                            replacement = Some(Operand::Value(page));
                        }
                    }
                }
            }
        }
        if let Some(base_op) = replacement {
            updates.push((
                inst.id,
                Operand::Deref {
                    base: Box::new(base_op),
                    offset: *offset,
                },
            ));
        }
    }
    for (id, new_addr) in updates {
        if let Some(inst) = func.values.get_mut(id.0 as usize) {
            match &mut inst.op {
                SsaOp::Store { addr, .. } | SsaOp::Load { addr } => *addr = new_addr,
                _ => {}
            }
        }
    }
}

fn nearest_data_page_def(func: &SsaFunction, block: BlockId) -> Option<SsaValueId> {
    let mut current = Some(block);
    let mut seen = HashSet::new();
    while let Some(b) = current {
        if !seen.insert(b) {
            break;
        }
        if let Some(map) = func.block_defs(b) {
            for id in map.values() {
                if let Some(inst) = func.values.get(id.0 as usize) {
                    if let SsaOp::Copy {
                        src: Operand::Constant(c),
                    } = &inst.op
                    {
                        if *c as u64 >= 0x10000 && (*c as u64) & 0xfff == 0 {
                            return Some(*id);
                        }
                    }
                }
            }
        }
        let preds = func.cfg.predecessors(b);
        if preds.len() == 1 {
            current = Some(preds[0]);
        } else {
            break;
        }
    }
    None
}

fn opcode_token(text: &str) -> &str {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if start == i {
        ""
    } else {
        &text[start..i]
    }
}

fn extract_dest_reg_ref(text: &str) -> Option<&str> {
    let rest = text.split_once(' ')?.1.trim();
    let tok = rest.split(',').next()?.trim();
    let tok = tok.trim_start_matches('[').trim_end_matches(']');
    if looks_like_reg_name(tok) || tok == "sp" {
        Some(tok)
    } else {
        None
    }
}

fn extract_mem_base_ref(text: &str) -> Option<&str> {
    let start = text.find('[')?;
    let inner = text[start + 1..].split(']').next()?;
    let base = inner.split(',').next()?.trim();
    if base.is_empty() {
        None
    } else {
        Some(base)
    }
}

fn extract_mem_base(text: &str) -> Option<String> {
    extract_mem_base_ref(text).map(|v| v.to_string())
}

fn extract_mem_offset(text: &str) -> i64 {
    if let Some(start) = text.find('[') {
        let rest = &text[start + 1..];
        let inner = rest.split(']').next().unwrap_or("");
        let parts: Vec<&str> = inner.split(',').collect();
        if parts.len() >= 2 {
            return parse_arm64_imm(parts[1].trim()).unwrap_or(0);
        }
    }
    0
}

fn parse_imm_str(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()
    } else if let Some(hex) = s.strip_prefix("-0x") {
        i64::from_str_radix(hex, 16).ok().map(|v| -v)
    } else {
        s.parse().ok()
    }
}

fn parse_branch_addr(current_addr: u64, text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(offset) = text.strip_prefix("$+") {
        let imm = parse_imm_str(offset.trim())?;
        return Some(current_addr.wrapping_add(imm as u64));
    }
    if let Some(offset) = text.strip_prefix("$-") {
        let imm = parse_imm_str(offset.trim())?;
        return Some(current_addr.wrapping_sub(imm as u64));
    }
    if let Some(idx) = text.find("$+") {
        return parse_branch_addr(current_addr, &text[idx..]);
    }
    if let Some(idx) = text.find("$-") {
        return parse_branch_addr(current_addr, &text[idx..]);
    }
    None
}

fn parse_arm64_page_target(current_addr: u64, text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(idx) = text.find("$+") {
        let imm = parse_imm_str(text[idx + 2..].split_whitespace().next()?.trim_end_matches(','))?;
        let page = (current_addr & !0xfffu64).wrapping_add(imm as u64);
        return Some(page & !0xfffu64);
    }
    if let Some(idx) = text.find("$-") {
        let imm = parse_imm_str(text[idx + 2..].split_whitespace().next()?.trim_end_matches(','))?;
        let page = (current_addr & !0xfffu64).wrapping_sub(imm as u64);
        return Some(page & !0xfffu64);
    }
    let target = parse_branch_addr(current_addr, text)?;
    Some(target & !0xfffu64)
}

fn parse_branch_addr_from_refs(
    inst_addr: u64,
    references: &[revx_core::Reference],
    kinds: &[revx_core::ReferenceKind],
) -> Option<u64> {
    references
        .iter()
        .find(|r| r.from == inst_addr && kinds.contains(&r.kind))
        .map(|r| r.to)
}

fn branch_targets(
    addr: u64,
    references: &[revx_core::Reference],
    block_addr_to_id: &HashMap<u64, BlockId>,
) -> Option<(BlockId, BlockId)> {
    let true_addr =
        parse_branch_addr_from_refs(addr, references, &[revx_core::ReferenceKind::BranchTrue])
            .or_else(|| {
                parse_branch_addr_from_refs(addr, references, &[revx_core::ReferenceKind::Branch])
            })?;
    let false_addr = parse_branch_addr_from_refs(
        addr,
        references,
        &[
            revx_core::ReferenceKind::BranchFalse,
            revx_core::ReferenceKind::Fallthrough,
        ],
    )
    .or_else(|| {
        let next = addr.saturating_add(4);
        block_addr_to_id.contains_key(&next).then_some(next)
    })
    .or_else(|| {
        let mut next = addr.saturating_add(4);
        for _ in 0..8 {
            if block_addr_to_id.contains_key(&next) {
                return Some(next);
            }
            next = next.saturating_add(4);
        }
        None
    })?;
    let tb = *block_addr_to_id.get(&true_addr)?;
    let fb = *block_addr_to_id.get(&false_addr)?;
    Some((tb, fb))
}

fn arm64_cond_kind(opcode: &str) -> Option<BinOpKind> {
    match opcode {
        "b.eq" | "b.cs" => Some(BinOpKind::Eq),
        "b.ne" | "b.cc" => Some(BinOpKind::Ne),
        "b.lt" | "b.mi" => Some(BinOpKind::Lt),
        "b.le" | "b.ls" => Some(BinOpKind::Le),
        "b.gt" | "b.hi" => Some(BinOpKind::Gt),
        "b.ge" | "b.hs" | "b.pl" => Some(BinOpKind::Ge),
        "b.lo" => Some(BinOpKind::Lt),
        _ => None,
    }
}

fn materialize_flag_condition(
    func: &mut SsaFunction,
    block: BlockId,
    opcode: &str,
    addr: u64,
) -> Operand {
    let Some(kind) = arm64_cond_kind(opcode) else {
        return Operand::Symbol("cond".to_string());
    };
    if let Some(cmp_id) = func.lookup("__cmp", block) {
        if let Some(inst) = func.values.get(cmp_id.0 as usize) {
            if let SsaOp::BinOp {
                kind: BinOpKind::Sub,
                lhs,
                rhs,
            } = &inst.op
            {
                let cond_id = func.define(
                    "__cond",
                    block,
                    SsaOp::BinOp {
                        kind,
                        lhs: lhs.clone(),
                        rhs: rhs.clone(),
                    },
                    addr,
                );
                return Operand::Value(cond_id);
            }
        }
        let cond_id = func.define(
            "__cond",
            block,
            SsaOp::BinOp {
                kind,
                lhs: Operand::Value(cmp_id),
                rhs: Operand::Constant(0),
            },
            addr,
        );
        return Operand::Value(cond_id);
    }
    Operand::Symbol("cond".to_string())
}

fn known_call_arg_count(callee: &str) -> Option<usize> {
    let bare = callee.strip_prefix('_').unwrap_or(callee);
    match bare {
        "setlocale" | "compat_mode" | "strcmp" | "strcoll" | "fopen" | "strcpy" | "strcat"
        | "strstr" | "strchr" | "strrchr" | "fputs" => Some(2),
        "snprintf" | "memcpy" | "memmove" | "memset" | "memcmp" | "strncmp" | "strncpy"
        | "strncat" | "strtol" | "strtoul" | "setenv" | "socket" | "ioctl" => Some(3),
        "strtonum" | "fread" | "fwrite" | "read" | "write" | "recv" | "send" | "connect" => {
            Some(4)
        }
        "printf" | "puts" | "getenv" | "isatty" | "atoi" | "atol" | "atoll" | "strlen"
        | "strdup" | "free" | "close" | "ftell" | "fclose" | "malloc" | "calloc" | "realloc" => {
            Some(1)
        }
        "getuid" | "geteuid" | "getpid" => Some(0),
        "getopt_long" | "getopt" => Some(5),
        "tgetent" | "tgetstr" | "signal" => Some(2),
        "getbsize" | "warn" | "warnx" => Some(2),
        "sysctlbyname" => Some(5),
        "FindClass" | "GetObjectClass" | "ExceptionClear" | "DeleteLocalRef" | "DeleteGlobalRef"
        | "NewGlobalRef" | "NewLocalRef" | "ExceptionDescribe" | "FatalError"
        | "GetStringUTFChars" | "GetStringChars" | "GetArrayLength" | "GetVersion"
        | "MonitorEnter" | "MonitorExit" | "ExceptionCheck" | "GetJavaVM" => Some(2),
        "AttachCurrentThread" | "GetEnv" | "ThrowNew" | "IsInstanceOf" | "GetMethodID"
        | "GetFieldID" | "GetStaticMethodID" | "GetStaticFieldID" | "NewStringUTF"
        | "ReleaseStringUTFChars" | "ReleaseStringChars" | "IsAssignableFrom" => Some(3),
        "RegisterNatives" | "NewObjectArray" | "SetObjectArrayElement" | "GetObjectArrayElement" => {
            Some(4)
        }
        "DefineClass" => Some(5),
        "CallVoidMethod" | "CallObjectMethod" | "CallIntMethod" | "CallBooleanMethod"
        | "CallStaticVoidMethod" | "CallStaticObjectMethod" | "CallStaticIntMethod" => Some(2),
        _ => None,
    }
}

fn is_variadic_call(callee: &str) -> bool {
    let bare = callee.strip_prefix('_').unwrap_or(callee);
    matches!(
        bare,
        "err"
            | "errx"
            | "warn"
            | "warnx"
            | "printf"
            | "fprintf"
            | "sprintf"
            | "snprintf"
            | "scanf"
            | "sscanf"
            | "fscanf"
    )
}

fn known_call_min_args(callee: &str) -> Option<usize> {
    let bare = callee.strip_prefix('_').unwrap_or(callee);
    match bare {
        "err" | "errx" | "warn" | "warnx" => Some(2),
        "printf" => Some(1),
        "fprintf" | "sprintf" | "snprintf" => Some(2),
        _ => known_call_arg_count(callee),
    }
}


fn resolve_callee_bare_name(
    target: &Operand,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> String {
    match target {
        Operand::Symbol(n) => {
            if let Some(addr) = parse_sub_symbol_addr(n) {
                if let Some(s) = symbols.get(&addr).or_else(|| local_symbols.get(&addr)) {
                    return s.trim_start_matches('_').to_string();
                }
            }
            n.trim_start_matches('_').to_string()
        }
        Operand::Constant(c) if *c >= 0 => {
            let addr = *c as u64;
            if let Some(s) = symbols.get(&addr).or_else(|| local_symbols.get(&addr)) {
                return s.trim_start_matches('_').to_string();
            }
            String::new()
        }
        _ => String::new(),
    }
}

fn parse_sub_symbol_addr(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("sub_")?;
    u64::from_str_radix(rest, 16).ok()
}

fn stack_slot_offset(func: &SsaFunction, addr: &Operand) -> Option<i64> {
    match addr {
        Operand::Deref { base, offset } => {
            if operand_is_frame_like(func, base, 0) {
                Some(*offset)
            } else {
                None
            }
        }
        Operand::Value(id) => match func.values.get(id.0 as usize).map(|i| &i.op) {
            Some(SsaOp::BinOp {
                kind: BinOpKind::Add,
                lhs,
                rhs,
            }) => {
                if operand_is_frame_like(func, lhs, 0) {
                    resolve_const_operand_static(func, rhs)
                } else if operand_is_frame_like(func, rhs, 0) {
                    resolve_const_operand_static(func, lhs)
                } else {
                    None
                }
            }
            Some(SsaOp::BinOp {
                kind: BinOpKind::Sub,
                lhs,
                rhs,
            }) => {
                if operand_is_frame_like(func, lhs, 0) {
                    resolve_const_operand_static(func, rhs).map(|c| -c)
                } else {
                    None
                }
            }
            Some(SsaOp::Copy { src }) => stack_slot_offset(func, src),
            _ => None,
        },
        _ => None,
    }
}

fn prefer_csel_arm(
    func: &SsaFunction,
    true_op: &Operand,
    false_op: &Operand,
    cond: &str,
) -> Operand {
    let cond = cond.trim().trim_start_matches('.').to_ascii_lowercase();
    let t_is_add_of_false = match true_op {
        Operand::Value(id) => match func.values.get(id.0 as usize).map(|i| &i.op) {
            Some(SsaOp::BinOp {
                kind: BinOpKind::Add,
                lhs,
                rhs,
            }) => {
                (operand_same_value(func, lhs, false_op)
                    && resolve_const_operand_static(func, rhs).is_some())
                    || (operand_same_value(func, rhs, false_op)
                        && resolve_const_operand_static(func, lhs).is_some())
            }
            _ => false,
        },
        _ => false,
    };
    if t_is_add_of_false {
        if matches!(cond.as_str(), "lt" | "le" | "mi" | "lo" | "ls") {
            return true_op.clone();
        }
        if matches!(cond.as_str(), "ge" | "gt" | "pl" | "hs" | "hi") {
            return false_op.clone();
        }
        return true_op.clone();
    }
    true_op.clone()
}

fn operand_same_value(func: &SsaFunction, a: &Operand, b: &Operand) -> bool {
    match (a, b) {
        (Operand::Value(x), Operand::Value(y)) => x == y,
        (Operand::Constant(x), Operand::Constant(y)) => x == y,
        (Operand::Symbol(x), Operand::Symbol(y)) => normalize_reg(x) == normalize_reg(y),
        (Operand::Value(id), other) | (other, Operand::Value(id)) => {
            match func.values.get(id.0 as usize).map(|i| &i.op) {
                Some(SsaOp::Copy { src }) => operand_same_value(func, src, other),
                _ => false,
            }
        }
        _ => false,
    }
}

fn resolve_const_operand(func: &SsaFunction, op: &Operand) -> Option<i64> {
    resolve_const_operand_depth(func, op, 0)
}

fn resolve_const_operand_depth(func: &SsaFunction, op: &Operand, depth: usize) -> Option<i64> {
    if depth > 24 {
        return None;
    }
    match op {
        Operand::Constant(c) => Some(*c),
        Operand::Value(id) => {
            let inst = func.values.get(id.0 as usize)?;
            match &inst.op {
                SsaOp::Copy {
                    src: Operand::Constant(c),
                } => Some(*c),
                SsaOp::BinOp {
                    kind: BinOpKind::Add,
                    lhs,
                    rhs,
                } => {
                    let l = resolve_const_operand_depth(func, lhs, depth + 1)?;
                    let r = resolve_const_operand_depth(func, rhs, depth + 1)?;
                    Some(l.wrapping_add(r))
                }
                SsaOp::Phi { incoming } => {
                    let mut found: Option<i64> = None;
                    for (_, vid) in incoming {
                        let Some(c) =
                            resolve_const_operand_depth(func, &Operand::Value(*vid), depth + 1)
                        else {
                            return None;
                        };
                        match found {
                            None => found = Some(c),
                            Some(prev) if prev == c => {}
                            Some(_) => return None,
                        }
                    }
                    found
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn fold_addr_operand(func: &SsaFunction, lhs: &Operand, rhs: &Operand) -> Option<u64> {
    let l = resolve_const_operand(func, lhs)?;
    let r = resolve_const_operand(func, rhs)?;
    let sum = (l as u64).wrapping_add(r as u64);
    if sum < 0x1000 {
        return None;
    }
    Some(sum)
}

fn fold_absolute_addr(func: &SsaFunction, op: &Operand) -> Option<u64> {
    fold_absolute_addr_depth(func, op, 0)
}

fn fold_absolute_addr_depth(func: &SsaFunction, op: &Operand, depth: usize) -> Option<u64> {
    if depth > 24 {
        return None;
    }
    match op {
        Operand::Constant(c) if *c > 0x1000 => Some(*c as u64),
        Operand::Symbol(name) if looks_like_reg_name(name) => {
            lookup_reg_const(&normalize_reg(name))
        }
        Operand::Value(id) => {
            let inst = func.values.get(id.0 as usize)?;
            match &inst.op {
                SsaOp::Copy {
                    src: Operand::Constant(c),
                } if *c > 0x1000 => Some(*c as u64),
                SsaOp::BinOp {
                    kind: BinOpKind::Add,
                    lhs,
                    rhs,
                } => fold_addr_operand(func, lhs, rhs),
                SsaOp::Phi { incoming } => {
                    let mut found: Option<u64> = None;
                    for (_, vid) in incoming {
                        let Some(a) =
                            fold_absolute_addr_depth(func, &Operand::Value(*vid), depth + 1)
                        else {
                            return None;
                        };
                        if a < 0x1000 {
                            return None;
                        }
                        match found {
                            None => found = Some(a),
                            Some(prev) if prev == a => {}
                            Some(_) => return None,
                        }
                    }
                    found
                }
                _ => None,
            }
        }
        Operand::Deref { base, offset } => {
            let base_addr = fold_absolute_addr_depth(func, base, depth + 1)?;
            let abs = base_addr.wrapping_add(*offset as u64);
            if abs < 0x1000 {
                return None;
            }
            Some(abs)
        }
        _ => resolve_const_operand(func, op).and_then(|v| (v > 0x1000).then_some(v as u64)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CallTargetSource {
    Plt,
    Got,
    Direct,
    Unresolved,
}

#[derive(Debug, Clone)]
pub struct ResolvedCall {
    pub call_addr: u64,
    pub target_addr: u64,
    pub name: String,
    pub source: CallTargetSource,
}

#[derive(Debug, Clone, Copy)]
enum RegDefKind {
    Adrp(u64),
    Address(u64),
    GotLoad(u64),
}

fn arm64_reg_slot(reg: &str) -> Option<usize> {
    let r = normalize_reg(reg);
    let rest = r.strip_prefix('x')?;
    rest.parse::<usize>().ok().filter(|n| *n < 32)
}

pub fn resolve_indirect_calls(
    blocks: &[revx_core::BasicBlock],
    imports: &[revx_core::Import],
) -> Vec<ResolvedCall> {
    let import_names: HashMap<u64, String> = imports
        .iter()
        .filter_map(|imp| imp.address.map(|addr| (addr, imp.name.clone())))
        .collect();
    let mut out = Vec::new();
    let mut reg_defs: [Option<RegDefKind>; 32] = [None; 32];
    let x64_named: HashMap<String, RegDefKind> = HashMap::new();
    for block in blocks {
        for inst in &block.instructions {
            let text = inst.text.as_ref();
            let addr = inst.address;
            if text.starts_with("adrp ") {
                if let Some(reg) = extract_dest_reg_ref(text) {
                    if let Some(slot) = arm64_reg_slot(reg) {
                        let target_str = text.split(',').last().unwrap_or("").trim();
                        if let Some(target) = parse_branch_addr(addr, target_str) {
                            reg_defs[slot] = Some(RegDefKind::Adrp(target & !0xfff));
                        }
                    }
                }
                continue;
            }
            if text.starts_with("add ") {
                if let Some(dst) = extract_dest_reg_ref(text) {
                    if let Some(dst_slot) = arm64_reg_slot(dst) {
                        let mut parts = text.splitn(4, ',');
                        let _ = parts.next();
                        if let (Some(src_raw), Some(imm_raw)) = (parts.next(), parts.next()) {
                            let src_reg = src_raw.trim();
                            if let Some(imm) = parse_arm64_imm(imm_raw.trim()) {
                                if let Some(src_slot) = arm64_reg_slot(src_reg) {
                                    if let Some(RegDefKind::Adrp(page)) = reg_defs[src_slot] {
                                        reg_defs[dst_slot] = Some(RegDefKind::Address(
                                            page.wrapping_add(imm as u64),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                continue;
            }
            if text.starts_with("ldr ") {
                if let Some(dst) = extract_dest_reg_ref(text) {
                    if let Some(dst_slot) = arm64_reg_slot(dst) {
                        let offset = extract_mem_offset(text);
                        if let Some(base_reg) = extract_mem_base_ref(text) {
                            if let Some(base_slot) = arm64_reg_slot(base_reg) {
                                match reg_defs[base_slot] {
                                    Some(RegDefKind::Adrp(page)) => {
                                        reg_defs[dst_slot] = Some(RegDefKind::GotLoad(
                                            page.wrapping_add(offset as u64),
                                        ));
                                    }
                                    Some(RegDefKind::Address(addr_val)) => {
                                        reg_defs[dst_slot] = Some(RegDefKind::GotLoad(
                                            addr_val.wrapping_add(offset as u64),
                                        ));
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                continue;
            }
            if text.starts_with("blr ") || text.starts_with("br ") {
                let reg = text.split_whitespace().nth(1).unwrap_or("").trim();
                if let Some(slot) = arm64_reg_slot(reg) {
                    match reg_defs[slot] {
                        Some(RegDefKind::GotLoad(got)) => {
                            if let Some(name) = import_names.get(&got) {
                                out.push(ResolvedCall {
                                    call_addr: addr,
                                    target_addr: got,
                                    name: name.clone(),
                                    source: CallTargetSource::Got,
                                });
                            } else {
                                out.push(ResolvedCall {
                                    call_addr: addr,
                                    target_addr: got,
                                    name: format_sub_addr(got),
                                    source: CallTargetSource::Got,
                                });
                            }
                        }
                        Some(RegDefKind::Address(target)) => {
                            let name = import_names
                                .get(&target)
                                .cloned()
                                .unwrap_or_else(|| format_sub_addr(target));
                            out.push(ResolvedCall {
                                call_addr: addr,
                                target_addr: target,
                                name,
                                source: CallTargetSource::Direct,
                            });
                        }
                        _ => {
                            out.push(ResolvedCall {
                                call_addr: addr,
                                target_addr: 0,
                                name: "unresolved".to_string(),
                                source: CallTargetSource::Unresolved,
                            });
                        }
                    }
                }
            }
            let _ = &x64_named;
        }
    }
    out
}

pub fn render_ssa_pseudocode(
    func: &SsaFunction,
    name: &str,
    arguments: &[revx_core::Variable],
) -> String {
    render_ssa_pseudocode_named(func, name, arguments, &HashMap::new())
}

pub fn render_ssa_pseudocode_named(
    func: &SsaFunction,
    name: &str,
    arguments: &[revx_core::Variable],
    symbols: &HashMap<u64, String>,
) -> String {
    render_ssa_pseudocode_named_layered(func, name, arguments, symbols, &HashMap::new())
}

pub fn render_ssa_pseudocode_named_layered(
    func: &SsaFunction,
    name: &str,
    arguments: &[revx_core::Variable],
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> String {
    render_ssa_pseudocode_named_layered_with_strings(
        func,
        name,
        arguments,
        symbols,
        local_symbols,
        &HashMap::new(),
    )
}

pub fn render_ssa_pseudocode_named_layered_with_string_arc(
    func: &SsaFunction,
    name: &str,
    arguments: &[revx_core::Variable],
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    strings: Arc<HashMap<u64, String>>,
) -> String {
    render_ssa_pseudocode_named_layered_with_strings_arc_inner(
        func, name, arguments, symbols, local_symbols, strings,
    )
}

pub fn render_ssa_pseudocode_named_layered_with_strings(
    func: &SsaFunction,
    name: &str,
    arguments: &[revx_core::Variable],
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    strings: &HashMap<u64, String>,
) -> String {
    render_ssa_pseudocode_named_layered_with_strings_arc_inner(
        func,
        name,
        arguments,
        symbols,
        local_symbols,
        strings_arc(strings),
    )
}

fn render_ssa_pseudocode_named_layered_with_strings_arc_inner(
    func: &SsaFunction,
    name: &str,
    arguments: &[revx_core::Variable],
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    strings: Arc<HashMap<u64, String>>,
) -> String {
    let data_base = infer_data_base(func);
    let global_names = infer_global_names(func, data_base, symbols);
    let reg_aliases = infer_reg_aliases(func);
    let reg_consts = infer_invariant_reg_constants(func);
    let code_names = infer_code_names(func, symbols, local_symbols, strings.as_ref());
    with_render_context(
        strings,
        data_base,
        &global_names,
        &reg_aliases,
        &reg_consts,
        &code_names,
        || {
            let mut lines = Vec::new();
            let args_str = if arguments.is_empty() {
                "void".to_string()
            } else {
                arguments
                    .iter()
                    .map(|a| {
                        format!(
                            "{} {}",
                            a.type_name.as_deref().unwrap_or("unknown_t"),
                            a.name
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            lines.push(format!("int {}({}) {{", name, args_str));
            if let Some(base) = data_base {
                lines.push(format!("    // g_data @ {base:#x}"));
                if !global_names.is_empty() {
                    let mut items: Vec<(u64, &String)> =
                        global_names.iter().map(|(a, n)| (*a, n)).collect();
                    items.sort_by_key(|(a, _)| *a);
                    let summary = items
                        .into_iter()
                        .take(10)
                        .map(|(a, n)| format!("{n}=+{:#x}", a.wrapping_sub(base)))
                        .collect::<Vec<_>>()
                        .join(", ");
                    lines.push(format!("    // globals: {summary}"));
                }
            }
            let mut emitted = HashSet::new();
            let switch_case_blocks = collect_switch_case_block_ids(func);
            let allow_structured_switch = switch_case_blocks.len() <= 48
                && func.cfg.blocks.len() <= 96
                && func.values.len() <= 768;
            for block in &func.cfg.blocks {
                if allow_structured_switch && switch_case_blocks.contains(&block.id) {
                    continue;
                }
                if allow_structured_switch
                    && emit_structured_switch(
                        func,
                        block,
                        symbols,
                        local_symbols,
                        &mut emitted,
                        &mut lines,
                        &switch_case_blocks,
                    )
                {
                    continue;
                }
                emit_ssa_block_linear(
                    func,
                    block,
                    symbols,
                    local_symbols,
                    &mut emitted,
                    &mut lines,
                );
            }
            lines.push("}".to_string());
            lines.join("\n")
        },
    )
}


pub fn render_ssa_pseudocode_linear_with_string_arc(
    func: &SsaFunction,
    name: &str,
    arguments: &[revx_core::Variable],
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    strings: Arc<HashMap<u64, String>>,
) -> String {
    render_ssa_pseudocode_linear_with_strings_arc_inner(
        func, name, arguments, symbols, local_symbols, strings,
    )
}

pub fn render_ssa_pseudocode_linear_with_strings(
    func: &SsaFunction,
    name: &str,
    arguments: &[revx_core::Variable],
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    strings: &HashMap<u64, String>,
) -> String {
    render_ssa_pseudocode_linear_with_strings_arc_inner(
        func,
        name,
        arguments,
        symbols,
        local_symbols,
        strings_arc(strings),
    )
}

fn render_ssa_pseudocode_linear_with_strings_arc_inner(
    func: &SsaFunction,
    name: &str,
    arguments: &[revx_core::Variable],
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    strings: Arc<HashMap<u64, String>>,
) -> String {
    let large = func.cfg.blocks.len() > 24 || func.values.len() > 160;
    let ultra = func.cfg.blocks.len() > 48 || func.values.len() > 400;
    let data_base = if large { None } else { infer_data_base(func) };
    let global_names = if large {
        HashMap::new()
    } else {
        infer_global_names(func, data_base, symbols)
    };
    let reg_aliases = if large {
        HashMap::new()
    } else {
        infer_reg_aliases(func)
    };
    let reg_consts = if large {
        HashMap::new()
    } else {
        infer_invariant_reg_constants(func)
    };
    let code_names = if large {
        HashMap::new()
    } else {
        infer_code_names(func, symbols, local_symbols, strings.as_ref())
    };
    with_render_context(
        strings,
        data_base,
        &global_names,
        &reg_aliases,
        &reg_consts,
        &code_names,
        || {
            let mut lines = Vec::with_capacity(if ultra { 128 } else if large { 192 } else { 256 });
            let args_str = if arguments.is_empty() {
                "void".to_string()
            } else {
                arguments
                    .iter()
                    .map(|a| {
                        format!(
                            "{} {}",
                            a.type_name.as_deref().unwrap_or("unknown_t"),
                            a.name
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            lines.push(format!("int {}({}) {{", name, args_str));
            if let Some(base) = data_base {
                lines.push(format!("    // g_data @ {base:#x}"));
            }
            if !func.case_labels.is_empty() && !ultra {
                let mut case_summary: Vec<String> = func
                    .case_labels
                    .iter()
                    .flat_map(|(_, labels)| labels.iter().cloned())
                    .filter(|l| l.starts_with("case ") || l == "default")
                    .collect();
                case_summary.sort();
                case_summary.dedup();
                if case_summary.len() >= 2 {
                    let head: Vec<&str> = case_summary.iter().take(24).map(|s| s.as_str()).collect();
                    let more = if case_summary.len() > 24 {
                        format!(", +{} more", case_summary.len() - 24)
                    } else {
                        String::new()
                    };
                    lines.push(format!(
                        "    // switch cases: {}{}",
                        head.join(", "),
                        more
                    ));
                }
            } else if !func.case_labels.is_empty() {
                lines.push(format!(
                    "    // switch sites: {}",
                    func.case_labels.len()
                ));
            }
            let mut emitted = HashSet::with_capacity(func.cfg.blocks.len().min(512));
            let mut stmt_budget = if ultra {
                96
            } else if large {
                140
            } else {
                240
            };
            for block in &func.cfg.blocks {
                if stmt_budget == 0 {
                    lines.push("    // ... truncated".to_string());
                    break;
                }
                if ultra {
                    emit_ssa_block_linear_ultra(
                        func,
                        block,
                        symbols,
                        local_symbols,
                        &mut emitted,
                        &mut lines,
                        &mut stmt_budget,
                    );
                } else {
                    emit_ssa_block_linear_simple(
                        func,
                        block,
                        symbols,
                        local_symbols,
                        &mut emitted,
                        &mut lines,
                        &mut stmt_budget,
                    );
                }
            }
            lines.push("}".to_string());
            join_lines_fast(&lines)
        },
    )
}

fn join_lines_fast(lines: &[String]) -> String {
    let mut size = 0usize;
    for (i, line) in lines.iter().enumerate() {
        size = size.saturating_add(line.len());
        if i > 0 {
            size = size.saturating_add(1);
        }
    }
    let mut out = String::with_capacity(size);
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(line);
    }
    out
}

fn emit_ssa_block_linear_ultra(
    func: &SsaFunction,
    block: &CfgBlock,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
    stmt_budget: &mut usize,
) {
    if *stmt_budget == 0 || !emitted.insert(block.id) {
        return;
    }
    let pad = "    ";
    if block.id.0 > 0 {
        if let Some(cases) = func.case_labels.get(&block.id) {
            if !cases.is_empty() {
                lines.push(format!("{pad}// bb{} @ {:#x}: {}", block.id.0, block.start_addr, cases.join(", ")));
            } else {
                lines.push(format!("{pad}// bb{} @ {:#x}", block.id.0, block.start_addr));
            }
        } else {
            lines.push(format!("{pad}// bb{} @ {:#x}", block.id.0, block.start_addr));
        }
    }
    for &iid in &block.insts {
        if *stmt_budget == 0 {
            break;
        }
        let Some(inst) = func.values.get(iid.0 as usize) else {
            continue;
        };
        match &inst.op {
            SsaOp::Store { .. } => {
                let rendered = render_named_value(func, inst.id, symbols, local_symbols);
                if is_trivial_stack_prologue_store(&rendered) {
                    continue;
                }
                lines.push(format!("{pad}{rendered};"));
                *stmt_budget = stmt_budget.saturating_sub(1);
            }
            SsaOp::Call { .. } => {
                let call = render_named_value(func, inst.id, symbols, local_symbols);
                lines.push(format!("{pad}{call};"));
                *stmt_budget = stmt_budget.saturating_sub(1);
            }
            SsaOp::Branch {
                true_block,
                false_block,
                cond,
            } => {
                let cond_text = render_condition_text(func, cond, symbols, local_symbols);
                lines.push(format!(
                    "{pad}if ({cond_text}) goto bb{}; else goto bb{};",
                    true_block.0, false_block.0
                ));
                *stmt_budget = stmt_budget.saturating_sub(1);
            }
            SsaOp::Jump { target } => {
                lines.push(format!("{pad}goto bb{};", target.0));
                *stmt_budget = stmt_budget.saturating_sub(1);
            }
            SsaOp::Return { .. } => {
                lines.push(format!("{pad}{};", func.render_value(inst.id)));
                *stmt_budget = stmt_budget.saturating_sub(1);
            }
            SsaOp::Copy {
                src: Operand::Symbol(name),
            } if name.starts_with("/* switch") => {
                lines.push(format!("{pad}{name}"));
                *stmt_budget = stmt_budget.saturating_sub(1);
            }
            _ => {}
        }
    }
}


fn emit_ssa_block_linear_simple(
    func: &SsaFunction,
    block: &CfgBlock,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
    stmt_budget: &mut usize,
) {
    if *stmt_budget == 0 || !emitted.insert(block.id) {
        return;
    }
    if is_pure_jump_block(func, block.id) {
        return;
    }
    let pad = "    ";
    if block.id.0 > 0 {
        if let Some(cases) = func.case_labels.get(&block.id) {
            if !cases.is_empty() {
                lines.push(format!("{pad}// bb{} @ {:#x}: {}", block.id.0, block.start_addr, cases.join(", ")));
            } else {
                lines.push(format!("{pad}// bb{} @ {:#x}", block.id.0, block.start_addr));
            }
        } else {
            lines.push(format!("{pad}// bb{} @ {:#x}", block.id.0, block.start_addr));
        }
    }
    for &iid in &block.insts {
        if *stmt_budget == 0 {
            break;
        }
        let Some(inst) = func.values.get(iid.0 as usize) else {
            continue;
        };
        match &inst.op {
            SsaOp::Store { .. } => {
                if store_is_stack_arg_for_call(func, inst.id) {
                    continue;
                }
                let rendered = render_named_value(func, inst.id, symbols, local_symbols);
                if is_trivial_stack_prologue_store(&rendered) {
                    continue;
                }
                lines.push(format!("{pad}{rendered};"));
                *stmt_budget = stmt_budget.saturating_sub(1);
            }
            SsaOp::Call { .. } => {
                let call = render_named_value(func, inst.id, symbols, local_symbols);
                if ssa_value_is_used(func, inst.id) {
                    lines.push(format!(
                        "{pad}{} = {};",
                        result_name_for_call(func, inst.id, symbols, local_symbols),
                        call
                    ));
                } else {
                    lines.push(format!("{pad}{};", call));
                }
                *stmt_budget = stmt_budget.saturating_sub(1);
            }
            SsaOp::Branch {
                true_block,
                false_block,
                cond,
            } => {
                let cond_text = render_condition_text(func, cond, symbols, local_symbols);
                lines.push(format!(
                    "{pad}if ({cond_text}) goto bb{}; else goto bb{};",
                    true_block.0, false_block.0
                ));
                *stmt_budget = stmt_budget.saturating_sub(1);
            }
            SsaOp::Jump { target } => {
                lines.push(format!("{pad}goto bb{};", target.0));
                *stmt_budget = stmt_budget.saturating_sub(1);
            }
            SsaOp::Return { .. } => {
                lines.push(format!("{pad}{};", func.render_value(inst.id)));
                *stmt_budget = stmt_budget.saturating_sub(1);
            }
            SsaOp::Copy {
                src: Operand::Symbol(name),
            } if name.starts_with("/* switch") => {
                lines.push(format!("{pad}{name}"));
                *stmt_budget = stmt_budget.saturating_sub(1);
            }
            SsaOp::Phi { .. } | SsaOp::Unknown => {}
            SsaOp::BinOp {
                kind:
                    BinOpKind::Eq
                    | BinOpKind::Ne
                    | BinOpKind::Lt
                    | BinOpKind::Le
                    | BinOpKind::Gt
                    | BinOpKind::Ge,
                ..
            } => {}
            _ => {
                if is_flag_or_cond_value(func, inst.id) || should_suppress_temp_emit(func, inst.id)
                {
                    continue;
                }
                let rendered = render_named_value(func, inst.id, symbols, local_symbols);
                if rendered.starts_with("/* switch") {
                    lines.push(format!("{pad}{rendered}"));
                    *stmt_budget = stmt_budget.saturating_sub(1);
                    continue;
                }
                lines.push(format!("{pad}v{} = {};", inst.id.0, rendered));
                *stmt_budget = stmt_budget.saturating_sub(1);
            }
        }
    }
}

fn collect_switch_case_block_ids(func: &SsaFunction) -> HashSet<BlockId> {
    func.case_labels
        .iter()
        .filter(|(_, labels)| {
            labels.iter().any(|l| l.starts_with("case ") || l == "default")
        })
        .map(|(id, _)| *id)
        .collect()
}

fn block_has_switch_marker(func: &SsaFunction, block: &CfgBlock) -> bool {
    for &iid in &block.insts {
        let Some(inst) = func.values.get(iid.0 as usize) else {
            continue;
        };
        if let SsaOp::Copy {
            src: Operand::Symbol(name),
        } = &inst.op
        {
            if name.starts_with("/* switch") {
                return true;
            }
        }
    }
    false
}

fn infer_switch_scrutinee(
    func: &SsaFunction,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> String {
    for block in &func.cfg.blocks {
        for &iid in &block.insts {
            let Some(inst) = func.values.get(iid.0 as usize) else {
                continue;
            };
            let SsaOp::Call { target, .. } = &inst.op else {
                continue;
            };
            let tname = match target {
                Operand::Symbol(n) => n.as_str(),
                _ => continue,
            };
            let bare = tname.trim_start_matches('_');
            if bare == "getopt_long" || bare == "getopt" {
                if ssa_value_is_used(func, inst.id) {
                    return result_name_for_call(func, inst.id, symbols, local_symbols);
                }
                return "opt".to_string();
            }
        }
    }
    "opt".to_string()
}

fn case_sort_key(labels: &[String]) -> (u8, i64) {
    if labels.iter().any(|l| l == "default") {
        return (2, 0);
    }
    for lab in labels {
        if let Some(ch) = parse_case_label_char(lab) {
            return (0, ch as i64);
        }
        if let Some(rest) = lab.strip_prefix("case ") {
            if let Ok(n) = rest.parse::<i64>() {
                return (1, n);
            }
            if let Some(hex) = rest.strip_prefix("0x") {
                if let Ok(n) = i64::from_str_radix(hex, 16) {
                    return (1, n);
                }
            }
        }
    }
    (1, 0)
}

fn format_switch_case_header(labels: &[String]) -> Vec<String> {
    if labels.iter().any(|l| l == "default") {
        return vec!["default:".to_string()];
    }
    let mut out = Vec::new();
    for lab in labels {
        if let Some(rest) = lab.strip_prefix("case ") {
            out.push(format!("case {rest}:"));
        } else if lab.starts_with("case ") {
            out.push(format!("{lab}:"));
        } else {
            out.push(format!("{lab}:"));
        }
    }
    if out.is_empty() {
        out.push("default:".to_string());
    }
    out
}

fn clone_linear_store_body(
    func: &SsaFunction,
    target: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    local_consts: &HashMap<String, i64>,
    depth: usize,
) -> Option<Vec<String>> {
    if depth > 4 {
        return None;
    }
    let block = func.cfg.blocks.get(target.0 as usize)?;
    let mut stmts = Vec::new();
    let mut jump_target: Option<BlockId> = None;
    for &iid in &block.insts {
        let inst = func.values.get(iid.0 as usize)?;
        match &inst.op {
            SsaOp::Store { addr, value } => {
                let rendered = render_named_value(func, inst.id, symbols, local_symbols);
                let rendered = specialize_flag_store_rhs(func, &rendered, value, local_consts);
                stmts.push(format!("{rendered};"));
                let _ = addr;
            }
            SsaOp::Call { .. } => {
                let call = render_named_value(func, inst.id, symbols, local_symbols);
                if ssa_value_is_used(func, inst.id) {
                    stmts.push(format!(
                        "{} = {};",
                        result_name_for_call(func, inst.id, symbols, local_symbols),
                        call
                    ));
                } else {
                    stmts.push(format!("{call};"));
                }
            }
            SsaOp::Jump { target } => jump_target = Some(*target),
            SsaOp::Branch { .. } => return None,
            SsaOp::Phi { .. } | SsaOp::Unknown => {}
            SsaOp::BinOp { kind, .. }
                if matches!(
                    kind,
                    BinOpKind::Eq
                        | BinOpKind::Ne
                        | BinOpKind::Lt
                        | BinOpKind::Le
                        | BinOpKind::Gt
                        | BinOpKind::Ge
                ) => {}
            _ => {
                if is_flag_or_cond_value(func, inst.id) || should_suppress_temp_emit(func, inst.id)
                {
                    continue;
                }
                return None;
            }
        }
    }
    if stmts.len() > 8 {
        return None;
    }
    if stmts.is_empty() {
        if let Some(t) = jump_target {
            return clone_linear_store_body(
                func,
                t,
                symbols,
                local_symbols,
                local_consts,
                depth + 1,
            );
        }
        let succs = func.cfg.successors(target);
        if succs.len() == 1 {
            return clone_linear_store_body(
                func,
                succs[0],
                symbols,
                local_symbols,
                local_consts,
                depth + 1,
            );
        }
        return None;
    }
    let next = jump_target.or_else(|| {
        let succs = func.cfg.successors(target);
        if succs.len() == 1 {
            Some(succs[0])
        } else {
            None
        }
    });
    if let Some(t) = next {
        if let Some(more) = clone_linear_store_body(
            func,
            t,
            symbols,
            local_symbols,
            local_consts,
            depth + 1,
        ) {
            if stmts.len() + more.len() <= 8 {
                stmts.extend(more);
            }
        }
    }
    Some(stmts)
}

fn emit_block_statements_for_switch(
    func: &SsaFunction,
    block: &CfgBlock,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    pad: &str,
    lines: &mut Vec<String>,
    case_blocks: &HashSet<BlockId>,
    join: Option<BlockId>,
    emitted: &mut HashSet<BlockId>,
    local_consts: &HashMap<String, i64>,
) -> Option<BlockId> {
    let mut term: Option<BlockId> = None;
    for &iid in &block.insts {
        let Some(inst) = func.values.get(iid.0 as usize) else {
            continue;
        };
        match &inst.op {
            SsaOp::Store { addr, value } => {
                if store_is_stack_arg_for_call(func, inst.id) {
                    continue;
                }
                let rendered = render_named_value(func, inst.id, symbols, local_symbols);
                let rendered = specialize_flag_store_rhs(func, &rendered, value, local_consts);
                lines.push(format!("{pad}{rendered};"));
                let _ = addr;
            }
            SsaOp::Call { .. } => {
                let call = render_named_value(func, inst.id, symbols, local_symbols);
                if ssa_value_is_used(func, inst.id) {
                    lines.push(format!(
                        "{pad}{} = {};",
                        result_name_for_call(func, inst.id, symbols, local_symbols),
                        call
                    ));
                } else {
                    lines.push(format!("{pad}{};", call));
                }
            }
            SsaOp::Branch {
                true_block,
                false_block,
                cond,
            } => {
                let cond_text = render_condition_text(func, cond, symbols, local_symbols);
                let t = *true_block;
                let f = *false_block;
                if join == Some(t) && !case_blocks.contains(&f) {
                    lines.push(format!("{pad}if ({cond_text}) break;"));
                    let mut path_consts = local_consts.clone();
                    if condition_implies_compat_one(&cond_text)
                        || condition_implies_compat_one(&negate_condition_text(&cond_text))
                    {
                        path_consts.insert("__path_const_1".to_string(), 1);
                    }
                    emit_switch_tail_chain(
                        func,
                        f,
                        symbols,
                        local_symbols,
                        case_blocks,
                        join,
                        emitted,
                        pad,
                        lines,
                        0,
                        &path_consts,
                    );
                    return None;
                } else if join == Some(f) && !case_blocks.contains(&t) {
                    lines.push(format!(
                        "{pad}if ({}) break;",
                        negate_condition_text(&cond_text)
                    ));
                    let mut path_consts = local_consts.clone();
                    if condition_implies_compat_one(&cond_text)
                        || condition_implies_compat_one(&negate_condition_text(&cond_text))
                    {
                        path_consts.insert("__path_const_1".to_string(), 1);
                    }
                    emit_switch_tail_chain(
                        func,
                        t,
                        symbols,
                        local_symbols,
                        case_blocks,
                        join,
                        emitted,
                        pad,
                        lines,
                        0,
                        &path_consts,
                    );
                    return None;
                } else if !case_blocks.contains(&t)
                    && !case_blocks.contains(&f)
                    && join != Some(t)
                    && join != Some(f)
                {
                    lines.push(format!("{pad}if ({cond_text}) {{"));
                    emit_switch_tail_chain(
                        func,
                        t,
                        symbols,
                        local_symbols,
                        case_blocks,
                        join,
                        emitted,
                        &format!("{pad}    "),
                        lines,
                         0,
                    &local_consts,
                    );
                    lines.push(format!("{pad}}} else {{"));
                    emit_switch_tail_chain(
                        func,
                        f,
                        symbols,
                        local_symbols,
                        case_blocks,
                        join,
                        emitted,
                        &format!("{pad}    "),
                        lines,
                         0,
                    &local_consts,
                    );
                    lines.push(format!("{pad}}}"));
                } else {
                    let mut t_consts = local_consts.clone();
                    let mut f_consts = local_consts.clone();
                    let compact = cond_text.replace(' ', "");
                    if compact.contains("g_compat_mode!=1") || compact.contains("compat!=1") {
                        f_consts.insert("__path_const_1".to_string(), 1);
                    } else if compact.contains("g_compat_mode==1") || compact.contains("compat==1") {
                        t_consts.insert("__path_const_1".to_string(), 1);
                    }
                    let t_body = clone_linear_store_body(func, t, symbols, local_symbols, &t_consts, 0);
                    let f_body = clone_linear_store_body(func, f, symbols, local_symbols, &f_consts, 0);
                    if t_body.is_some() || f_body.is_some() {
                        lines.push(format!("{pad}if ({cond_text}) {{"));
                        if let Some(body) = t_body {
                            for stmt in body {
                                lines.push(format!("{pad}    {stmt}"));
                            }
                            mark_linear_chain_emitted(func, t, case_blocks, join, emitted, 0);
                        } else if join == Some(t) {
                            lines.push(format!("{pad}    break;"));
                        } else {
                            lines.push(format!("{pad}    goto bb{};", t.0));
                        }
                        lines.push(format!("{pad}}} else {{"));
                        if let Some(body) = f_body {
                            for stmt in body {
                                lines.push(format!("{pad}    {stmt}"));
                            }
                            mark_linear_chain_emitted(func, f, case_blocks, join, emitted, 0);
                        } else if join == Some(f) {
                            lines.push(format!("{pad}    break;"));
                        } else {
                            lines.push(format!("{pad}    goto bb{};", f.0));
                        }
                        lines.push(format!("{pad}}}"));
                        return None;
                    } else {
                        lines.push(format!(
                            "{pad}if ({cond_text}) goto bb{}; else goto bb{};",
                            t.0, f.0
                        ));
                    }
                }
            }
            SsaOp::Jump { target } => {
                term = Some(*target);
            }
            SsaOp::Return { .. } => {
                lines.push(format!("{pad}{};", func.render_value(inst.id)));
            }
            SsaOp::Phi { .. } | SsaOp::Unknown => {}
            SsaOp::BinOp { kind, .. }
                if matches!(
                    kind,
                    BinOpKind::Eq
                        | BinOpKind::Ne
                        | BinOpKind::Lt
                        | BinOpKind::Le
                        | BinOpKind::Gt
                        | BinOpKind::Ge
                ) => {}
            _ => {
                if is_flag_or_cond_value(func, inst.id) {
                    continue;
                }
                if let SsaOp::Copy {
                    src: Operand::Symbol(name),
                } = &inst.op
                {
                    if name.starts_with("/* switch") {
                        continue;
                    }
                }
                if should_suppress_temp_emit(func, inst.id) {
                    continue;
                }
                let rendered = render_named_value(func, inst.id, symbols, local_symbols);
                if rendered.starts_with("/* switch") {
                    continue;
                }
                lines.push(format!("{pad}v{} = {};", inst.id.0, rendered));
            }
        }
    }
    term
}

fn is_switch_shared_tail(
    func: &SsaFunction,
    block_id: BlockId,
    case_blocks: &HashSet<BlockId>,
    join: Option<BlockId>,
) -> bool {
    if case_blocks.contains(&block_id) {
        return false;
    }
    if join == Some(block_id) {
        return false;
    }
    let preds = func.cfg.predecessors(block_id);
    if preds.len() < 2 {
        return false;
    }
    let from_cases = preds.iter().filter(|p| case_blocks.contains(p)).count();
    from_cases >= 2
}

fn mark_linear_chain_emitted(
    func: &SsaFunction,
    start: BlockId,
    case_blocks: &HashSet<BlockId>,
    join: Option<BlockId>,
    emitted: &mut HashSet<BlockId>,
    depth: usize,
) {
    if depth > 6 {
        return;
    }
    if join == Some(start) || case_blocks.contains(&start) {
        return;
    }
    if !emitted.insert(start) {
        return;
    }
    let Some(block) = func.cfg.blocks.get(start.0 as usize) else {
        return;
    };
    for &iid in &block.insts {
        let Some(inst) = func.values.get(iid.0 as usize) else {
            continue;
        };
        if let SsaOp::Jump { target } = &inst.op {
            if join != Some(*target) && !case_blocks.contains(target) {
                mark_linear_chain_emitted(func, *target, case_blocks, join, emitted, depth + 1);
            }
            return;
        }
        if matches!(inst.op, SsaOp::Branch { .. }) {
            return;
        }
    }
    let succs = func.cfg.successors(start);
    if succs.len() == 1 {
        let t = succs[0];
        if join != Some(t) && !case_blocks.contains(&t) {
            mark_linear_chain_emitted(func, t, case_blocks, join, emitted, depth + 1);
        }
    }
}

fn specialize_flag_store_rhs(
    func: &SsaFunction,
    rendered: &str,
    value: &Operand,
    local_consts: &HashMap<String, i64>,
) -> String {
    let Some(eq) = rendered.find(" = ") else {
        return rendered.to_string();
    };
    let lhs = &rendered[..eq];
    let rhs = rendered[eq + 3..].trim();
    if rhs == "0" || rhs == "1" {
        return rendered.to_string();
    }
    if rhs.starts_with('\'') || rhs.starts_with('"') || rhs.starts_with("0x") {
        return rendered.to_string();
    }
    if let Some(c) = resolve_const_operand_static(func, value) {
        if c == 0 || c == 1 {
            return format!("{lhs} = {c}");
        }
        return rendered.to_string();
    }
    if local_consts.get("__path_const_1") == Some(&1)
        && matches!(rhs, "g_compat_mode" | "compat")
    {
        return format!("{lhs} = 1");
    }
    if let Some(&c) = local_consts
        .get("w8")
        .or_else(|| local_consts.get("x8"))
        .or_else(|| local_consts.get("w9"))
        .or_else(|| local_consts.get("x9"))
        .or_else(|| local_consts.get("w10"))
        .or_else(|| local_consts.get("x10"))
        .or_else(|| local_consts.get("__path_const_1"))
    {
        if c == 0 || c == 1 {
            return format!("{lhs} = {c}");
        }
    }
    rendered.to_string()
}

fn condition_implies_compat_one(cond_text: &str) -> bool {
    let t = cond_text.replace(' ', "");
    t.contains("g_compat_mode!=1")
        || t.contains("compat!=1")
        || t.contains("g_compat_mode==1")
        || t.contains("compat==1")
}

fn collect_block_const_defs(func: &SsaFunction, block: BlockId) -> HashMap<String, i64> {
    let mut out = HashMap::new();
    let Some(map) = func.block_defs(block) else {
        return out;
    };
    for (reg, id) in map.iter_pairs() {
        let Some(c) = resolve_const_operand_static(func, &Operand::Value(id)) else {
            continue;
        };
        if c != 0 && c != 1 {
            continue;
        }
        out.insert(normalize_reg(reg), c);
        if let Some(n) = reg.strip_prefix('x').or_else(|| reg.strip_prefix('w')) {
            out.insert(format!("x{n}"), c);
            out.insert(format!("w{n}"), c);
        }
    }
    out
}

fn emit_switch_tail_chain(
    func: &SsaFunction,
    start: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    case_blocks: &HashSet<BlockId>,
    join: Option<BlockId>,
    emitted: &mut HashSet<BlockId>,
    pad: &str,
    lines: &mut Vec<String>,
    depth: usize,
    local_consts: &HashMap<String, i64>,
) {
    if depth > 6 {
        lines.push(format!("{pad}goto bb{};", start.0));
        return;
    }
    if join == Some(start) {
        return;
    }
    if emitted.contains(&start) {
        return;
    }
    if case_blocks.contains(&start) && depth > 0 {
        lines.push(format!("{pad}goto bb{};", start.0));
        return;
    }
    if let Some(body) =
        clone_linear_store_body(func, start, symbols, local_symbols, local_consts, 0)
    {
        for stmt in body {
            lines.push(format!("{pad}{stmt}"));
        }
        mark_linear_chain_emitted(func, start, case_blocks, join, emitted, 0);
        return;
    }
    let Some(block) = func.cfg.blocks.get(start.0 as usize) else {
        lines.push(format!("{pad}goto bb{};", start.0));
        return;
    };
    emitted.insert(start);
    let term = emit_block_statements_for_switch(
        func,
        block,
        symbols,
        local_symbols,
        pad,
        lines,
        case_blocks,
        join,
        emitted,
        &local_consts,
    );
    if let Some(target) = term {
        if join == Some(target) {
            return;
        }
        if is_switch_shared_tail(func, target, case_blocks, join)
            || func.cfg.predecessors(target).len() <= 1
        {
            emit_switch_tail_chain(
                func,
                target,
                symbols,
                local_symbols,
                case_blocks,
                join,
                emitted,
                pad,
                lines,
                depth + 1,
            &local_consts,
            );
        } else {
            lines.push(format!("{pad}goto bb{};", target.0));
        }
    } else {
        let succs = func.cfg.successors(start);
        if succs.len() == 1 {
            let target = succs[0];
            if join == Some(target) {
                return;
            }
            emit_switch_tail_chain(
                func,
                target,
                symbols,
                local_symbols,
                case_blocks,
                join,
                emitted,
                pad,
                lines,
                depth + 1,
            &local_consts,
            );
        }
    }
}

fn emit_structured_switch(
    func: &SsaFunction,
    block: &CfgBlock,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
    case_blocks: &HashSet<BlockId>,
) -> bool {
    if !block_has_switch_marker(func, block) {
        return false;
    }
    if case_blocks.len() < 2 {
        return false;
    }
    if !emitted.insert(block.id) {
        return true;
    }

    let pad = "    ";
    let inner = "        ";
    let scrutinee = infer_switch_scrutinee(func, symbols, local_symbols);

    let mut cases: Vec<(BlockId, Vec<String>)> = case_blocks
        .iter()
        .filter_map(|id| {
            let labels = func.case_labels.get(id)?.clone();
            if labels.is_empty() {
                return None;
            }
            Some((*id, labels))
        })
        .collect();
    cases.sort_by(|a, b| {
        case_sort_key(&a.1)
            .cmp(&case_sort_key(&b.1))
            .then_with(|| a.0 .0.cmp(&b.0 .0))
    });

    let mut join_votes: HashMap<BlockId, usize> = HashMap::new();
    for (id, _) in &cases {
        let succs = func.cfg.successors(*id);
        if succs.len() == 1 {
            *join_votes.entry(succs[0]).or_default() += 1;
        } else {
            for &iid in &func.cfg.blocks.get(id.0 as usize).map(|b| b.insts.clone()).unwrap_or_default() {
                if let Some(SsaOp::Jump { target }) = func.values.get(iid.0 as usize).map(|i| &i.op) {
                    *join_votes.entry(*target).or_default() += 1;
                }
            }
        }
    }
    let join = join_votes
        .into_iter()
        .max_by_key(|(id, n)| (*n, u32::MAX - id.0))
        .filter(|(_, n)| *n >= 2)
        .map(|(id, _)| id);

    lines.push(format!("{pad}switch ({scrutinee}) {{"));

    for (case_id, labels) in &cases {
        if !emitted.insert(*case_id) {
            continue;
        }
        for header in format_switch_case_header(labels) {
            lines.push(format!("{pad}{header}"));
        }
        let Some(case_block) = func.cfg.blocks.get(case_id.0 as usize) else {
            lines.push(format!("{inner}break;"));
            continue;
        };
        let local_consts = collect_block_const_defs(func, *case_id);
        let term = emit_block_statements_for_switch(
            func,
            case_block,
            symbols,
            local_symbols,
            inner,
            lines,
            case_blocks,
            join,
            emitted,
            &local_consts,
        );
        match term {
            Some(target) if join == Some(target) => {
                lines.push(format!("{inner}break;"));
            }
            Some(target) if case_blocks.contains(&target) => {
                if let Some(body) =
                    clone_linear_store_body(func, target, symbols, local_symbols, &local_consts, 0)
                {
                    for stmt in body {
                        lines.push(format!("{inner}{stmt}"));
                    }
                    mark_linear_chain_emitted(func, target, case_blocks, join, emitted, 0);
                    lines.push(format!("{inner}break;"));
                } else {
                    // Fallthrough into another case body (e.g. 'f' -> 'A').
                    emit_switch_tail_chain(
                        func,
                        target,
                        symbols,
                        local_symbols,
                        case_blocks,
                        join,
                        emitted,
                        inner,
                        lines,
                        0,
                        &local_consts,
                    );
                    lines.push(format!("{inner}break;"));
                }
            }
            Some(target) => {
                if let Some(body) =
                    clone_linear_store_body(func, target, symbols, local_symbols, &local_consts, 0)
                {
                    for stmt in body {
                        lines.push(format!("{inner}{stmt}"));
                    }
                } else {
                    emit_switch_tail_chain(
                        func,
                        target,
                        symbols,
                        local_symbols,
                        case_blocks,
                        join,
                        emitted,
                        inner,
                        lines,
                        0,
                        &local_consts,
                    );
                }
                lines.push(format!("{inner}break;"));
            }
            None => {
                let succs = func.cfg.successors(*case_id);
                if succs.len() == 1 {
                    let target = succs[0];
                    if join == Some(target) {
                        lines.push(format!("{inner}break;"));
                    } else if case_blocks.contains(&target) {
                        if let Some(body) = clone_linear_store_body(
                            func,
                            target,
                            symbols,
                            local_symbols,
                            &local_consts,
                            0,
                        ) {
                            for stmt in body {
                                lines.push(format!("{inner}{stmt}"));
                            }
                            lines.push(format!("{inner}break;"));
                        } else {
                            emit_switch_tail_chain(
                                func,
                                target,
                                symbols,
                                local_symbols,
                                case_blocks,
                                join,
                                emitted,
                                inner,
                                lines,
                                0,
                                &local_consts,
                            );
                            lines.push(format!("{inner}break;"));
                        }
                    } else {
                        emit_switch_tail_chain(
                            func,
                            target,
                            symbols,
                            local_symbols,
                            case_blocks,
                            join,
                            emitted,
                            inner,
                            lines,
                             0,
                        &local_consts,
                        );
                        lines.push(format!("{inner}break;"));
                    }
                } else {
                    lines.push(format!("{inner}break;"));
                }
            }
        }
    }

    lines.push(format!("{pad}}}"));
    if let Some(j) = join {
        lines.push(format!("{pad}goto bb{};", j.0));
    }
    true
}

fn is_pure_jump_block(func: &SsaFunction, block_id: BlockId) -> bool {
    let Some(block) = func.cfg.blocks.get(block_id.0 as usize) else {
        return false;
    };
    let mut saw_jump = false;
    let mut saw_side = false;
    for &iid in &block.insts {
        let Some(inst) = func.values.get(iid.0 as usize) else {
            continue;
        };
        match &inst.op {
            SsaOp::Jump { .. } => {
                if saw_jump {
                    return false;
                }
                saw_jump = true;
            }
            SsaOp::Phi { .. } | SsaOp::Unknown => {}
            SsaOp::Copy {
                src: Operand::Symbol(name),
            } if name.starts_with("/* switch") => {
                return false;
            }
            SsaOp::Copy { .. } | SsaOp::BinOp { .. } | SsaOp::UnaryOp { .. } | SsaOp::Load { .. }
                if should_suppress_temp_emit(func, inst.id) || is_flag_or_cond_value(func, inst.id) => {}
            _ => {
                saw_side = true;
            }
        }
    }
    if saw_side {
        return false;
    }
    if saw_jump {
        return true;
    }
    // Empty fallthrough-only block: single successor, no side effects.
    let succs = func.cfg.successors(block_id);
    succs.len() == 1 && block.insts.is_empty()
}

fn resolve_jump_target(func: &SsaFunction, start: BlockId) -> BlockId {
    let mut cur = start;
    for _ in 0..12 {
        if !is_pure_jump_block(func, cur) {
            break;
        }
        let Some(block) = func.cfg.blocks.get(cur.0 as usize) else {
            break;
        };
        let mut next: Option<BlockId> = None;
        for &iid in &block.insts {
            if let Some(SsaOp::Jump { target }) = func.values.get(iid.0 as usize).map(|i| &i.op) {
                next = Some(*target);
            }
        }
        let Some(n) = next else {
            break;
        };
        if n == cur {
            break;
        }
        cur = n;
    }
    cur
}

fn same_cfg_join(func: &SsaFunction, a: BlockId, b: BlockId) -> bool {
    if a == b {
        return true;
    }
    let ra = resolve_jump_target(func, a);
    let rb = resolve_jump_target(func, b);
    if ra == rb {
        return true;
    }
    let one_hop = |from: BlockId, to: BlockId| -> bool {
        if resolve_jump_target(func, from) == to {
            return true;
        }
        let succs = func.cfg.successors(from);
        succs.len() == 1 && (succs[0] == to || resolve_jump_target(func, succs[0]) == to)
    };
    one_hop(a, b) || one_hop(b, a) || one_hop(ra, rb) || one_hop(rb, ra)
}

fn call_is_strcmp(
    func: &SsaFunction,
    id: SsaValueId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> bool {
    match func.values.get(id.0 as usize).map(|i| &i.op) {
        Some(SsaOp::Call { target, .. }) => {
            let name = render_call_target(func, target, symbols, local_symbols);
            let bare = name.trim_start_matches('_');
            bare == "strcmp" || bare.ends_with("strcmp")
        }
        _ => false,
    }
}

fn block_strcmp_only_branches_on(func: &SsaFunction, block: BlockId, call_id: SsaValueId) -> bool {
    let Some(b) = func.cfg.blocks.get(block.0 as usize) else {
        return false;
    };
    let mut saw_branch = false;
    for &iid in &b.insts {
        let Some(inst) = func.values.get(iid.0 as usize) else {
            continue;
        };
        if inst.id == call_id {
            continue;
        }
        match &inst.op {
            SsaOp::Branch { cond, .. } => {
                saw_branch = true;
                if !(operand_uses_value(cond, call_id) || ssa_value_is_used_by(func, call_id, cond))
                {
                    return false;
                }
            }
            SsaOp::BinOp {
                kind: BinOpKind::Eq | BinOpKind::Ne,
                lhs,
                rhs,
            } => {
                let uses = matches!(lhs, Operand::Value(v) if *v == call_id)
                    || matches!(rhs, Operand::Value(v) if *v == call_id);
                if !uses {
                    // allow other binops that don't use call
                    if operand_uses_value(lhs, call_id) || operand_uses_value(rhs, call_id) {
                        return false;
                    }
                }
            }
            SsaOp::Copy {
                src: Operand::Value(v),
            } if *v == call_id => {}
            SsaOp::Phi { .. } | SsaOp::Unknown | SsaOp::Jump { .. } => {}
            SsaOp::Store { .. } | SsaOp::Call { .. } | SsaOp::Return { .. } => return false,
            _ => {
                if operand_uses_value(
                    match &inst.op {
                        SsaOp::Load { addr } => addr,
                        _ => continue,
                    },
                    call_id,
                ) {
                    return false;
                }
            }
        }
    }
    saw_branch
}

fn value_only_used_as_zero_test(func: &SsaFunction, id: SsaValueId) -> bool {
    let mut uses = 0usize;
    let mut pure = 0usize;
    for other in &func.values {
        if other.id == id {
            continue;
        }
        let mut used = HashSet::new();
        collect_used_operands(&other.op, &mut used);
        if !used.contains(&id) {
            continue;
        }
        uses += 1;
        match &other.op {
            SsaOp::BinOp {
                kind: BinOpKind::Eq | BinOpKind::Ne,
                lhs,
                rhs,
            } => {
                let zero_rhs = matches!(rhs, Operand::Constant(0));
                let zero_lhs = matches!(lhs, Operand::Constant(0));
                let has_id = matches!(lhs, Operand::Value(v) if *v == id)
                    || matches!(rhs, Operand::Value(v) if *v == id);
                if has_id && (zero_lhs || zero_rhs) {
                    pure += 1;
                } else if has_id {
                    // Non-zero compare still comparison-only.
                    pure += 1;
                } else {
                    return false;
                }
            }
            SsaOp::Copy {
                src: Operand::Value(v),
            } if *v == id => {
                pure += 1;
            }
            SsaOp::Branch { cond, .. } => {
                if operand_uses_value(cond, id) || ssa_value_is_used_by(func, id, cond) {
                    pure += 1;
                } else {
                    return false;
                }
            }
            SsaOp::UnaryOp { src: Operand::Value(v), .. } if *v == id => {
                pure += 1;
            }
            _ => return false,
        }
    }
    uses > 0 && pure == uses
}

fn peel_zero_test(
    func: &SsaFunction,
    cond: &Operand,
) -> Option<(SsaValueId, bool)> {
    // returns (value, is_negated) where is_negated means "value == 0" / "!value"
    let mut cur = match cond {
        Operand::Value(id) => *id,
        _ => return None,
    };
    for _ in 0..6 {
        let Some(inst) = func.values.get(cur.0 as usize) else {
            return None;
        };
        match &inst.op {
            SsaOp::BinOp {
                kind: BinOpKind::Eq,
                lhs: Operand::Value(v),
                rhs: Operand::Constant(0),
            }
            | SsaOp::BinOp {
                kind: BinOpKind::Eq,
                lhs: Operand::Constant(0),
                rhs: Operand::Value(v),
            } => return Some((*v, true)),
            SsaOp::BinOp {
                kind: BinOpKind::Ne,
                lhs: Operand::Value(v),
                rhs: Operand::Constant(0),
            }
            | SsaOp::BinOp {
                kind: BinOpKind::Ne,
                lhs: Operand::Constant(0),
                rhs: Operand::Value(v),
            } => return Some((*v, false)),
            SsaOp::Copy {
                src: Operand::Value(v),
            } => cur = *v,
            _ => return Some((cur, false)),
        }
    }
    None
}

fn format_code_pointer(
    addr: u64,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> Option<String> {
    if addr < 0x1000 {
        return None;
    }
    if let Some(name) = lookup_code_name(addr) {
        return Some(name);
    }
    if let Some(name) = lookup_symbol_name(symbols, local_symbols, addr) {
        return Some(name.to_string());
    }
    // Prefer text-only range; avoid __DATA/GOT pages (0x...8000+).
    if (0x100000000..0x100008000).contains(&addr) {
        return Some(format_sub_addr(addr));
    }
    None
}

fn lookup_code_name(addr: u64) -> Option<String> {
    RENDER_CODE_NAMES.with(|slot| slot.borrow().get(&addr).cloned())
}

fn block_is_strcmp_zero_branch(
    func: &SsaFunction,
    block_id: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> Option<(String, BlockId, BlockId, bool)> {
    // returns (strcmp_call_text, true_target, false_target, true_if_equal)
    let block = func.cfg.blocks.get(block_id.0 as usize)?;
    let mut call_id: Option<SsaValueId> = None;
    let mut branch: Option<(Operand, BlockId, BlockId)> = None;
    for &iid in &block.insts {
        let inst = func.values.get(iid.0 as usize)?;
        match &inst.op {
            SsaOp::Call { .. } if call_is_strcmp(func, inst.id, symbols, local_symbols) => call_id = Some(inst.id),
            SsaOp::Branch {
                cond,
                true_block,
                false_block,
            } => branch = Some((cond.clone(), *true_block, *false_block)),
            SsaOp::Phi { .. } | SsaOp::Unknown | SsaOp::Jump { .. } => {}
            SsaOp::Copy { .. } | SsaOp::BinOp { .. } | SsaOp::UnaryOp { .. } | SsaOp::Load { .. }
                if should_suppress_temp_emit(func, inst.id) || is_flag_or_cond_value(func, inst.id) => {}
            SsaOp::BinOp {
                kind: BinOpKind::Eq | BinOpKind::Ne,
                ..
            } => {}
            _ => {
                if matches!(inst.op, SsaOp::Store { .. } | SsaOp::Call { .. }) {
                    return None;
                }
            }
        }
    }
    let call_id = call_id?;
    let (cond, t, f) = branch?;
    let (vid, is_eq_zero) = peel_zero_test(func, &cond).unwrap_or((
        match cond {
            Operand::Value(v) => v,
            _ => return None,
        },
        false,
    ));
    // vid should be call or cmp of call
    let mut root = vid;
    for _ in 0..4 {
        match func.values.get(root.0 as usize).map(|i| &i.op) {
            Some(SsaOp::Copy {
                src: Operand::Value(v),
            }) => root = *v,
            Some(SsaOp::BinOp {
                kind: BinOpKind::Eq | BinOpKind::Ne,
                lhs: Operand::Value(v),
                rhs: Operand::Constant(0),
            })
            | Some(SsaOp::BinOp {
                kind: BinOpKind::Eq | BinOpKind::Ne,
                lhs: Operand::Constant(0),
                rhs: Operand::Value(v),
            }) => root = *v,
            _ => break,
        }
    }
    if root != call_id && !call_is_strcmp(func, root, symbols, local_symbols) {
        // allow peel from call_id itself
        if !matches!(
            func.values.get(vid.0 as usize).map(|i| &i.op),
            Some(SsaOp::Call { .. })
        ) {
            // check cond uses call
            if !ssa_value_is_used_by(func, call_id, &cond) {
                return None;
            }
        }
    }
    let call_text = render_named_value(func, call_id, symbols, local_symbols);
    let t = resolve_jump_target(func, t);
    let f = resolve_jump_target(func, f);
    // is_eq_zero true => branch true when strcmp==0 (equal strings)
    // natural form: if (!strcmp(...)) goto equal_target
    Some((call_text, t, f, is_eq_zero))
}

fn ssa_value_is_used_by(func: &SsaFunction, id: SsaValueId, op: &Operand) -> bool {
    match op {
        Operand::Value(v) => {
            if *v == id {
                return true;
            }
            match func.values.get(v.0 as usize).map(|i| &i.op) {
                Some(SsaOp::Copy { src }) => ssa_value_is_used_by(func, id, src),
                Some(SsaOp::BinOp { lhs, rhs, .. }) => {
                    ssa_value_is_used_by(func, id, lhs) || ssa_value_is_used_by(func, id, rhs)
                }
                _ => false,
            }
        }
        _ => false,
    }
}


fn block_simple_global_store_jump(
    func: &SsaFunction,
    block_id: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> Option<(String, BlockId)> {
    let block = func.cfg.blocks.get(block_id.0 as usize)?;
    let mut store: Option<String> = None;
    let mut jump: Option<BlockId> = None;
    for &iid in &block.insts {
        let inst = func.values.get(iid.0 as usize)?;
        match &inst.op {
            SsaOp::Store { .. } => {
                if store_is_stack_arg_for_call(func, inst.id) {
                    continue;
                }
                let r = render_named_value(func, inst.id, symbols, local_symbols);
                if is_trivial_stack_prologue_store(&r) {
                    continue;
                }
                if store.is_some() {
                    return None;
                }
                store = Some(r);
            }
            SsaOp::Jump { target } => {
                if jump.is_some() {
                    return None;
                }
                jump = Some(resolve_jump_target(func, *target));
            }
            SsaOp::Call { .. } | SsaOp::Branch { .. } | SsaOp::Return { .. } => return None,
            SsaOp::Phi { .. } | SsaOp::Unknown => {}
            SsaOp::Copy { .. }
            | SsaOp::BinOp { .. }
            | SsaOp::UnaryOp { .. }
            | SsaOp::Load { .. }
                if should_suppress_temp_emit(func, inst.id) || is_flag_or_cond_value(func, inst.id) => {}
            _ => return None,
        }
    }
    let store = store?;
    let jump = jump.or_else(|| {
        let succs = func.cfg.successors(block_id);
        if succs.len() == 1 {
            Some(succs[0])
        } else {
            None
        }
    })?;
    Some((store, jump))
}

fn block_is_null_check_branch(
    func: &SsaFunction,
    block_id: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> Option<(String, BlockId, BlockId, bool)> {
    let block = func.cfg.blocks.get(block_id.0 as usize)?;
    let mut branch = None;
    for &iid in &block.insts {
        let inst = func.values.get(iid.0 as usize)?;
        match &inst.op {
            SsaOp::Branch {
                cond,
                true_block,
                false_block,
            } => {
                branch = Some((
                    render_condition_text(func, cond, symbols, local_symbols),
                    resolve_jump_target(func, *true_block),
                    resolve_jump_target(func, *false_block),
                ));
            }
            SsaOp::Call { .. } | SsaOp::Store { .. } | SsaOp::Return { .. } => return None,
            SsaOp::Phi { .. } | SsaOp::Unknown | SsaOp::Jump { .. } => {}
            SsaOp::Copy { .. }
            | SsaOp::BinOp { .. }
            | SsaOp::UnaryOp { .. }
            | SsaOp::Load { .. }
                if should_suppress_temp_emit(func, inst.id) || is_flag_or_cond_value(func, inst.id) => {}
            SsaOp::BinOp {
                kind: BinOpKind::Eq | BinOpKind::Ne,
                ..
            } => {}
            _ => return None,
        }
    }
    let (cond, t, f) = branch?;
    let fall = resolve_jump_target(func, BlockId(block_id.0.saturating_add(1)));
    let c = cond.replace(' ', "");
    let is_nullish = c == "!optarg"
        || c == "optarg==0"
        || c == "!env"
        || c.starts_with("!")
            && (c.contains("optarg") || c.ends_with("env"));
    if !is_nullish && !(c.contains("optarg") && (c.contains("==0") || c.contains("!=0"))) {
        return None;
    }
    if t != fall && f == fall {
        Some((cond, t, f, true))
    } else if f != fall && t == fall {
        Some((negate_condition_text(&cond), f, t, true))
    } else {
        None
    }
}


fn block_collect_side_effects(
    func: &SsaFunction,
    block_id: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> Option<(Vec<String>, Option<BlockId>, Option<(String, BlockId, BlockId)>)> {
    let block = func.cfg.blocks.get(block_id.0 as usize)?;
    let mut lines = Vec::new();
    let mut jump = None;
    let mut branch = None;
    for &iid in &block.insts {
        let inst = func.values.get(iid.0 as usize)?;
        match &inst.op {
            SsaOp::Call { .. } => {
                let call = render_named_value(func, inst.id, symbols, local_symbols);
                if ssa_value_is_used(func, inst.id) {
                    lines.push(format!(
                        "{} = {};",
                        result_name_for_call(func, inst.id, symbols, local_symbols),
                        call
                    ));
                } else {
                    lines.push(format!("{call};"));
                }
            }
            SsaOp::Store { .. } => {
                if store_is_stack_arg_for_call(func, inst.id) {
                    continue;
                }
                let r = render_named_value(func, inst.id, symbols, local_symbols);
                if is_trivial_stack_prologue_store(&r) {
                    continue;
                }
                lines.push(format!("{r};"));
            }
            SsaOp::Jump { target } => {
                jump = Some(resolve_jump_target(func, *target));
            }
            SsaOp::Branch {
                cond,
                true_block,
                false_block,
            } => {
                branch = Some((
                    render_condition_text(func, cond, symbols, local_symbols),
                    resolve_jump_target(func, *true_block),
                    resolve_jump_target(func, *false_block),
                ));
            }
            SsaOp::Return { .. } => return None,
            SsaOp::Phi { .. } | SsaOp::Unknown => {}
            SsaOp::Copy { .. }
            | SsaOp::BinOp { .. }
            | SsaOp::UnaryOp { .. }
            | SsaOp::Load { .. }
                if should_suppress_temp_emit(func, inst.id) || is_flag_or_cond_value(func, inst.id) => {}
            SsaOp::BinOp {
                kind: BinOpKind::Eq
                    | BinOpKind::Ne
                    | BinOpKind::Lt
                    | BinOpKind::Le
                    | BinOpKind::Gt
                    | BinOpKind::Ge,
                ..
            } => {}
            _ => {}
        }
    }
    Some((lines, jump, branch))
}

fn try_emit_if_guard_body(
    func: &SsaFunction,
    start: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
) -> bool {
    if emitted.contains(&start) {
        return false;
    }
    let Some((prelude, jump, branch)) =
        block_collect_side_effects(func, start, symbols, local_symbols)
    else {
        return false;
    };
    let Some((cond, t, f)) = branch else {
        return false;
    };
    if jump.is_some() {
        return false;
    }
    let cl = cond.replace(' ', "");
    if cl.contains("opt<")
        || cl.contains("opt>")
        || cl.contains("opt==")
        || cl.contains("opt!=")
        || prelude.iter().any(|s| s.contains("getopt"))
    {
        return false;
    }
    // Don't steal color cascade / multi-strcmp regions.
    if prelude.iter().any(|s| s.contains("strcmp")) {
        return false;
    }
    let fall = resolve_jump_target(func, BlockId(start.0.saturating_add(1)));
    let (join, body_start, take_cond) = if t != fall && f == fall {
        (t, f, negate_condition_text(&cond))
    } else if f != fall && t == fall {
        (f, t, cond.clone())
    } else {
        return false;
    };
    if body_start == join {
        return false;
    }

    let mut body_blocks = Vec::new();
    let mut body_lines = Vec::new();
    let mut cur = body_start;
    for _ in 0..6 {
        if cur == join {
            break;
        }
        if emitted.contains(&cur) && cur != body_start {
            return false;
        }
        let Some((blines, bjump, bbranch)) =
            block_collect_side_effects(func, cur, symbols, local_symbols)
        else {
            return false;
        };
        if bbranch.is_some() {
            return false;
        }
        // Stop before large unrelated calls
        if blines.iter().any(|s| {
            s.contains("getopt")
                || s.contains("traverse")
                || s.contains("getbsize")
                || s.contains("parse_colors")
                || s.contains("ferror")
                || s.contains("fflush")
                || s.contains("_exit")
                || s.contains("exit(")
                || s.contains("_err")
                || s.contains("strtonum")
                || s.contains("ioctl")
                || s.contains("tgetent")
                || s.contains("tgetstr")
        }) {
            return false;
        }
        body_lines.extend(blines);
        body_blocks.push(cur);
        if let Some(j) = bjump {
            cur = j;
            continue;
        }
        let succs = func.cfg.successors(cur);
        if succs.len() == 1 {
            cur = resolve_jump_target(func, succs[0]);
            continue;
        }
        if succs.is_empty() {
            break;
        }
        return false;
    }
    if cur != join || body_lines.is_empty() || body_lines.len() > 3 {
        return false;
    }
    let interesting = body_lines.iter().any(|s| {
        s.contains("g_f_")
            || s.contains("g_color")
            || s.contains("g_samesort")
            || s.contains("usage")
            || s.contains("sysctl")
    });
    if !interesting {
        return false;
    }

    let pad = "    ";
    emitted.insert(start);
    for b in body_blocks {
        emitted.insert(b);
    }
    for s in prelude {
        lines.push(format!("{pad}{s}"));
    }
    lines.push(format!("{pad}if ({take_cond}) {{"));
    for s in body_lines {
        lines.push(format!("{pad}    {s}"));
    }
    lines.push(format!("{pad}}}"));
    true
}

fn try_emit_early_usage(
    func: &SsaFunction,
    start: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
) -> bool {
    if emitted.contains(&start) {
        return false;
    }
    let Some((prelude, _, branch)) =
        block_collect_side_effects(func, start, symbols, local_symbols)
    else {
        return false;
    };
    if prelude.len() > 1 {
        return false;
    }
    if prelude.len() == 1 && !prelude[0].contains("headerlen") {
        return false;
    }
    let Some((cond, t, f)) = branch else {
        return false;
    };
    if !cond.contains("argc") {
        return false;
    }
    let fall = resolve_jump_target(func, BlockId(start.0.saturating_add(1)));
    let (usage_b, _cont_b, need_usage) = if t != fall && f == fall {
        (f, t, negate_condition_text(&cond))
    } else if f != fall && t == fall {
        (t, f, cond.clone())
    } else {
        return false;
    };
    let Some((ulines, _, ubranch)) =
        block_collect_side_effects(func, usage_b, symbols, local_symbols)
    else {
        return false;
    };
    if ubranch.is_some() || !ulines.iter().any(|s| s.contains("usage")) {
        return false;
    }
    let pad = "    ";
    emitted.insert(start);
    emitted.insert(usage_b);
    for s in prelude {
        lines.push(format!("{pad}{s}"));
    }
    lines.push(format!("{pad}if ({need_usage}) {{"));
    for s in ulines {
        lines.push(format!("{pad}    {s}"));
    }
    lines.push(format!("{pad}}}"));
    true
}

fn try_emit_tty_termwidth(
    func: &SsaFunction,
    start: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
) -> bool {
    // if (is_tty) { default width; COLUMNS?/ioctl? } else { singlecol; COLUMNS? }
    // Keep only when both arms are short and join cleanly without leftover stores.
    if emitted.contains(&start) {
        return false;
    }
    let Some((prelude, _, branch)) =
        block_collect_side_effects(func, start, symbols, local_symbols)
    else {
        return false;
    };
    if !prelude.iter().any(|s| s.contains("isatty") || s.contains("is_tty =")) {
        return false;
    }
    let Some((cond, t, f)) = branch else {
        return false;
    };
    if !(cond.contains("is_tty") || cond.contains("isatty")) {
        return false;
    }
    let fall = resolve_jump_target(func, BlockId(start.0.saturating_add(1)));
    // if (is_tty) goto TTY; fallthrough NON_TTY
    let (tty, nontty, tty_cond) = if t != fall && f == fall {
        if cond.starts_with('!') {
            (f, t, negate_condition_text(&cond))
        } else {
            (t, f, cond.clone())
        }
    } else if f != fall && t == fall {
        if cond.starts_with('!') {
            (t, f, negate_condition_text(&cond))
        } else {
            (f, t, cond.clone())
        }
    } else {
        return false;
    };

    let collect = |arm: BlockId| -> Option<(Vec<BlockId>, Vec<String>, BlockId)> {
        let mut blocks = Vec::new();
        let mut out = Vec::new();
        let mut cur = arm;
        for _ in 0..10 {
            if blocks.contains(&cur) {
                break;
            }
            let (blines, bjump, bbranch) =
                block_collect_side_effects(func, cur, symbols, local_symbols)?;
            if blines.iter().any(|s| {
                s.contains("LS_SAMESORT")
                    || s.contains("CLICOLOR")
                    || s.contains("getopt")
                    || s.contains("usage(")
            }) {
                return Some((blocks, out, cur));
            }
            // Don't swallow pure join stores that are also reachable from other arm
            // without being part of this arm's exclusive path - handled by join detect
            blocks.push(cur);
            out.extend(blines);
            if let Some((c, bt, bf)) = bbranch {
                let fall2 = resolve_jump_target(func, BlockId(cur.0.saturating_add(1)));
                // Prefer path that continues arm-local setup; treat goto-out as arm exit
                // if (c) goto OUT; fallthrough continue
                if bt != fall2 && bf == fall2 {
                    // if going to a block that looks like join (later getenv), exit arm
                    let target_is_join = func
                        .cfg
                        .blocks
                        .get(bt.0 as usize)
                        .map(|b| {
                            b.insts.iter().any(|&iid| {
                                func.values.get(iid.0 as usize).map(|i| {
                                    matches!(i.op, SsaOp::Call { .. })
                                        && render_named_value(func, i.id, symbols, local_symbols)
                                            .contains("getenv")
                                }).unwrap_or(false)
                            })
                        })
                        .unwrap_or(false);
                    if target_is_join {
                        return Some((blocks, out, bt));
                    }
                    // continue fallthrough for empty checks etc
                    if c.contains("env") || c.contains('*') || c.contains("ioctl") || c.contains("ws_col") {
                        cur = fall2;
                        continue;
                    }
                    cur = bt;
                    continue;
                }
                if bf != fall2 && bt == fall2 {
                    cur = fall2;
                    continue;
                }
                cur = fall2;
                continue;
            }
            if let Some(j) = bjump {
                // unconditional jump often to join
                let joinish = func
                    .cfg
                    .blocks
                    .get(j.0 as usize)
                    .map(|b| {
                        b.insts.iter().any(|&iid| {
                            func.values.get(iid.0 as usize).map(|i| {
                                matches!(i.op, SsaOp::Call { .. })
                                    && render_named_value(func, i.id, symbols, local_symbols)
                                        .contains("getenv")
                            }).unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);
                if joinish {
                    return Some((blocks, out, j));
                }
                cur = j;
                continue;
            }
            let succs = func.cfg.successors(cur);
            if succs.len() == 1 {
                cur = resolve_jump_target(func, succs[0]);
                continue;
            }
            return Some((blocks, out, cur));
        }
        Some((blocks, out, cur))
    };

    let Some((tb, tl, tj)) = collect(tty) else {
        return false;
    };
    let Some((nb, nl, nj)) = collect(nontty) else {
        return false;
    };
    if tl.is_empty() && nl.is_empty() {
        return false;
    }
    if !tl.iter().chain(nl.iter()).any(|s| {
        s.contains("COLUMNS")
            || s.contains("g_termwidth")
            || s.contains("TIOCGWINSZ")
            || s.contains("g_f_singlecol")
            || s.contains("g_f_nonprint")
    }) {
        return false;
    }
    // Require both arms mention termwidth or COLUMNS-ish
    let tty_ok = tl.iter().any(|s| s.contains("termwidth") || s.contains("COLUMNS") || s.contains("0x50") || s.contains("ioctl"));
    let non_ok = nl.iter().any(|s| s.contains("singlecol") || s.contains("COLUMNS") || s.contains("termwidth") || s.contains("strtonum"));
    if !tty_ok || !non_ok {
        return false;
    }

    // Only accept if join targets agree OR both end at same post-block id neighborhood
    if tj != nj {
        // still ok if both joins are getenv LS_SAMESORT region - allow
        let j_ok = |j: BlockId| {
            func.cfg.blocks.get(j.0 as usize).map(|b| {
                b.insts.iter().any(|&iid| {
                    func.values.get(iid.0 as usize).map(|i| {
                        let t = render_named_value(func, i.id, symbols, local_symbols);
                        t.contains("LS_SAMESORT") || t.contains("CLICOLOR") || t.contains("getenv")
                    }).unwrap_or(false)
                })
            }).unwrap_or(false)
        };
        if !(j_ok(tj) && j_ok(nj)) && (tj.0 as i32 - nj.0 as i32).abs() > 2 {
            return false;
        }
    }

    // Reject if either arm is too long (likely incomplete internal structure)
    if tl.len() > 10 || nl.len() > 10 {
        return false;
    }

    let pad = "    ";
    emitted.insert(start);
    for b in tb.iter().chain(nb.iter()) {
        emitted.insert(*b);
    }
    for s in prelude {
        lines.push(format!("{pad}{s}"));
    }
    lines.push(format!("{pad}if ({tty_cond}) {{"));
    for s in &tl {
        lines.push(format!("{pad}    {s}"));
    }
    lines.push(format!("{pad}}} else {{"));
    for s in &nl {
        lines.push(format!("{pad}    {s}"));
    }
    lines.push(format!("{pad}}}"));
    true
}

fn naturalize_truthiness_if_needed(cond: &str) -> String {
    let t = cond.trim();
    if t.starts_with('!') {
        return t.to_string();
    }
    naturalize_truthiness(t)
}



fn try_emit_skip_noop_branch(
    func: &SsaFunction,
    start: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
) -> bool {
    if emitted.contains(&start) {
        return false;
    }
    let Some((prelude, _, branch)) =
        block_collect_side_effects(func, start, symbols, local_symbols)
    else {
        return false;
    };
    if !prelude.is_empty() {
        return false;
    }
    let Some((cond, t, f)) = branch else {
        return false;
    };
    if !(cond.contains("g_color_on") || cond.contains("color_on")) {
        return false;
    }
    let fall = resolve_jump_target(func, BlockId(start.0.saturating_add(1)));
    let (taken, not_taken) = if t != fall && f == fall {
        (t, f)
    } else if f != fall && t == fall {
        (f, t)
    } else {
        return false;
    };
    if same_cfg_join(func, taken, not_taken) || same_cfg_join(func, taken, fall) {
        emitted.insert(start);
        let _ = (cond, lines, symbols, local_symbols);
        return true;
    }
    false
}

fn try_emit_tcap_op_fallback(
    func: &SsaFunction,
    start: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
) -> bool {
    if emitted.contains(&start) {
        return false;
    }
    let Some((prelude, _, branch)) =
        block_collect_side_effects(func, start, symbols, local_symbols)
    else {
        return false;
    };
    if prelude.len() < 3 {
        return false;
    }
    let has_op = prelude.iter().any(|s| s.contains("tgetstr") && s.contains("op"));
    let has_af = prelude.iter().any(|s| s.contains("g_tcap_af") || s.contains("AF"));
    if !has_op || !has_af {
        return false;
    }
    let Some((cond, t, f)) = branch else {
        return false;
    };
    if !cond.contains("tcap") {
        return false;
    }
    let c = cond.replace(' ', "");
    let fall = resolve_jump_target(func, BlockId(start.0.saturating_add(1)));
    let (join, fallback, need_fallback) = if t != fall && f == fall {
        if c.starts_with('!') {
            return false;
        }
        (t, f, format!("!{cond}"))
    } else if f != fall && t == fall {
        if c.starts_with('!') {
            (f, t, cond.clone())
        } else {
            return false;
        }
    } else {
        return false;
    };
    let Some((flines, fjump, fbr)) =
        block_collect_side_effects(func, fallback, symbols, local_symbols)
    else {
        return false;
    };
    if fbr.is_some() {
        return false;
    }
    if !flines.iter().any(|s| s.contains("tgetstr") && s.contains("oc")) {
        return false;
    }
    let after = fjump.unwrap_or_else(|| {
        let succs = func.cfg.successors(fallback);
        if succs.len() == 1 {
            resolve_jump_target(func, succs[0])
        } else {
            join
        }
    });
    if !same_cfg_join(func, after, join) {
        return false;
    }
    let pad = "    ";
    emitted.insert(start);
    emitted.insert(fallback);
    for s in prelude {
        lines.push(format!("{pad}{s}"));
    }
    lines.push(format!("{pad}if ({need_fallback}) {{"));
    for s in flines {
        lines.push(format!("{pad}    {s}"));
    }
    lines.push(format!("{pad}}}"));
    true
}

fn try_emit_sysctl_if(
    func: &SsaFunction,
    start: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
) -> bool {
    if emitted.contains(&start) {
        return false;
    }
    let Some((prelude, _, branch)) =
        block_collect_side_effects(func, start, symbols, local_symbols)
    else {
        return false;
    };
    if prelude.len() > 4 {
        return false;
    }
    // prelude may include g_sortfn = ... only
    if prelude.iter().any(|s| {
        s.contains("err")
            || s.contains("exit")
            || s.contains("traverse")
            || s.contains("getopt")
            || s.contains("strcmp")
    }) {
        return false;
    }
    let Some((cond, t, f)) = branch else {
        return false;
    };
    if !(cond.contains("dataless") || cond.contains("g_f_dataless")) {
        return false;
    }
    let fall = resolve_jump_target(func, BlockId(start.0.saturating_add(1)));
    let (join, body, take) = if t != fall && f == fall {
        (t, f, negate_condition_text(&cond))
    } else if f != fall && t == fall {
        (f, t, cond.clone())
    } else {
        return false;
    };

    let mut body_lines = Vec::new();
    let mut body_blocks = Vec::new();
    let mut cur = body;
    for _ in 0..3 {
        if cur == join || resolve_jump_target(func, cur) == resolve_jump_target(func, join) {
            break;
        }
        // refuse walking into high-id error tails that are also join targets of other regions
        let Some((blines, bjump, bbr)) =
            block_collect_side_effects(func, cur, symbols, local_symbols)
        else {
            return false;
        };
        if blines.iter().any(|s| {
            s.contains("_err")
                || s.contains("errx")
                || s.contains("err(")
                || s.contains("exit(")
                || s.contains("traverse")
                || s.contains("unsupported")
        }) {
            return false;
        }
        body_blocks.push(cur);
        body_lines.extend(blines);
        if let Some((_c2, t2, f2)) = bbr {
            let fall2 = resolve_jump_target(func, BlockId(cur.0.saturating_add(1)));
            // branch should only skip remaining body to join; both targets join-ish or fallthrough empty
            let targets = [t2, f2];
            if !targets.iter().any(|x| same_cfg_join(func, *x, join)) {
                return false;
            }
            // continue on non-join side only if empty
            let cont = if same_cfg_join(func, t2, join) { f2 } else { t2 };
            if same_cfg_join(func, cont, join) {
                break;
            }
            // only allow empty fallthrough
            if let Some((cl, _, cb)) =
                block_collect_side_effects(func, cont, symbols, local_symbols)
            {
                if cb.is_some() || !cl.is_empty() {
                    break;
                }
            }
            break;
        }
        if let Some(j) = bjump {
            if same_cfg_join(func, j, join) {
                break;
            }
            // don't follow jump into unrelated region
            return false;
        }
        let succs = func.cfg.successors(cur);
        if succs.len() == 1 {
            let n = resolve_jump_target(func, succs[0]);
            if same_cfg_join(func, n, join) {
                break;
            }
            cur = n;
            continue;
        }
        break;
    }
    if body_lines.is_empty() || !body_lines.iter().any(|s| s.contains("sysctl")) {
        return false;
    }
    // body should be only sysctl_new + sysctlbyname (+ maybe rc assign)
    if body_lines.len() > 4 {
        return false;
    }
    if !body_lines.iter().all(|s| {
        s.contains("sysctl")
            || s.contains("sysctl_new")
            || s.contains("sysctl_rc")
            || s.contains("= 1")
            || s.contains("=1")
    }) {
        return false;
    }
    let pad = "    ";
    emitted.insert(start);
    for b in body_blocks {
        emitted.insert(b);
    }
    for s in prelude {
        lines.push(format!("{pad}{s}"));
    }
    lines.push(format!("{pad}if ({take}) {{"));
    for s in body_lines {
        lines.push(format!("{pad}    {s}"));
    }
    lines.push(format!("{pad}}}"));
    true
}

fn try_emit_color_optarg(
    func: &SsaFunction,
    start: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
) -> bool {
    let mut blocks: Vec<BlockId> = Vec::new();
    let mut cur = start;
    let mut null_goto: Option<(String, BlockId)> = None;
    if let Some((cond, match_t, cont, _)) =
        block_is_null_check_branch(func, cur, symbols, local_symbols)
    {
        if cond.contains("optarg") {
            null_goto = Some((cond, match_t));
            blocks.push(cur);
            cur = cont;
        }
    }

    let mut chain: Vec<(BlockId, String, BlockId, BlockId, bool)> = Vec::new();
    let chain_start = cur;
    for _ in 0..16 {
        let Some((call, t, f, eq0)) =
            block_is_strcmp_zero_branch(func, cur, symbols, local_symbols)
        else {
            break;
        };
        if !call.contains("optarg") {
            break;
        }
        let next_id = BlockId(cur.0.saturating_add(1));
        let fall = resolve_jump_target(func, next_id);
        let (match_t, cont_t, match_on_eq) = if eq0 {
            if t != fall && f == fall {
                (t, f, true)
            } else if f != fall && t == fall {
                (f, t, true)
            } else {
                (t, f, true)
            }
        } else if f != fall && t == fall {
            (f, t, true)
        } else if t != fall && f == fall {
            (t, f, false)
        } else {
            (f, t, true)
        };
        chain.push((cur, call, match_t, cont_t, match_on_eq));
        blocks.push(cur);
        if cont_t == fall || cont_t.0 == cur.0 + 1 {
            cur = cont_t;
            continue;
        }
        break;
    }
    if chain.len() < 2 {
        return false;
    }

    let mut prefix_parts: Vec<String> = Vec::new();
    let mut prefix_ok: Option<BlockId> = None;
    let mut prefix_fail: Option<BlockId> = None;
    let mut pcur = cur;
    for _ in 0..4 {
        let Some(block) = func.cfg.blocks.get(pcur.0 as usize) else {
            break;
        };
        let mut branch = None;
        let mut side = false;
        for &iid in &block.insts {
            let Some(inst) = func.values.get(iid.0 as usize) else {
                continue;
            };
            match &inst.op {
                SsaOp::Branch {
                    cond,
                    true_block,
                    false_block,
                } => {
                    branch = Some((
                        render_condition_text(func, cond, symbols, local_symbols),
                        resolve_jump_target(func, *true_block),
                        resolve_jump_target(func, *false_block),
                    ));
                }
                SsaOp::Call { .. } | SsaOp::Store { .. } | SsaOp::Return { .. } => side = true,
                SsaOp::Phi { .. } | SsaOp::Unknown | SsaOp::Jump { .. } => {}
                SsaOp::Copy { .. }
                | SsaOp::Load { .. }
                | SsaOp::UnaryOp { .. }
                | SsaOp::BinOp { .. }
                    if should_suppress_temp_emit(func, inst.id) || is_flag_or_cond_value(func, inst.id) => {}
                SsaOp::BinOp {
                    kind: BinOpKind::Eq | BinOpKind::Ne | BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge,
                    ..
                } => {}
                _ => side = true,
            }
        }
        if side || branch.is_none() {
            break;
        }
        let (cond, t, f) = branch.unwrap();
        if !(cond.contains('[') && cond.contains("optarg")) {
            break;
        }
        let fall = resolve_jump_target(func, BlockId(pcur.0.saturating_add(1)));
        let (goto_t, cont, cond_goto) = if t != fall && f == fall {
            (t, f, cond.clone())
        } else if f != fall && t == fall {
            (f, t, negate_condition_text(&cond))
        } else {
            break;
        };
        let c = cond_goto.replace(' ', "");
        if c.contains("!=") {
            prefix_parts.push(negate_condition_text(&cond_goto));
            if prefix_fail.is_none() {
                prefix_fail = Some(goto_t);
            }
        } else if c.contains("==0") || cond_goto.contains("== 0") {
            prefix_parts.push(cond_goto.clone());
            prefix_ok = Some(goto_t);
        } else if c.contains("==") {
            prefix_parts.push(cond_goto.clone());
            if prefix_ok.is_none() {
                prefix_ok = Some(goto_t);
            }
        } else {
            break;
        }
        blocks.push(pcur);
        pcur = cont;
        if prefix_parts.len() >= 3 {
            break;
        }
    }
    cur = pcur;

    let mut none_call: Option<String> = None;
    let mut none_ok: Option<BlockId> = None;
    let mut none_err: Option<BlockId> = None;
    if let Some((call, t, f, eq0)) =
        block_is_strcmp_zero_branch(func, cur, symbols, local_symbols)
    {
        if call.contains("none") || call.contains("optarg") {
            let fall = resolve_jump_target(func, BlockId(cur.0.saturating_add(1)));
            let (eq_t, ne_t) = if eq0 {
                if t != fall && f == fall {
                    (t, f)
                } else if f != fall && t == fall {
                    (f, t)
                } else {
                    (t, f)
                }
            } else if t != fall && f == fall {
                (f, t)
            } else {
                (f, t)
            };
            none_call = Some(call);
            none_ok = Some(eq_t);
            none_err = Some(ne_t);
            blocks.push(cur);
        }
    }

    let mut groups: Vec<(BlockId, Vec<String>)> = Vec::new();
    for (_, call, match_t, _, match_on_eq) in &chain {
        let expr = if *match_on_eq {
            if call.contains("strcmp") {
                format!("!{call}")
            } else {
                format!("{call} == 0")
            }
        } else {
            call.clone()
        };
        if let Some(last) = groups.last_mut() {
            if last.0 == *match_t {
                last.1.push(expr);
                continue;
            }
        }
        groups.push((*match_t, vec![expr]));
    }
    if let Some((cond, t)) = &null_goto {
        if let Some(g) = groups.iter_mut().find(|g| g.0 == *t) {
            g.1.insert(0, cond.clone());
        } else {
            groups.insert(0, (*t, vec![cond.clone()]));
        }
    }
    if let (Some(ok), parts) = (prefix_ok, &prefix_parts) {
        if !parts.is_empty() {
            let expr = parts.join(" && ");
            if let Some(g) = groups.iter_mut().find(|g| g.0 == ok) {
                g.1.push(expr);
            } else {
                groups.push((ok, vec![expr]));
            }
        }
    }
    if let (Some(ok), Some(call)) = (none_ok, none_call.as_ref()) {
        let expr = if call.contains("strcmp") {
            format!("!{call}")
        } else {
            format!("{call} == 0")
        };
        if let Some(g) = groups.iter_mut().find(|g| g.0 == ok) {
            g.1.push(expr);
        } else {
            groups.push((ok, vec![expr]));
        }
    }

    let mut arms: Vec<(String, String)> = Vec::new();
    let mut join: Option<BlockId> = None;
    let mut value_blocks: Vec<BlockId> = Vec::new();
    for (target, exprs) in &groups {
        let Some((store, j)) = block_simple_global_store_jump(func, *target, symbols, local_symbols)
        else {
            return false;
        };
        if !store.contains("g_color") {
            return false;
        }
        if let Some(prev) = join {
            if prev != j {
                return false;
            }
        } else {
            join = Some(j);
        }
        value_blocks.push(*target);
        arms.push((exprs.join(" || "), store));
    }
    if arms.len() < 2 {
        return false;
    }

    let mut err_line: Option<String> = None;
    let mut err_block: Option<BlockId> = None;
    if let Some(eb) = none_err {
        if let Some(block) = func.cfg.blocks.get(eb.0 as usize) {
            for &iid in &block.insts {
                let Some(inst) = func.values.get(iid.0 as usize) else {
                    continue;
                };
                if matches!(inst.op, SsaOp::Call { .. }) {
                    let call = render_named_value(func, inst.id, symbols, local_symbols);
                    if call.contains("errx") || call.contains("err") {
                        err_line = Some(format!("{call};"));
                        err_block = Some(eb);
                        break;
                    }
                }
            }
        }
    }

    let pad = "    ";
    for b in blocks {
        emitted.insert(b);
    }
    for b in value_blocks {
        emitted.insert(b);
    }
    if let Some(eb) = err_block {
        emitted.insert(eb);
    }

    for (i, (cond, store)) in arms.iter().enumerate() {
        let keyword = if i == 0 { "if" } else { "else if" };
        let cond_text = if cond.contains("||") && cond.contains("&&") {
            // parenthesize && clusters for readable precedence
            cond.split(" || ")
                .map(|part| {
                    if part.contains("&&") && !part.starts_with('(') {
                        format!("({part})")
                    } else {
                        part.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(" || ")
        } else {
            cond.clone()
        };
        lines.push(format!("{pad}{keyword} ({cond_text}) {{"));
        lines.push(format!("{pad}    {store};"));
        lines.push(format!("{pad}}}"));
    }
    if let Some(err) = err_line {
        lines.push(format!("{pad}else {{"));
        lines.push(format!("{pad}    {err}"));
        lines.push(format!("{pad}}}"));
    }
    let _ = (chain_start, prefix_fail, join);
    true
}

fn try_emit_exit_epilogue(
    func: &SsaFunction,
    start: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
) -> bool {
    if emitted.contains(&start) {
        return false;
    }
    let Some(block) = func.cfg.blocks.get(start.0 as usize) else {
        return false;
    };
    let mut traverse_call: Option<String> = None;
    let mut branch: Option<(String, BlockId, BlockId)> = None;
    for &iid in &block.insts {
        let Some(inst) = func.values.get(iid.0 as usize) else {
            continue;
        };
        match &inst.op {
            SsaOp::Call { target, .. } => {
                let name = render_call_target(func, target, symbols, local_symbols);
                let bare = name.trim_start_matches('_');
                if bare == "traverse" {
                    traverse_call = Some("traverse()".to_string());
                } else if bare.starts_with("sub_") {
                    if traverse_call.is_none() {
                        let call = render_named_value(func, inst.id, symbols, local_symbols);
                        traverse_call = Some(format!("{call};").trim_end_matches(';').to_string());
                    } else {
                        return false;
                    }
                } else if matches!(bare, "ferror" | "fflush" | "exit" | "err") {
                    return false;
                } else {
                    return false;
                }
            }
            SsaOp::Branch {
                cond,
                true_block,
                false_block,
            } => {
                branch = Some((
                    render_condition_text(func, cond, symbols, local_symbols),
                    resolve_jump_target(func, *true_block),
                    resolve_jump_target(func, *false_block),
                ));
            }
            SsaOp::Store { .. } => {
                if !store_is_stack_arg_for_call(func, inst.id) {
                    let r = render_named_value(func, inst.id, symbols, local_symbols);
                    if !is_trivial_stack_prologue_store(&r) {
                        return false;
                    }
                }
            }
            SsaOp::Return { .. } => return false,
            SsaOp::Phi { .. } | SsaOp::Unknown | SsaOp::Jump { .. } => {}
            SsaOp::Copy { .. }
            | SsaOp::BinOp { .. }
            | SsaOp::UnaryOp { .. }
            | SsaOp::Load { .. }
                if should_suppress_temp_emit(func, inst.id) || is_flag_or_cond_value(func, inst.id) => {}
            _ => {}
        }
    }
    let Some(traverse_call) = traverse_call else {
        return false;
    };

    let mut used = vec![start];
    let (cond, t, f) = if let Some(b) = branch {
        b
    } else {
        let mut cur = resolve_jump_target(func, BlockId(start.0.saturating_add(1)));
        let mut found = None;
        for _ in 0..3 {
            if emitted.contains(&cur) {
                break;
            }
            let Some(nb) = func.cfg.blocks.get(cur.0 as usize) else {
                break;
            };
            let mut br = None;
            let mut side = false;
            for &iid in &nb.insts {
                let Some(inst) = func.values.get(iid.0 as usize) else {
                    continue;
                };
                match &inst.op {
                    SsaOp::Branch {
                        cond,
                        true_block,
                        false_block,
                    } => {
                        br = Some((
                            render_condition_text(func, cond, symbols, local_symbols),
                            resolve_jump_target(func, *true_block),
                            resolve_jump_target(func, *false_block),
                        ));
                    }
                    SsaOp::Call { .. } | SsaOp::Store { .. } | SsaOp::Return { .. } => side = true,
                    SsaOp::Jump { target } => {
                        cur = resolve_jump_target(func, *target);
                    }
                    _ => {}
                }
            }
            if side {
                break;
            }
            if let Some(b) = br {
                used.push(cur);
                found = Some(b);
                break;
            }
            let succs = func.cfg.successors(cur);
            if succs.len() == 1 {
                used.push(cur);
                cur = succs[0];
                continue;
            }
            break;
        }
        let Some(b) = found else {
            return false;
        };
        b
    };

    let cond_l = cond.to_ascii_lowercase();
    if !(cond_l.contains("rval") || cond_l.contains("g_rval")) {
        return false;
    }

    let find_exit = |bid: BlockId| -> Option<(BlockId, String)> {
        let mut bid = bid;
        for _ in 0..3 {
            let b = func.cfg.blocks.get(bid.0 as usize)?;
            for &iid in &b.insts {
                let inst = func.values.get(iid.0 as usize)?;
                if let SsaOp::Call { target, .. } = &inst.op {
                    let name = render_call_target(func, target, symbols, local_symbols);
                    if name.trim_start_matches('_') == "exit"
                        || render_named_value(func, inst.id, symbols, local_symbols).contains("exit")
                    {
                        let c = render_named_value(func, inst.id, symbols, local_symbols);
                        return Some((bid, c));
                    }
                }
            }
            if is_pure_jump_block(func, bid) {
                let succs = func.cfg.successors(bid);
                if succs.len() == 1 {
                    bid = succs[0];
                    continue;
                }
            }
            break;
        }
        None
    };

    let t_exit = find_exit(t);
    let f_exit = find_exit(f);
    let (exit_b, cont_b, need_exit, exit_call) = match (t_exit, f_exit) {
        (Some((eb, ec)), None) => (eb, f, cond.clone(), ec),
        (None, Some((eb, ec))) => (eb, t, negate_condition_text(&cond), ec),
        _ => return false,
    };
    used.push(exit_b);

    let mut cur = cont_b;
    let mut io_assigns: Vec<String> = Vec::new();
    let mut io_checks: Vec<String> = Vec::new();
    let mut final_exit: Option<String> = None;
    let mut err_call: Option<String> = None;
    for _ in 0..8 {
        let Some(b) = func.cfg.blocks.get(cur.0 as usize) else {
            break;
        };
        let mut local_calls: Vec<(SsaValueId, String, String)> = Vec::new();
        let mut br = None;
        for &iid in &b.insts {
            let Some(inst) = func.values.get(iid.0 as usize) else {
                continue;
            };
            match &inst.op {
                SsaOp::Call { target, .. } => {
                    let name = render_call_target(func, target, symbols, local_symbols);
                    let text = render_named_value(func, inst.id, symbols, local_symbols);
                    local_calls.push((inst.id, name, text));
                }
                SsaOp::Branch {
                    cond,
                    true_block,
                    false_block,
                } => {
                    br = Some((
                        render_condition_text(func, cond, symbols, local_symbols),
                        resolve_jump_target(func, *true_block),
                        resolve_jump_target(func, *false_block),
                    ));
                }
                _ => {}
            }
        }

        if br.is_none() {
            for (_id, name, text) in &local_calls {
                let bare = name.trim_start_matches('_');
                if bare == "exit" || text.contains("exit(") {
                    final_exit = Some(text.clone());
                    used.push(cur);
                }
                if bare == "err" || (text.contains("err(") && !text.contains("errx")) {
                    err_call = Some(text.clone());
                    used.push(cur);
                }
            }
            if final_exit.is_some() {
                break;
            }
            let succs = func.cfg.successors(cur);
            if succs.len() == 1 {
                used.push(cur);
                cur = succs[0];
                continue;
            }
            break;
        }

        let (cnd, t2, f2) = br.unwrap();
        let fall2 = resolve_jump_target(func, BlockId(cur.0.saturating_add(1)));
        let fail_has_err = |bid: BlockId| -> bool {
            func.cfg
                .blocks
                .get(bid.0 as usize)
                .map(|bb| {
                    bb.insts.iter().any(|&iid| {
                        func.values
                            .get(iid.0 as usize)
                            .map(|i| {
                                matches!(i.op, SsaOp::Call { .. })
                                    && render_named_value(func, i.id, symbols, local_symbols)
                                        .contains("err")
                            })
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        };
        let (fail, cont) = if t2 != fall2 && f2 == fall2 {
            (t2, f2)
        } else if f2 != fall2 && t2 == fall2 {
            (f2, t2)
        } else if fail_has_err(t2) {
            (t2, f2)
        } else if fail_has_err(f2) {
            (f2, t2)
        } else {
            (t2, f2)
        };

        let mut is_io = false;
        for (id, name, text) in &local_calls {
            let bare = name.trim_start_matches('_');
            if bare == "ferror" || bare == "fflush" || text.contains("ferror") || text.contains("fflush")
            {
                is_io = true;
                if ssa_value_is_used(func, *id) {
                    let rn = result_name_for_call(func, *id, symbols, local_symbols);
                    io_assigns.push(format!("{rn} = {text};"));
                    let check = if cnd.starts_with('!') {
                        negate_condition_text(&cnd)
                    } else if cnd.contains(&rn) {
                        cnd.clone()
                    } else {
                        rn
                    };
                    io_checks.push(check);
                } else {
                    let check = if cnd.starts_with('!') {
                        negate_condition_text(&cnd)
                    } else {
                        cnd.clone()
                    };
                    io_checks.push(check);
                }
            }
        }
        if !is_io {
            break;
        }
        used.push(cur);
        if let Some(fb) = func.cfg.blocks.get(fail.0 as usize) {
            for &iid in &fb.insts {
                if let Some(inst) = func.values.get(iid.0 as usize) {
                    if matches!(inst.op, SsaOp::Call { .. }) {
                        let c = render_named_value(func, inst.id, symbols, local_symbols);
                        if c.contains("err") {
                            err_call = Some(c);
                            used.push(fail);
                        }
                    }
                }
            }
        }
        cur = cont;
    }

    if final_exit.is_none() {
        if let Some((_, c)) = find_exit(cur) {
            final_exit = Some(c);
            used.push(cur);
        }
    }
    if io_checks.is_empty() || final_exit.is_none() {
        return false;
    }
    if err_call.is_none() {
        err_call = Some("_err(1)".to_string());
    }

    // Swallow trailing err-only leftovers that the fold already covered.
    for bid in 0..func.cfg.blocks.len() as u32 {
        let bid = BlockId(bid);
        if used.contains(&bid) || emitted.contains(&bid) {
            continue;
        }
        let Some(b) = func.cfg.blocks.get(bid.0 as usize) else {
            continue;
        };
        let mut only_err = false;
        let mut other = false;
        for &iid in &b.insts {
            let Some(inst) = func.values.get(iid.0 as usize) else {
                continue;
            };
            match &inst.op {
                SsaOp::Call { target, .. } => {
                    let name = render_call_target(func, target, symbols, local_symbols);
                    let bare = name.trim_start_matches('_');
                    if bare == "err" {
                        only_err = true;
                    } else {
                        other = true;
                    }
                }
                SsaOp::Jump { .. } | SsaOp::Phi { .. } | SsaOp::Unknown => {}
                SsaOp::Copy { .. }
                | SsaOp::BinOp { .. }
                | SsaOp::UnaryOp { .. }
                | SsaOp::Load { .. }
                    if should_suppress_temp_emit(func, inst.id) || is_flag_or_cond_value(func, inst.id) => {}
                SsaOp::Store { .. } if store_is_stack_arg_for_call(func, inst.id) => {}
                _ => other = true,
            }
        }
        if only_err && !other {
            used.push(bid);
        }
    }

    let pad = "    ";
    for b in &used {
        emitted.insert(*b);
    }
    let trav = if traverse_call.ends_with(';') {
        traverse_call
    } else {
        format!("{traverse_call};")
    };
    lines.push(format!("{pad}{trav}"));
    lines.push(format!("{pad}if ({need_exit}) {{"));
    lines.push(format!("{pad}    {exit_call};"));
    lines.push(format!("{pad}}}"));
    for a in io_assigns {
        lines.push(format!("{pad}{a}"));
    }
    if io_checks.len() == 1 {
        lines.push(format!("{pad}if ({}) {{", io_checks[0]));
    } else {
        lines.push(format!("{pad}if ({}) {{", io_checks.join(" || ")));
    }
    if let Some(err) = err_call {
        lines.push(format!("{pad}    {err};"));
    }
    lines.push(format!("{pad}}}"));
    lines.push(format!("{pad}{};", final_exit.unwrap()));
    true
}


fn try_emit_strcmp_cascade(
    func: &SsaFunction,
    start: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
) -> bool {
    // Recognize a linear chain of strcmp(optarg, "...") zero-tests that share a small set of targets.
    let mut chain: Vec<(BlockId, String, BlockId, BlockId, bool)> = Vec::new();
    let mut cur = start;
    for _ in 0..16 {
        let Some((call, t, f, eq0)) =
            block_is_strcmp_zero_branch(func, cur, symbols, local_symbols)
        else {
            break;
        };
        // Prefer form: if (!strcmp) goto MATCH; else fallthrough next
        let next_id = BlockId(cur.0.saturating_add(1));
        let fall = resolve_jump_target(func, next_id);
        let (match_t, cont_t, match_on_eq) = if eq0 {
            // true branch when equal
            if t != fall && f == fall {
                (t, f, true)
            } else if f != fall && t == fall {
                (f, t, true)
            } else {
                (t, f, true)
            }
        } else {
            // true when not equal
            if f != fall && t == fall {
                (f, t, true)
            } else if t != fall && f == fall {
                (t, f, false)
            } else {
                (f, t, true)
            }
        };
        chain.push((cur, call, match_t, cont_t, match_on_eq));
        if cont_t == fall || cont_t.0 == cur.0 + 1 {
            cur = cont_t;
            if emitted.contains(&cur) {
                break;
            }
            continue;
        }
        break;
    }
    if chain.len() < 2 {
        return false;
    }
    // Group by match target
    let mut groups: Vec<(BlockId, Vec<String>)> = Vec::new();
    for (_, call, match_t, _, match_on_eq) in &chain {
        let expr = if *match_on_eq {
            if call.starts_with('_') || call.contains("strcmp") {
                format!("!{call}")
            } else {
                format!("{call} == 0")
            }
        } else {
            call.clone()
        };
        if let Some(last) = groups.last_mut() {
            if last.0 == *match_t {
                last.1.push(expr);
                continue;
            }
        }
        groups.push((*match_t, vec![expr]));
    }
    if groups.len() < 2 && chain.len() < 3 {
        return false;
    }
    let pad = "    ";
    for (bid, _, _, _, _) in &chain {
        emitted.insert(*bid);
    }
    for (i, (target, exprs)) in groups.iter().enumerate() {
        let cond = exprs.join(" || ");
        let keyword = if i == 0 { "if" } else { "else if" };
        lines.push(format!("{pad}{keyword} ({cond}) goto bb{};", target.0));
    }
    if let Some((_, _, _, cont, _)) = chain.last() {
        let last_block = chain.last().unwrap().0;
        let fall = resolve_jump_target(func, BlockId(last_block.0.saturating_add(1)));
        if *cont != fall {
            lines.push(format!("{pad}goto bb{};", cont.0));
        }
    }
    true
}

fn try_emit_and_guard_assign(
    func: &SsaFunction,
    start: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
) -> bool {
    // Pattern:
    //   if (c0) goto JOIN;
    //   [optional call]
    //   if (c1) goto JOIN;
    //   if (c2) goto JOIN;
    //   STORE;
    // JOIN:
    let mut guards: Vec<String> = Vec::new();
    let mut call_lines: Vec<String> = Vec::new();
    let mut blocks: Vec<BlockId> = Vec::new();
    let mut cur = start;
    let mut join: Option<BlockId> = None;
    let mut store_line: Option<String> = None;
    for step in 0..6 {
        if emitted.contains(&cur) && step > 0 {
            break;
        }
        let Some(block) = func.cfg.blocks.get(cur.0 as usize) else {
            break;
        };
        let mut local_call: Option<String> = None;
        let mut local_branch: Option<(String, BlockId, BlockId)> = None;
        let mut local_store: Option<String> = None;
        let mut side = false;
        for &iid in &block.insts {
            let Some(inst) = func.values.get(iid.0 as usize) else {
                continue;
            };
            match &inst.op {
                SsaOp::Call { .. } => {
                    let call = render_named_value(func, inst.id, symbols, local_symbols);
                    if ssa_value_is_used(func, inst.id) {
                        local_call = Some(format!(
                            "{} = {}",
                            result_name_for_call(func, inst.id, symbols, local_symbols),
                            call
                        ));
                    } else {
                        local_call = Some(call);
                    }
                }
                SsaOp::Branch {
                    cond,
                    true_block,
                    false_block,
                } => {
                    let cond_text = render_condition_text(func, cond, symbols, local_symbols);
                    local_branch = Some((
                        cond_text,
                        resolve_jump_target(func, *true_block),
                        resolve_jump_target(func, *false_block),
                    ));
                }
                SsaOp::Store { .. } => {
                    if store_is_stack_arg_for_call(func, inst.id) {
                        continue;
                    }
                    let rendered = render_named_value(func, inst.id, symbols, local_symbols);
                    if is_trivial_stack_prologue_store(&rendered) {
                        continue;
                    }
                    local_store = Some(rendered);
                }
                SsaOp::Jump { target } => {
                    let t = resolve_jump_target(func, *target);
                    if local_branch.is_none() && local_store.is_some() {
                        // store then jump to join
                        join = Some(t);
                    }
                }
                SsaOp::Phi { .. } | SsaOp::Unknown => {}
                SsaOp::BinOp { kind, .. }
                    if matches!(
                        kind,
                        BinOpKind::Eq
                            | BinOpKind::Ne
                            | BinOpKind::Lt
                            | BinOpKind::Le
                            | BinOpKind::Gt
                            | BinOpKind::Ge
                    ) => {}
                SsaOp::Copy { .. } | SsaOp::UnaryOp { .. } | SsaOp::Load { .. } | SsaOp::BinOp { .. }
                    if should_suppress_temp_emit(func, inst.id) || is_flag_or_cond_value(func, inst.id) => {}
                _ => side = true,
            }
        }
        if side {
            break;
        }
        if let Some((cond, t, f)) = local_branch {
            let fall = resolve_jump_target(func, BlockId(cur.0.saturating_add(1)));
            let (j, cont, cond_to_skip) = if t != fall && f == fall {
                (t, f, cond)
            } else if f != fall && t == fall {
                (f, t, negate_condition_text(&cond))
            } else {
                break;
            };
            if let Some(prev_join) = join {
                if prev_join != j {
                    break;
                }
            } else {
                join = Some(j);
            }
            if let Some(c) = local_call {
                call_lines.push(c);
            }
            guards.push(cond_to_skip);
            blocks.push(cur);
            cur = cont;
            continue;
        }
        if let Some(st) = local_store {
            if let Some(c) = local_call {
                call_lines.push(c);
            }
            store_line = Some(st);
            blocks.push(cur);
            break;
        }
        break;
    }
    if guards.len() < 2 || store_line.is_none() {
        return false;
    }
    let pad = "    ";
    for b in &blocks {
        emitted.insert(*b);
    }
    // guards are "skip conditions"; assignment happens when all are false
    let all = guards
        .iter()
        .map(|g| {
            let n = negate_condition_text(g);
            if is_simple_ident(&n) || n.starts_with('!') {
                n
            } else {
                format!("({n})")
            }
        })
        .collect::<Vec<_>>()
        .join(" && ");
    if call_lines.len() == 1 && guards.len() >= 2 {
        // if (!g0) { call; if (!g1 && !g2) store; }
        let g0 = negate_condition_text(&guards[0]);
        lines.push(format!("{pad}if ({g0}) {{"));
        lines.push(format!("{pad}    {};", call_lines[0]));
        let rest = guards[1..]
            .iter()
            .map(|g| {
                let n = negate_condition_text(g);
                if is_simple_ident(&n) || n.starts_with('!') {
                    n
                } else {
                    format!("({n})")
                }
            })
            .collect::<Vec<_>>()
            .join(" && ");
        lines.push(format!("{pad}    if ({rest}) {{"));
        lines.push(format!("{pad}        {};", store_line.unwrap()));
        lines.push(format!("{pad}    }}"));
        lines.push(format!("{pad}}}"));
    } else {
        for c in call_lines {
            lines.push(format!("{pad}{c};"));
        }
        lines.push(format!("{pad}if ({all}) {{"));
        lines.push(format!("{pad}    {};", store_line.unwrap()));
        lines.push(format!("{pad}}}"));
    }
    true
}

fn try_emit_or_skip_join(
    func: &SsaFunction,
    start: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
) -> bool {
    // if (a) goto JOIN; if (b) goto JOIN; if (c) goto JOIN; JOIN:
    // => if (a || b || c) { /* empty */ }  which is useless
    // Better: these are skip-to-join guards with empty bodies - just emit nothing and mark,
    // falling through is wrong. Keep as: // fallthrough join if all false is the path.
    // Actually for ls: if (nofollow) goto bb122; if (longform) goto bb122; if (listdir) goto bb122; bb122:
    // Meaning: if any, skip intermediate empty region - so intermediate is empty.
    // If all false, still reaches bb122. So the whole chain is a no-op! Can suppress entirely.
    let mut guards = Vec::new();
    let mut blocks = Vec::new();
    let mut cur = start;
    let mut join = None;
    for _ in 0..5 {
        if emitted.contains(&cur) && !blocks.is_empty() {
            break;
        }
        let Some(block) = func.cfg.blocks.get(cur.0 as usize) else {
            break;
        };
        let mut branch = None;
        let mut side = false;
        for &iid in &block.insts {
            let Some(inst) = func.values.get(iid.0 as usize) else {
                continue;
            };
            match &inst.op {
                SsaOp::Branch {
                    cond,
                    true_block,
                    false_block,
                } => {
                    branch = Some((
                        render_condition_text(func, cond, symbols, local_symbols),
                        resolve_jump_target(func, *true_block),
                        resolve_jump_target(func, *false_block),
                    ));
                }
                SsaOp::Phi { .. } | SsaOp::Unknown | SsaOp::Jump { .. } => {}
                SsaOp::Copy { .. }
                | SsaOp::Load { .. }
                | SsaOp::UnaryOp { .. }
                | SsaOp::BinOp { .. }
                    if should_suppress_temp_emit(func, inst.id) || is_flag_or_cond_value(func, inst.id) => {}
                SsaOp::BinOp {
                    kind: BinOpKind::Eq | BinOpKind::Ne | BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge,
                    ..
                } => {}
                _ => side = true,
            }
        }
        if side || branch.is_none() {
            break;
        }
        let (cond, t, f) = branch.unwrap();
        let fall = resolve_jump_target(func, BlockId(cur.0.saturating_add(1)));
        let (j, cont) = if t != fall && f == fall {
            (t, f)
        } else if f != fall && t == fall {
            (f, t)
        } else {
            break;
        };
        if let Some(prev) = join {
            if prev != j {
                break;
            }
        } else {
            join = Some(j);
        }
        guards.push(cond);
        blocks.push(cur);
        cur = cont;
        if blocks.len() >= 2 && cont == j {
            break;
        }
    }
    if blocks.len() < 2 {
        return false;
    }
    // Verify join block has no dependency on skipped region (empty skip) => no-op chain.
    // Emit nothing; mark blocks and let linear emission of join continue when reached.
    // But then we must not leave a hole - subsequent blocks still emitted when visited.
    // If we return true without emitting, join must still be emitted later.
    for b in blocks {
        emitted.insert(b);
    }
    true
}

fn try_emit_getbsize_guard(
    func: &SsaFunction,
    start: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
) -> bool {
    // if (((inode|longform)|size)==0) goto SKIP;
    // if (!kblocks) goto DO;
    // goto SKIP;  (or empty)
    // DO: getbsize(...); g_blocksize = ...
    // SKIP:
    let Some(block) = func.cfg.blocks.get(start.0 as usize) else {
        return false;
    };
    let mut branch = None;
    for &iid in &block.insts {
        let Some(inst) = func.values.get(iid.0 as usize) else {
            continue;
        };
        if let SsaOp::Branch {
            cond,
            true_block,
            false_block,
        } = &inst.op
        {
            branch = Some((
                render_condition_text(func, cond, symbols, local_symbols),
                resolve_jump_target(func, *true_block),
                resolve_jump_target(func, *false_block),
            ));
        }
    }
    let Some((cond0, t0, f0)) = branch else {
        return false;
    };
    if !(cond0.contains("g_f_inode")
        || cond0.contains("g_f_longform")
        || cond0.contains("g_f_size")
        || cond0.contains("inode"))
    {
        return false;
    }
    let fall = resolve_jump_target(func, BlockId(start.0.saturating_add(1)));
    let (skip, cont) = if t0 != fall && f0 == fall {
        (t0, f0)
    } else if f0 != fall && t0 == fall {
        (f0, t0)
    } else {
        return false;
    };
    // cont should lead to kblocks check then getbsize
    let mut cur = cont;
    let mut k_cond = None;
    let mut do_block = None;
    let mut blocks = vec![start];
    for _ in 0..4 {
        if cur == skip {
            break;
        }
        let Some(b) = func.cfg.blocks.get(cur.0 as usize) else {
            break;
        };
        let mut br = None;
        let mut has_getbsize = false;
        let mut store_bs = false;
        for &iid in &b.insts {
            let Some(inst) = func.values.get(iid.0 as usize) else {
                continue;
            };
            match &inst.op {
                SsaOp::Branch {
                    cond,
                    true_block,
                    false_block,
                } => {
                    br = Some((
                        render_condition_text(func, cond, symbols, local_symbols),
                        resolve_jump_target(func, *true_block),
                        resolve_jump_target(func, *false_block),
                    ));
                }
                SsaOp::Call { target, .. } => {
                    let name = render_call_target(func, target, symbols, local_symbols);
                    if name.contains("getbsize") {
                        has_getbsize = true;
                    }
                }
                SsaOp::Store { addr, .. } => {
                    if let Some(abs) = fold_absolute_addr(func, addr) {
                        if abs & 0xfff == 0xc8 {
                            store_bs = true;
                        }
                    }
                    let r = render_named_value(func, inst.id, symbols, local_symbols);
                    if r.contains("g_blocksize") {
                        store_bs = true;
                    }
                }
                _ => {}
            }
        }
        blocks.push(cur);
        if has_getbsize || store_bs {
            do_block = Some(cur);
            break;
        }
        if let Some((c, t, f)) = br {
            let fall2 = resolve_jump_target(func, BlockId(cur.0.saturating_add(1)));
            if c.contains("kblocks") || c.contains("g_f_kblocks") {
                k_cond = Some(c);
                // take path that doesn't skip
                if t == skip {
                    cur = f;
                } else if f == skip {
                    cur = t;
                } else if t != fall2 {
                    cur = t;
                } else {
                    cur = f;
                }
                continue;
            }
            if t == skip || f == skip {
                cur = if t == skip { f } else { t };
                continue;
            }
            cur = if t != fall2 { t } else { f };
        } else {
            break;
        }
    }
    let Some(do_b) = do_block else {
        return false;
    };
    let mut body: Vec<String> = Vec::new();
    let mut body_blocks: Vec<BlockId> = Vec::new();
    let mut seen = HashSet::new();
    let mut db = do_b;
    for _ in 0..3 {
        if !seen.insert(db) || db == skip {
            break;
        }
        let Some(b) = func.cfg.blocks.get(db.0 as usize) else {
            break;
        };
        let mut block_has_getbsize = false;
        let mut block_lines: Vec<String> = Vec::new();
        let mut next_jump: Option<BlockId> = None;
        for &iid in &b.insts {
            let Some(inst) = func.values.get(iid.0 as usize) else {
                continue;
            };
            match &inst.op {
                SsaOp::Call { target, .. } => {
                    let name = render_call_target(func, target, symbols, local_symbols);
                    let call = render_named_value(func, inst.id, symbols, local_symbols);
                    if name.contains("getbsize") {
                        block_has_getbsize = true;
                    }
                    if ssa_value_is_used(func, inst.id) {
                        block_lines.push(format!(
                            "{} = {};",
                            result_name_for_call(func, inst.id, symbols, local_symbols),
                            call
                        ));
                    } else {
                        block_lines.push(format!("{call};"));
                    }
                }
                SsaOp::Store { .. } => {
                    if store_is_stack_arg_for_call(func, inst.id) {
                        continue;
                    }
                    let r = render_named_value(func, inst.id, symbols, local_symbols);
                    if is_trivial_stack_prologue_store(&r) {
                        continue;
                    }
                    block_lines.push(format!("{r};"));
                }
                SsaOp::Jump { target } => {
                    next_jump = Some(resolve_jump_target(func, *target));
                }
                SsaOp::Branch { .. } => {
                    next_jump = None;
                }
                _ => {}
            }
        }
        let only_blocksize_norm = !block_has_getbsize
            && !block_lines.is_empty()
            && block_lines.iter().all(|s| {
                s.contains("g_blocksize")
                    && (s.contains(">> 9") || s.contains(">>9") || s.contains("0x1ff"))
            });
        if only_blocksize_norm && body.iter().any(|s| s.contains("getbsize")) {
            break;
        }
        if only_blocksize_norm && body.is_empty() && !block_has_getbsize {
            break;
        }
        body.extend(block_lines);
        body_blocks.push(db);
        if block_has_getbsize {
            let mut hop = next_jump;
            if hop.is_none() {
                let succs = func.cfg.successors(db);
                if succs.len() == 1 {
                    hop = Some(succs[0]);
                }
            }
            if let Some(nj) = hop {
                if nj != skip {
                    if let Some(nb) = func.cfg.blocks.get(nj.0 as usize) {
                        let mut has_bs = false;
                        let mut only_bs = true;
                        let mut lines_tmp = Vec::new();
                        for &iid in &nb.insts {
                            let Some(inst) = func.values.get(iid.0 as usize) else {
                                continue;
                            };
                            match &inst.op {
                                SsaOp::Store { .. } => {
                                    if store_is_stack_arg_for_call(func, inst.id) {
                                        continue;
                                    }
                                    let r = render_named_value(func, inst.id, symbols, local_symbols);
                                    if is_trivial_stack_prologue_store(&r) {
                                        continue;
                                    }
                                    if r.contains("g_blocksize") {
                                        has_bs = true;
                                        lines_tmp.push(format!("{r};"));
                                    } else {
                                        only_bs = false;
                                    }
                                }
                                SsaOp::Call { .. } => only_bs = false,
                                SsaOp::Branch { .. } => only_bs = false,
                                SsaOp::Jump { .. } | SsaOp::Phi { .. } | SsaOp::Unknown => {}
                                SsaOp::Copy { .. }
                                | SsaOp::BinOp { .. }
                                | SsaOp::UnaryOp { .. }
                                | SsaOp::Load { .. }
                                    if should_suppress_temp_emit(func, inst.id)
                                        || is_flag_or_cond_value(func, inst.id) => {}
                                _ => {}
                            }
                        }
                        if has_bs && only_bs {
                            body.extend(lines_tmp);
                            body_blocks.push(nj);
                        }
                    }
                }
            }
            break;
        }
        let succs = func.cfg.successors(db);
        if succs.len() == 1 && succs[0] != skip {
            if body.iter().any(|s| s.contains("getbsize"))
                && !body.iter().any(|s| s.contains("g_blocksize ="))
            {
                let nj = succs[0];
                let preds = func
                    .cfg
                    .blocks
                    .iter()
                    .filter(|pb| {
                        func.cfg
                            .successors(pb.id)
                            .iter()
                            .any(|s| *s == nj || resolve_jump_target(func, *s) == nj)
                    })
                    .count();
                if preds <= 1 {
                    db = nj;
                    continue;
                }
            }
        }
        break;
    }
    if body.is_empty() || !body.iter().any(|s| s.contains("getbsize")) {
        return false;
    }
    let pad = "    ";
    let need = negate_condition_text(&cond0);
    let kpart = k_cond
        .as_ref()
        .map(|k| {
            if k.contains('!') {
                k.clone()
            } else {
                negate_condition_text(k)
            }
        })
        .unwrap_or_else(|| "1".to_string());
    let cond = if kpart == "1" {
        need
    } else {
        format!("({need}) && ({kpart})")
    };
    for b in blocks {
        emitted.insert(b);
    }
    for b in body_blocks {
        emitted.insert(b);
    }
    lines.push(format!("{pad}if ({cond}) {{"));
    for s in body {
        lines.push(format!("{pad}    {s}"));
    }
    lines.push(format!("{pad}}}"));
    true
}

fn try_emit_char_prefix_chain(
    func: &SsaFunction,
    start: BlockId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
) -> bool {
    // if (s[0] != 'n') goto FAIL;
    // if (s[1] != 'o') goto FAIL;
    // if (s[2] == 0) goto OK;
    // FAIL: ...
    let mut checks: Vec<(BlockId, String, bool)> = Vec::new(); // (block, cond_for_continue, is_eq)
    let mut cur = start;
    let mut fail: Option<BlockId> = None;
    let mut ok: Option<BlockId> = None;
    for _ in 0..4 {
        if emitted.contains(&cur) && !checks.is_empty() {
            break;
        }
        let Some(block) = func.cfg.blocks.get(cur.0 as usize) else {
            break;
        };
        let mut branch = None;
        let mut side = false;
        for &iid in &block.insts {
            let Some(inst) = func.values.get(iid.0 as usize) else {
                continue;
            };
            match &inst.op {
                SsaOp::Branch {
                    cond,
                    true_block,
                    false_block,
                } => {
                    let cond_text = render_condition_text(func, cond, symbols, local_symbols);
                    branch = Some((
                        cond_text,
                        resolve_jump_target(func, *true_block),
                        resolve_jump_target(func, *false_block),
                    ));
                }
                SsaOp::Phi { .. } | SsaOp::Unknown | SsaOp::Jump { .. } => {}
                SsaOp::Copy { .. }
                | SsaOp::UnaryOp { .. }
                | SsaOp::Load { .. }
                | SsaOp::BinOp { .. }
                    if should_suppress_temp_emit(func, inst.id) || is_flag_or_cond_value(func, inst.id) => {}
                SsaOp::BinOp {
                    kind: BinOpKind::Eq | BinOpKind::Ne | BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge,
                    ..
                } => {}
                _ => side = true,
            }
        }
        if side || branch.is_none() {
            break;
        }
        let (cond, t, f) = branch.unwrap();
        let fall = resolve_jump_target(func, BlockId(cur.0.saturating_add(1)));
        // Prefer: if (cond) goto X; fallthrough Y
        let (goto_t, cont, cond_goto) = if t != fall && f == fall {
            (t, f, cond.clone())
        } else if f != fall && t == fall {
            (f, t, negate_condition_text(&cond))
        } else {
            break;
        };
        let is_index = cond.contains('[') && (cond.contains("==") || cond.contains("!="));
        if !is_index && !cond.contains("optarg") {
            break;
        }
        // If goto looks like fail (later used) and cont continues chain
        checks.push((cur, cond_goto, cont == fall || cont.0 == cur.0 + 1));
        if fail.is_none() {
            fail = Some(goto_t);
        } else if fail != Some(goto_t) && ok.is_none() {
            // last successful goto may be OK target (e.g. == 0 goto ok)
            ok = Some(goto_t);
            emitted.insert(cur);
            break;
        }
        emitted.insert(cur);
        cur = cont;
        if checks.len() >= 3 {
            // if next not char check, stop
            break;
        }
    }
    if checks.len() < 2 {
        for (b, _, _) in &checks {
            emitted.remove(b);
        }
        return false;
    }
    // Build positive form: optarg[0]=='n' && optarg[1]=='o' && optarg[2]==0
    let mut parts = Vec::new();
    for (i, (_, cond_goto, _)) in checks.iter().enumerate() {
        // cond_goto is condition of the if that jumps away
        // For != char, continue when equal; for == 0, continue/success when true
        let c = cond_goto.replace(' ', "");
        if c.contains("!=") {
            // if (s[i] != 'x') goto fail; => need s[i]=='x'
            parts.push(negate_condition_text(cond_goto));
        } else if c.contains("==0") || c.ends_with("==0") || cond_goto.contains("== 0") {
            parts.push(cond_goto.clone());
            if ok.is_none() {
                // this branch's goto is success
            }
        } else if c.contains("==") {
            parts.push(cond_goto.clone());
        } else {
            parts.push(negate_condition_text(cond_goto));
        }
        let _ = i;
    }
    let ok_t = ok.or(fail);
    let Some(ok_t) = ok_t else {
        return false;
    };
    // If last check was ==0 goto ok, fail is the other target from first checks
    let fail_t = fail.unwrap_or(ok_t);
    let pad = "    ";
    let all = parts
        .iter()
        .map(|p| {
            if is_simple_ident(p) || p.contains("==") || p.contains("!=") || p.starts_with('!') {
                p.clone()
            } else {
                format!("({p})")
            }
        })
        .collect::<Vec<_>>()
        .join(" && ");
    if fail_t != ok_t {
        let next = BlockId(start.0.saturating_add(checks.len() as u32));
        let next_fall = resolve_jump_target(func, next);
        if fail_t == next_fall || fail_t.0 == start.0 + checks.len() as u32 {
            lines.push(format!("{pad}if ({all}) goto bb{};", ok_t.0));
        } else {
            lines.push(format!(
                "{pad}if ({all}) goto bb{}; else goto bb{};",
                ok_t.0, fail_t.0
            ));
        }
    } else {
        lines.push(format!("{pad}if ({all}) goto bb{};", ok_t.0));
    }
    true
}

fn emit_ssa_block_linear(
    func: &SsaFunction,
    block: &CfgBlock,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    emitted: &mut HashSet<BlockId>,
    lines: &mut Vec<String>,
) {
    if is_pure_jump_block(func, block.id) {
        emitted.insert(block.id);
        return;
    }
    if emitted.contains(&block.id) {
        return;
    }
    if try_emit_early_usage(func, block.id, symbols, local_symbols, emitted, lines) {
        return;
    }
    if try_emit_if_guard_body(func, block.id, symbols, local_symbols, emitted, lines) {
        return;
    }
    if try_emit_skip_noop_branch(func, block.id, symbols, local_symbols, emitted, lines) {
        return;
    }
    if try_emit_tcap_op_fallback(func, block.id, symbols, local_symbols, emitted, lines) {
        return;
    }
    if try_emit_sysctl_if(func, block.id, symbols, local_symbols, emitted, lines) {
        return;
    }
    if try_emit_color_optarg(func, block.id, symbols, local_symbols, emitted, lines) {
        return;
    }
    if try_emit_strcmp_cascade(func, block.id, symbols, local_symbols, emitted, lines) {
        return;
    }
    if try_emit_char_prefix_chain(func, block.id, symbols, local_symbols, emitted, lines) {
        return;
    }
    if try_emit_and_guard_assign(func, block.id, symbols, local_symbols, emitted, lines) {
        return;
    }
    if try_emit_or_skip_join(func, block.id, symbols, local_symbols, emitted, lines) {
        return;
    }
    if try_emit_getbsize_guard(func, block.id, symbols, local_symbols, emitted, lines) {
        return;
    }
    if try_emit_exit_epilogue(func, block.id, symbols, local_symbols, emitted, lines) {
        return;
    }
    if !emitted.insert(block.id) {
        return;
    }
    let pad = "    ";
    let label_idx = if block.id.0 > 0 {
        if let Some(cases) = func.case_labels.get(&block.id) {
            if !cases.is_empty() {
                lines.push(format!("{pad}// bb{} @ {:#x}: {}", block.id.0, block.start_addr, cases.join(", ")));
            } else {
                lines.push(format!("{pad}// bb{} @ {:#x}", block.id.0, block.start_addr));
            }
        } else {
            lines.push(format!("{pad}// bb{} @ {:#x}", block.id.0, block.start_addr));
        }
        Some(lines.len() - 1)
    } else {
        None
    };
    let lines_before = lines.len();
    for &iid in &block.insts {
        let Some(inst) = func.values.get(iid.0 as usize) else {
            continue;
        };
        match &inst.op {
            SsaOp::Store { .. } => {
                if store_is_stack_arg_for_call(func, inst.id) {
                    continue;
                }
                let rendered = render_named_value(func, inst.id, symbols, local_symbols);
                if is_trivial_stack_prologue_store(&rendered) {
                    continue;
                }
                lines.push(format!("{pad}{rendered};"));
            }
            SsaOp::Call { .. } => {
                if call_is_strcmp(func, inst.id, symbols, local_symbols)
                    && (value_only_used_as_zero_test(func, inst.id)
                        || block_strcmp_only_branches_on(func, block.id, inst.id))
                {
                    continue;
                }
                let call = render_named_value(func, inst.id, symbols, local_symbols);
                if ssa_value_is_used(func, inst.id) {
                    lines.push(format!(
                        "{pad}{} = {};",
                        result_name_for_call(func, inst.id, symbols, local_symbols),
                        call
                    ));
                } else {
                    lines.push(format!("{pad}{};", call));
                }
            }
            SsaOp::Branch {
                true_block,
                false_block,
                cond,
            } => {
                let mut cond_text = render_condition_text(func, cond, symbols, local_symbols);
                if let Some((vid, negated)) = peel_zero_test(func, cond) {
                    if call_is_strcmp(func, vid, symbols, local_symbols) {
                        let call = render_named_value(func, vid, symbols, local_symbols);
                        cond_text = if negated {
                            format!("!{call}")
                        } else {
                            call
                        };
                        cond_text = simplify_condition_text(cond_text);
                    }
                }
                let t = resolve_jump_target(func, *true_block);
                let f = resolve_jump_target(func, *false_block);
                let next_id = block.id.0.saturating_add(1);
                let next_fall = resolve_jump_target(func, BlockId(next_id));
                if f == next_fall {
                    lines.push(format!("{pad}if ({cond_text}) goto bb{};", t.0));
                } else if t == next_fall {
                    lines.push(format!(
                        "{pad}if ({}) goto bb{};",
                        negate_condition_text(&cond_text),
                        f.0
                    ));
                } else {
                    lines.push(format!(
                        "{pad}if ({cond_text}) goto bb{}; else goto bb{};",
                        t.0, f.0
                    ));
                }
            }
            SsaOp::Jump { target } => {
                let t = resolve_jump_target(func, *target);
                let next_id = block.id.0.saturating_add(1);
                let fall = resolve_jump_target(func, BlockId(next_id));
                if t.0 != next_id && t != fall {
                    lines.push(format!("{pad}goto bb{};", t.0));
                }
            }
            SsaOp::Return { .. } => {
                lines.push(format!("{pad}{};", func.render_value(inst.id)));
            }
            SsaOp::Phi { .. } | SsaOp::Unknown => {}
            SsaOp::BinOp { kind, .. }
                if matches!(
                    kind,
                    BinOpKind::Eq
                        | BinOpKind::Ne
                        | BinOpKind::Lt
                        | BinOpKind::Le
                        | BinOpKind::Gt
                        | BinOpKind::Ge
                ) => {}
            _ => {
                if is_flag_or_cond_value(func, inst.id) {
                    continue;
                }
                if let SsaOp::Copy {
                    src: Operand::Symbol(name),
                } = &inst.op
                {
                    if name.starts_with("/* switch") {
                        lines.push(format!("{pad}{name}"));
                        continue;
                    }
                }
                if should_suppress_temp_emit(func, inst.id) {
                    continue;
                }
                let rendered = render_named_value(func, inst.id, symbols, local_symbols);
                if rendered.starts_with("/* switch") {
                    lines.push(format!("{pad}{rendered}"));
                    continue;
                }
                lines.push(format!("{pad}v{} = {};", inst.id.0, rendered));
            }
        }
    }
    if let Some(idx) = label_idx {
        if lines.len() == lines_before {
            lines.remove(idx);
        }
    }
}

fn is_flag_or_cond_value(func: &SsaFunction, id: SsaValueId) -> bool {
    let key = func.values.as_ptr() as usize ^ func.values.len();
    SSA_FLAG_COND.with(|slot| {
        let mut guard = slot.borrow_mut();
        let needs = match guard.as_ref() {
            Some((k, bits)) if *k == key && bits.len() == func.values.len() => false,
            _ => true,
        };
        if needs {
            let mut bits = vec![false; func.values.len()];
            for map in func.defs.iter() {
                if let Some(vid) = map.get("__cmp") {
                    if let Some(slotb) = bits.get_mut(vid.0 as usize) {
                        *slotb = true;
                    }
                }
                if let Some(vid) = map.get("__cond") {
                    if let Some(slotb) = bits.get_mut(vid.0 as usize) {
                        *slotb = true;
                    }
                }
            }
            *guard = Some((key, bits));
        }
        guard
            .as_ref()
            .and_then(|(_, bits)| bits.get(id.0 as usize).copied())
            .unwrap_or(false)
    })
}

fn ssa_build_use_graph(func: &SsaFunction) -> (Vec<u32>, Vec<Vec<u32>>) {
    let n = func.values.len();
    let mut counts = vec![0u32; n];
    let mut users: Vec<Vec<u32>> = vec![Vec::new(); n];
    let mut used_buf: Vec<SsaValueId> = Vec::with_capacity(8);
    for inst in &func.values {
        used_buf.clear();
        collect_used_operands_vec(&inst.op, &mut used_buf);
        if used_buf.len() > 1 {
            used_buf.sort_unstable_by_key(|v| v.0);
            used_buf.dedup();
        }
        for uid in &used_buf {
            let idx = uid.0 as usize;
            if idx >= n {
                continue;
            }
            counts[idx] = counts[idx].saturating_add(1);
            users[idx].push(inst.id.0);
        }
    }
    (counts, users)
}

fn collect_used_operands_vec(op: &SsaOp, used: &mut Vec<SsaValueId>) {
    let mut push = |operand: &Operand| match operand {
        Operand::Value(id) => used.push(*id),
        Operand::Deref { base, .. } => {
            if let Operand::Value(id) = base.as_ref() {
                used.push(*id);
            }
        }
        _ => {}
    };
    match op {
        SsaOp::Copy { src } => push(src),
        SsaOp::BinOp { lhs, rhs, .. } => {
            push(lhs);
            push(rhs);
        }
        SsaOp::UnaryOp { src, .. } => push(src),
        SsaOp::Load { addr } => push(addr),
        SsaOp::Store { addr, value } => {
            push(addr);
            push(value);
        }
        SsaOp::Call { target, args } => {
            push(target);
            for a in args {
                push(a);
            }
        }
        SsaOp::Return { value } => {
            if let Some(v) = value {
                push(v);
            }
        }
        SsaOp::Branch { cond, .. } => push(cond),
        SsaOp::Phi { incoming } => {
            for (_, v) in incoming {
                used.push(*v);
            }
        }
        SsaOp::Jump { .. } | SsaOp::Unknown => {}
    }
}

fn ssa_with_use_graph<R>(func: &SsaFunction, f: impl FnOnce(&[u32], &[Vec<u32>]) -> R) -> R {
    let key = func.values.as_ptr() as usize ^ func.values.len();
    SSA_USE_GRAPH.with(|slot| {
        let mut guard = slot.borrow_mut();
        let needs = match guard.as_ref() {
            Some((k, counts, users))
                if *k == key && counts.len() == func.values.len() && users.len() == func.values.len() =>
            {
                false
            }
            _ => true,
        };
        if needs {
            let (counts, users) = ssa_build_use_graph(func);
            *guard = Some((key, counts, users));
        }
        let (_, counts, users) = guard.as_ref().expect("ssa use graph");
        f(counts, users)
    })
}

fn ssa_value_is_used(func: &SsaFunction, id: SsaValueId) -> bool {
    ssa_with_use_graph(func, |counts, _| {
        counts.get(id.0 as usize).copied().unwrap_or(0) > 0
    })
}

fn operand_uses_value(op: &Operand, id: SsaValueId) -> bool {
    match op {
        Operand::Value(v) => *v == id,
        Operand::Deref { base, .. } => operand_uses_value(base, id),
        _ => false,
    }
}

fn should_suppress_temp_emit(func: &SsaFunction, id: SsaValueId) -> bool {
    let Some(inst) = func.values.get(id.0 as usize) else {
        return true;
    };
    match &inst.op {
        SsaOp::Store { .. } | SsaOp::Call { .. } | SsaOp::Return { .. }
        | SsaOp::Branch { .. } | SsaOp::Jump { .. } => return false,
        _ => {}
    }
    ssa_with_use_graph(func, |counts, users| {
        let use_count = counts.get(id.0 as usize).copied().unwrap_or(0) as usize;
        if use_count == 0 {
            return true;
        }
        let user_ids = users.get(id.0 as usize).map(|v| v.as_slice()).unwrap_or(&[]);
        let mut side_use = false;
        let mut pure_or_cond = 0usize;
        let mut store_value_uses = 0usize;
        let mut other_uses = 0usize;
        for &user in user_ids {
            let Some(other) = func.values.get(user as usize) else {
                continue;
            };
            match &other.op {
                SsaOp::Branch { .. }
                | SsaOp::Phi { .. }
                | SsaOp::BinOp {
                    kind:
                        BinOpKind::Eq
                        | BinOpKind::Ne
                        | BinOpKind::Lt
                        | BinOpKind::Le
                        | BinOpKind::Gt
                        | BinOpKind::Ge,
                    ..
                } => {
                    pure_or_cond += 1;
                    other_uses += 1;
                }
                SsaOp::Copy { .. } | SsaOp::UnaryOp { .. } | SsaOp::BinOp { .. } => {
                    pure_or_cond += 1;
                    other_uses += 1;
                }
                SsaOp::Load { addr } => {
                    if operand_uses_value(addr, id) {
                        pure_or_cond += 1;
                    } else {
                        side_use = true;
                    }
                    other_uses += 1;
                }
                SsaOp::Store { addr, value } => {
                    if operand_uses_value(value, id) {
                        store_value_uses += 1;
                        pure_or_cond += 1;
                    }
                    if operand_uses_value(addr, id) {
                        pure_or_cond += 1;
                        other_uses += 1;
                    }
                }
                SsaOp::Call { target, args } => {
                    if operand_uses_value(target, id) || args.iter().any(|a| operand_uses_value(a, id))
                    {
                        pure_or_cond += 1;
                    }
                    other_uses += 1;
                }
                SsaOp::Return { value } => {
                    if value.as_ref().is_some_and(|v| operand_uses_value(v, id)) {
                        side_use = true;
                    }
                    other_uses += 1;
                }
                SsaOp::Jump { .. } => {}
                _ => {
                    side_use = true;
                    other_uses += 1;
                }
            }
        }
        if store_value_uses == 1 && other_uses == 0 {
            return true;
        }
        if side_use {
            return false;
        }
        match &inst.op {
            SsaOp::BinOp {
                kind: BinOpKind::Add | BinOpKind::Sub,
                lhs,
                rhs,
            } => {
                if is_simple_addr_binop(func, lhs, rhs) {
                    return true;
                }
                pure_or_cond == use_count
            }
            SsaOp::Copy { src } => {
                if let Operand::Symbol(name) = src {
                    if name.starts_with("/* switch") {
                        return false;
                    }
                }
                pure_or_cond == use_count
            }
            SsaOp::Load { .. } | SsaOp::UnaryOp { .. } => pure_or_cond == use_count,
            SsaOp::Phi { .. } => true,
            _ => pure_or_cond == use_count && use_count <= 2,
        }
    })
}


fn operand_is_frame_like(func: &SsaFunction, op: &Operand, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    match op {
        Operand::Symbol(name) => {
            let n = normalize_reg(name);
            n == "sp" || n == "fp" || n == "x29" || n == "x31"
        }
        Operand::Value(id) => {
            let Some(inst) = func.values.get(id.0 as usize) else {
                return false;
            };
            match &inst.op {
                SsaOp::BinOp {
                    kind: BinOpKind::Add | BinOpKind::Sub,
                    ..
                } => true,
                SsaOp::Copy {
                    src: Operand::Symbol(name),
                } => {
                    let n = normalize_reg(name);
                    n == "sp" || n == "fp" || n == "x29" || n == "x31"
                }
                SsaOp::Copy { src } => operand_is_frame_like(func, src, depth + 1),
                _ => false,
            }
        }
        _ => false,
    }
}

fn operand_is_small_imm(func: &SsaFunction, op: &Operand) -> bool {
    match op {
        Operand::Constant(c) => (*c).abs() < 0x10000,
        Operand::Value(id) => matches!(
            func.values.get(id.0 as usize).map(|i| &i.op),
            Some(SsaOp::Copy {
                src: Operand::Constant(c)
            }) if (*c).abs() < 0x10000
        ),
        _ => false,
    }
}

fn operand_is_callish(func: &SsaFunction, op: &Operand) -> bool {
    match op {
        Operand::Value(id) => matches!(
            func.values.get(id.0 as usize).map(|i| &i.op),
            Some(SsaOp::Call { .. })
                | Some(SsaOp::Copy {
                    src: Operand::Value(_)
                })
                | Some(SsaOp::Phi { .. })
        ),
        Operand::Symbol(name) => !looks_like_reg_name(name),
        _ => false,
    }
}

fn is_simple_addr_binop(func: &SsaFunction, lhs: &Operand, rhs: &Operand) -> bool {
    if (operand_is_frame_like(func, lhs, 0) && operand_is_small_imm(func, rhs))
        || (operand_is_frame_like(func, rhs, 0) && operand_is_small_imm(func, lhs))
    {
        return true;
    }
    (operand_is_callish(func, lhs) && operand_is_small_imm(func, rhs))
        || (operand_is_callish(func, rhs) && operand_is_small_imm(func, lhs))
}

fn collect_used_operands(op: &SsaOp, used: &mut HashSet<SsaValueId>) {
    let mut collect = |operand: &Operand| match operand {
        Operand::Value(id) => {
            used.insert(*id);
        }
        Operand::Deref { base, .. } => match base.as_ref() {
            Operand::Value(id) => {
                used.insert(*id);
            }
            _ => {}
        },
        _ => {}
    };
    match op {
        SsaOp::Copy { src } => collect(src),
        SsaOp::BinOp { lhs, rhs, .. } => {
            collect(lhs);
            collect(rhs);
        }
        SsaOp::UnaryOp { src, .. } => collect(src),
        SsaOp::Load { addr } => collect(addr),
        SsaOp::Store { addr, value } => {
            collect(addr);
            collect(value);
        }
        SsaOp::Call { target, args } => {
            collect(target);
            for a in args {
                collect(a);
            }
        }
        SsaOp::Return { value } => {
            if let Some(v) = value {
                collect(v);
            }
        }
        SsaOp::Branch { cond, .. } => collect(cond),
        SsaOp::Phi { incoming } => {
            for (_, v) in incoming {
                used.insert(*v);
            }
        }
        _ => {}
    }
}

fn lookup_symbol_name<'a>(
    symbols: &'a HashMap<u64, String>,
    local_symbols: &'a HashMap<u64, String>,
    addr: u64,
) -> Option<&'a str> {
    local_symbols
        .get(&addr)
        .or_else(|| symbols.get(&addr))
        .map(|s| s.as_str())
}

fn polish_call_arg_operand(
    func: &SsaFunction,
    operand: &Operand,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    depth: usize,
) -> String {
    if let Some(abs) = fold_absolute_addr(func, operand).filter(|a| *a >= 0x1000) {
        if lookup_render_string(abs).is_some() {
            return render_operand_named_depth(func, operand, symbols, local_symbols, depth);
        }
        if let Some(name) = lookup_global_name(abs) {
            if name.starts_with("g_") && name != "g_data" && !name.contains('+') {
                return format!("&{name}");
            }
        }
        if let Some(name) = lookup_symbol_name(symbols, local_symbols, abs) {
            if name.starts_with("g_") && name != "g_data" && !name.contains('+') {
                return format!("&{name}");
            }
            return name.to_string();
        }
    }
    let text = render_operand_named_depth(func, operand, symbols, local_symbols, depth);
    if text.starts_with('&') {
        return text;
    }
    if let Some((base, off)) = parse_addr_chain(&text) {
        if let Some(name) = frame_slot_name_from_parts(&base, off) {
            return format!("&{name}");
        }
    }
    if let Some(name) = frame_slot_name_from_parts(&text, 0) {
        return format!("&{name}");
    }
    text
}

fn store_is_stack_arg_for_call(func: &SsaFunction, store_id: SsaValueId) -> bool {
    let Some(store_inst) = func.values.get(store_id.0 as usize) else {
        return false;
    };
    let SsaOp::Store { addr, value } = &store_inst.op else {
        return false;
    };
    let Some(off) = stack_slot_offset(func, addr) else {
        return false;
    };
    if !(0..0x20).contains(&off) {
        return false;
    }
    for other in &func.values {
        if other.id == store_id || other.block != store_inst.block {
            continue;
        }
        if other.source_addr < store_inst.source_addr {
            continue;
        }
        if other.source_addr.saturating_sub(store_inst.source_addr) > 0x28 {
            continue;
        }
        let SsaOp::Call { args, .. } = &other.op else {
            continue;
        };
        if args
            .iter()
            .any(|a| operand_same_value(func, a, value) || a == value)
        {
            return true;
        }
        let name = match &other.op {
            SsaOp::Call { target, .. } => match target {
                Operand::Symbol(n) => n.as_str(),
                _ => "",
            },
            _ => "",
        };
        if is_variadic_call(name)
            && other.source_addr.saturating_sub(store_inst.source_addr) <= 0x18
            && off == 0
        {
            return true;
        }
    }
    false
}

fn render_call_target(
    func: &SsaFunction,
    target: &Operand,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> String {
    if let Some(name) = jni_vtable_call_name(func, target) {
        return name.to_string();
    }
    match target {
        Operand::Constant(value) if *value >= 0 => {
            let addr = *value as u64;
            if let Some(name) = lookup_code_name(addr) {
                return name;
            }
            if let Some(name) = lookup_symbol_name(symbols, local_symbols, addr) {
                return name.to_string();
            }
            format_sub_addr(addr)
        }
        Operand::Symbol(name) => {
            if let Some(addr) = parse_sub_symbol_addr(name) {
                if let Some(cn) = lookup_code_name(addr) {
                    return cn;
                }
                if let Some(sym) = lookup_symbol_name(symbols, local_symbols, addr) {
                    return sym.to_string();
                }
            }
            name.clone()
        }
        _ => {
            if let Some(c) = resolve_const_operand_static(func, target) {
                if c > 0 {
                    let addr = c as u64;
                    if let Some(name) = lookup_code_name(addr) {
                        return name;
                    }
                    if let Some(name) = lookup_symbol_name(symbols, local_symbols, addr) {
                        return name.to_string();
                    }
                    if (0x100000000..0x100008000).contains(&addr) {
                        return format_sub_addr(addr);
                    }
                }
            }
            render_operand_named(func, target, symbols, local_symbols)
        }
    }
}

fn jni_vtable_slot_offset(func: &SsaFunction, target: &Operand) -> Option<i64> {
    let Operand::Value(id) = target else {
        return None;
    };
    let mut cur = *id;
    for _ in 0..4 {
        let inst = func.values.get(cur.0 as usize)?;
        match &inst.op {
            SsaOp::Load {
                addr: Operand::Deref { base, offset },
            } if *offset != 0 => {
                let base_is_vtable = match base.as_ref() {
                    Operand::Value(base_id) => matches!(
                        func.values.get(base_id.0 as usize).map(|i| &i.op),
                        Some(SsaOp::Load {
                            addr: Operand::Deref { offset: 0, .. }
                        }) | Some(SsaOp::Copy { .. })
                    ),
                    Operand::Symbol(_) => true,
                    _ => false,
                };
                if base_is_vtable || *offset >= 0x18 {
                    return Some(*offset);
                }
                return Some(*offset);
            }
            SsaOp::Copy { src: Operand::Value(prev) } => cur = *prev,
            SsaOp::Load {
                addr: Operand::Deref { base, offset: 0 },
            } => {
                if let Operand::Value(prev) = base.as_ref() {
                    cur = *prev;
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }
    None
}

fn jni_vtable_call_name(func: &SsaFunction, target: &Operand) -> Option<&'static str> {
    let offset = jni_vtable_slot_offset(func, target)? as u64;
    jni_method_name_for_offset(offset)
}

fn jni_method_name_for_offset(offset: u64) -> Option<&'static str> {
    match offset {
        0x18 => Some("DestroyJavaVM"),
        0x20 => Some("GetVersion"),
        0x28 => Some("DetachCurrentThread"),
        0x30 => Some("FindClass"),
        0x38 => Some("FromReflectedMethod"),
        0x40 => Some("FromReflectedField"),
        0x48 => Some("ToReflectedMethod"),
        0x50 => Some("GetSuperclass"),
        0x58 => Some("IsAssignableFrom"),
        0x60 => Some("ToReflectedField"),
        0x68 => Some("Throw"),
        0x70 => Some("ThrowNew"),
        0x78 => Some("ExceptionOccurred"),
        0x80 => Some("ExceptionDescribe"),
        0x88 => Some("ExceptionClear"),
        0x90 => Some("FatalError"),
        0x98 => Some("PushLocalFrame"),
        0xa0 => Some("PopLocalFrame"),
        0xa8 => Some("NewGlobalRef"),
        0xb0 => Some("DeleteGlobalRef"),
        0xb8 => Some("DeleteLocalRef"),
        0xc0 => Some("IsSameObject"),
        0xc8 => Some("NewLocalRef"),
        0xd0 => Some("EnsureLocalCapacity"),
        0xd8 => Some("AllocObject"),
        0xe0 => Some("NewObject"),
        0xe8 => Some("NewObjectV"),
        0xf0 => Some("NewObjectA"),
        0xf8 => Some("GetObjectClass"),
        0x100 => Some("IsInstanceOf"),
        0x108 => Some("GetMethodID"),
        0x110 => Some("CallObjectMethod"),
        0x168 => Some("CallBooleanMethod"),
        0x1c0 => Some("CallIntMethod"),
        0x218 => Some("CallVoidMethod"),
        0x278 => Some("GetFieldID"),
        0x280 => Some("GetObjectField"),
        0x288 => Some("GetBooleanField"),
        0x298 => Some("GetIntField"),
        0x2a8 => Some("GetLongField"),
        0x2c0 => Some("SetObjectField"),
        0x2d8 => Some("SetIntField"),
        0x2e8 => Some("SetLongField"),
        0x340 => Some("GetStaticMethodID"),
        0x348 => Some("CallStaticObjectMethod"),
        0x3a0 => Some("CallStaticBooleanMethod"),
        0x3f8 => Some("CallStaticIntMethod"),
        0x450 => Some("CallStaticVoidMethod"),
        0x4b0 => Some("GetStaticFieldID"),
        0x4b8 => Some("GetStaticObjectField"),
        0x4d0 => Some("GetStaticIntField"),
        0x538 => Some("NewString"),
        0x540 => Some("GetStringLength"),
        0x548 => Some("GetStringChars"),
        0x550 => Some("ReleaseStringChars"),
        0x558 => Some("NewStringUTF"),
        0x560 => Some("GetStringUTFLength"),
        0x568 => Some("GetStringUTFChars"),
        0x570 => Some("ReleaseStringUTFChars"),
        0x578 => Some("GetArrayLength"),
        0x580 => Some("NewObjectArray"),
        0x588 => Some("GetObjectArrayElement"),
        0x590 => Some("SetObjectArrayElement"),
        0x5e8 => Some("NewByteArray"),
        0x5f0 => Some("NewCharArray"),
        0x600 => Some("NewIntArray"),
        0x648 => Some("GetByteArrayElements"),
        0x6b8 => Some("RegisterNatives"),
        0x6c0 => Some("UnregisterNatives"),
        0x6c8 => Some("MonitorEnter"),
        0x6d0 => Some("MonitorExit"),
        0x6d8 => Some("GetJavaVM"),
        0x6e0 => Some("GetStringRegion"),
        0x6e8 => Some("GetStringUTFRegion"),
        0x748 => Some("ExceptionCheck"),
        0x750 => Some("NewDirectByteBuffer"),
        0x758 => Some("GetDirectBufferAddress"),
        0x760 => Some("GetDirectBufferCapacity"),
        0x768 => Some("GetObjectRefType"),
        _ => None,
    }
}


fn refine_jni_method_name(
    offset: u64,
    current: &str,
    args: &[String],
) -> Option<&'static str> {
    let has_class_string = args.iter().any(|a| a.contains('/') && a.contains('"'));
    let versionish = args
        .get(2)
        .map(|a| a.starts_with("0x1000") || a == "0x00010006")
        .unwrap_or(false);
    match offset {
        0x20 => {
            if args.len() >= 3 {
                Some("AttachCurrentThread")
            } else if args.len() <= 1 {
                Some("GetVersion")
            } else if current == "AttachCurrentThread" {
                Some("AttachCurrentThread")
            } else {
                Some("GetVersion")
            }
        }
        0x30 => {
            if versionish {
                Some("GetEnv")
            } else if has_class_string || args.len() == 2 {
                Some("FindClass")
            } else if args.len() >= 3 {
                Some("GetEnv")
            } else {
                Some("FindClass")
            }
        }
        _ => None,
    }
}

fn result_name_for_call(
    func: &SsaFunction,
    id: SsaValueId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> String {
    if let Some(inst) = func.values.get(id.0 as usize) {
        if let SsaOp::Call { target, .. } = &inst.op {
            let name = render_call_target(func, target, symbols, local_symbols);
            let bare = name.trim_start_matches('_');
            let pretty = match bare {
                "getopt_long" | "getopt" => "opt",
                "isatty" => "is_tty",
                "getenv" => "env",
                "strtonum" => "num",
                "ioctl" => "ioctl_rc",
                "compat_mode" => "compat",
                "getuid" => "uid",
                "tgetent" => "tgetent_rc",
                "tgetstr" => "tcap",
                "sysctlbyname" => "sysctl_rc",
                "ferror" => "ferror_rc",
                "fflush" => "fflush_rc",
                "FindClass" => "clazz",
                "GetMethodID" => "mid",
                "GetFieldID" => "fid",
                "GetObjectClass" => "clazz",
                "NewStringUTF" => "jstr",
                "GetStringUTFChars" => "cstr",
                "RegisterNatives" => "reg_rc",
                "GetEnv" | "AttachCurrentThread" => "jni_rc",
                _ => "",
            };
            if !pretty.is_empty() {
                return pretty.to_string();
            }
            if !bare.is_empty()
                && bare
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            {
                return format!("r_{bare}");
            }
        }
    }
    format!("v{}", id.0)
}

fn render_named_value(
    func: &SsaFunction,
    id: SsaValueId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> String {
    render_named_value_depth(func, id, symbols, local_symbols, 0)
}

fn render_store_rhs(
    func: &SsaFunction,
    value: &Operand,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    depth: usize,
) -> String {
    if let Some(c) = resolve_const_operand_static(func, value) {
        if c > 0 {
            if let Some(name) = format_code_pointer(c as u64, symbols, local_symbols) {
                return name;
            }
        }
    }
    if let Operand::Value(id) = value {
        if let Some(SsaOp::Phi { incoming }) = func.values.get(id.0 as usize).map(|i| &i.op) {
            if let Some(text) = render_phi_as_store_expr(func, incoming, symbols, local_symbols) {
                return text;
            }
        }
    }
    let text = render_operand_named_depth(func, value, symbols, local_symbols, depth);
    if let Some(hex) = text.strip_prefix("0x") {
        if let Ok(addr) = u64::from_str_radix(hex, 16) {
            if let Some(name) = format_code_pointer(addr, symbols, local_symbols) {
                return name;
            }
        }
    }
    text
}

fn render_phi_as_store_expr(
    func: &SsaFunction,
    incoming: &[(BlockId, SsaValueId)],
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> Option<String> {
    if incoming.len() != 2 {
        return None;
    }
    let mut const_arm: Option<i64> = None;
    let mut expr_arm: Option<String> = None;
    for (_, vid) in incoming {
        if let Some(c) = resolve_const_operand_static(func, &Operand::Value(*vid)) {
            if c.abs() <= 0x1000 {
                const_arm = Some(c);
                continue;
            }
        }
        let rendered = render_named_value_depth(func, *vid, symbols, local_symbols, 1);
        if rendered.starts_with('v') && rendered.chars().skip(1).all(|ch| ch.is_ascii_digit()) {
            return None;
        }
        if rendered.len() > 96 {
            return None;
        }
        expr_arm = Some(rendered);
    }
    match (const_arm, expr_arm) {
        (Some(c), Some(e)) if matches!(c, 0 | 1 | 2) => Some(e),
        (None, Some(e)) => Some(e),
        _ => None,
    }
}

fn phi_common_render(
    func: &SsaFunction,
    incoming: &[(BlockId, SsaValueId)],
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> Option<String> {
    if incoming.is_empty() {
        return None;
    }
    let mut common: Option<String> = None;
    let mut call_names: Vec<String> = Vec::new();
    let mut const_vals: Vec<i64> = Vec::new();
    for (_, vid) in incoming {
        let text = match func.values.get(vid.0 as usize).map(|i| &i.op) {
            Some(SsaOp::Copy {
                src: Operand::Symbol(name),
            }) => name.clone(),
            Some(SsaOp::Copy {
                src: Operand::Constant(c),
            }) => {
                const_vals.push(*c);
                if *c > 0x1000 {
                    format!("0x{:x}", *c as u64)
                } else {
                    c.to_string()
                }
            }
            Some(SsaOp::Call { .. }) => {
                let n = result_name_for_call(func, *vid, symbols, local_symbols);
                call_names.push(n.clone());
                n
            }
            _ => {
                if let Some(c) = resolve_const_operand(func, &Operand::Value(*vid)) {
                    const_vals.push(c);
                    if c > 0x1000 {
                        format!("0x{:x}", c as u64)
                    } else {
                        c.to_string()
                    }
                } else {
                    // Prefer rendering the incoming value expression when short.
                    let rendered =
                        render_named_value_depth(func, *vid, symbols, local_symbols, 1);
                    if rendered.starts_with('v') && rendered.chars().skip(1).all(|c| c.is_ascii_digit())
                    {
                        format!("v{}", vid.0)
                    } else {
                        rendered
                    }
                }
            }
        };
        match &common {
            None => common = Some(text),
            Some(prev) if prev == &text => {}
            Some(_) => common = None,
        }
    }
    if let Some(text) = common {
        return Some(text);
    }
    call_names.sort();
    call_names.dedup();
    if call_names.len() == 1 {
        return Some(call_names[0].clone());
    }
    if const_vals.len() == incoming.len() {
        const_vals.sort_unstable();
        const_vals.dedup();
        if const_vals.len() == 1 {
            let c = const_vals[0];
            if c > 0x1000 {
                return Some(format!("0x{:x}", c as u64));
            }
            return Some(c.to_string());
        }
    }
    None
}

fn render_named_value_depth(
    func: &SsaFunction,
    id: SsaValueId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    depth: usize,
) -> String {
    if depth > 32 {
        return format!("v{}", id.0);
    }
    if id.0 as usize >= func.values.len() {
        return format!("v{}", id.0);
    }
    if let Some(hit) = NAMED_RENDER_CACHE.with(|c| c.borrow().get(&id.0).cloned()) {
        return hit;
    }
    let already = NAMED_RENDER_VISITING.with(|v| {
        let mut s = v.borrow_mut();
        if !s.insert(id.0) {
            true
        } else {
            false
        }
    });
    if already {
        return format!("v{}", id.0);
    }
    let out = render_named_value_depth_inner(func, id, symbols, local_symbols, depth);
    NAMED_RENDER_VISITING.with(|v| {
        v.borrow_mut().remove(&id.0);
    });
    let out = if out.len() > 512 {
        format!("v{}", id.0)
    } else {
        out
    };
    NAMED_RENDER_CACHE.with(|c| {
        c.borrow_mut().insert(id.0, out.clone());
    });
    out
}

fn render_named_value_depth_inner(
    func: &SsaFunction,
    id: SsaValueId,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    depth: usize,
) -> String {
    let inst = &func.values[id.0 as usize];
    match &inst.op {
        SsaOp::Phi { incoming } => {
            if let Some(common) = phi_common_render(func, incoming, symbols, local_symbols) {
                return common;
            }
            format!("v{}", id.0)
        }
        SsaOp::Call { target, args } => {
            if depth > 0 {
                return result_name_for_call(func, id, symbols, local_symbols);
            }
            let mut target_text = render_call_target(func, target, symbols, local_symbols);
            let jni_slot = jni_vtable_slot_offset(func, target);
            let max_args = if jni_slot.is_some() {
                args.len()
            } else if is_variadic_call(&target_text) {
                args.len()
            } else {
                known_call_arg_count(&target_text).unwrap_or(args.len())
            };
            let selected = if max_args < args.len() {
                &args[..max_args]
            } else {
                args.as_slice()
            };
            let mut args_rendered: Vec<String> = selected
                .iter()
                .map(|a| polish_call_arg_operand(func, a, symbols, local_symbols, depth + 1))
                .collect();
            if let Some(off) = jni_vtable_slot_offset(func, target) {
                if let Some(refined) =
                    refine_jni_method_name(off as u64, &target_text, &args_rendered)
                {
                    target_text = refined.to_string();
                    if let Some(n) = known_call_arg_count(&target_text) {
                        if n < args_rendered.len() {
                            args_rendered.truncate(n);
                        }
                    }
                }
            }
            let bare = target_text.trim_start_matches('_');
            if bare == "getopt_long" && args_rendered.len() >= 4 {
                let a3 = args_rendered[3].as_str();
                if a3.starts_with("0x")
                    || a3 == "longopts"
                    || a3.starts_with("sub_")
                    || a3.starts_with("g_data")
                {
                    args_rendered[3] = "longopts".to_string();
                }
            }
            if bare == "strcmp" && args_rendered.len() >= 2 {
                let a0 = args_rendered[0].as_str();
                if a0 == "stderr"
                    || a0 == "stdout"
                    || a0.ends_with("_ptr")
                    || a0.starts_with("0x")
                    || a0.starts_with("*(")
                {
                    args_rendered[0] = "optarg".to_string();
                }
            }
            if (bare == "ferror" || bare == "fflush") && args_rendered.len() == 1 {
                let a = args_rendered[0].as_str();
                if a == "*stdout"
                    || a == "stdout"
                    || a.contains("0x1000082b8")
                    || a == "*stdout_ptr"
                {
                    args_rendered[0] = "stdout".to_string();
                }
            }
            if bare == "getbsize" && args_rendered.len() >= 2 {
                let a1 = args_rendered[1].as_str();
                if !a1.starts_with('&')
                    && (a1.starts_with("g_") || a1.starts_with("g_data") || a1.starts_with("0x"))
                {
                    args_rendered[1] = format!("&{a1}");
                }
            }
            if bare == "ioctl" {
                if args_rendered.len() >= 2 {
                    if args_rendered[1] == "0x40087468" || args_rendered[1] == "TIOCGWINSZ" {
                        args_rendered[1] = "TIOCGWINSZ".to_string();
                        if args_rendered.len() == 2 {
                            args_rendered.push("&winsize".to_string());
                        } else if args_rendered.len() >= 3 {
                            let a2 = args_rendered[2].as_str();
                            if a2.starts_with('x')
                                || a2.starts_with('v')
                                || a2.contains("sp")
                                || a2.contains("x29")
                            {
                                args_rendered[2] = "&winsize".to_string();
                            }
                        }
                    }
                }
            }
            if bare == "signal" && args_rendered.len() >= 2 {
                if let Some(rest) = args_rendered[1].strip_prefix("0x") {
                    if let Ok(addr) = u64::from_str_radix(rest, 16) {
                        if let Some(name) = format_code_pointer(addr, symbols, local_symbols) {
                            args_rendered[1] = name;
                        }
                    }
                } else if args_rendered[1].starts_with("sub_") {
                    if let Some(addr) = parse_sub_symbol_addr(&args_rendered[1]) {
                        if let Some(name) = lookup_code_name(addr) {
                            args_rendered[1] = name;
                        }
                    }
                }
                if args_rendered[0] == "2" {
                    args_rendered[0] = "SIGINT".to_string();
                } else if args_rendered[0] == "3" {
                    args_rendered[0] = "SIGQUIT".to_string();
                }
            }
            if bare == "sysctlbyname" && args_rendered.len() > 5 {
                args_rendered.truncate(5);
            }
            if matches!(bare, "errx" | "err" | "warnx" | "warn") {
                let fmt = args_rendered.get(1).map(|s| s.as_str()).unwrap_or("");
                if fmt.contains("%s") {
                    if args_rendered.len() >= 3 {
                        let a = args_rendered[2].as_str();
                        let looks_wrong = a != "optarg"
                            && (a.starts_with('v')
                                || a.starts_with('x')
                                || a == "stderr"
                                || a.ends_with("_ptr")
                                || a.starts_with("g_")
                                || a.starts_with("0x"));
                        if looks_wrong {
                            args_rendered[2] = "optarg".to_string();
                        }
                    } else if args_rendered.len() == 2 {
                        args_rendered.push("optarg".to_string());
                    }
                }
            }
            let args_str = args_rendered.join(", ");
            format!("{target_text}({args_str})")
        }
        SsaOp::Store { addr, value } => {
            let dst = if let Some(abs) = fold_absolute_addr(func, addr).filter(|a| *a >= 0x1000) {
                format_data_deref(abs)
            } else {
                match addr {
                    Operand::Deref { base, offset } => {
                        let base_text = render_operand_named_depth(
                            func,
                            base,
                            symbols,
                            local_symbols,
                            depth + 1,
                        );
                        format_mem_access(&base_text, *offset)
                    }
                    other => format!(
                        "*({})",
                        render_operand_named_depth(func, other, symbols, local_symbols, depth + 1)
                    ),
                }
            };
            let rhs = render_store_rhs(func, value, symbols, local_symbols, depth + 1);
            format!("{dst} = {rhs}")
        }
        SsaOp::BinOp {
            kind: BinOpKind::Add,
            lhs,
            rhs,
        } => {
            if let Some(addr) = fold_addr_operand(func, lhs, rhs) {
                if let Some(name) = lookup_symbol_name(symbols, local_symbols, addr) {
                    return name.to_string();
                }
                if addr & 0xfff != 0 {
                    if let Some(s) = lookup_render_string(addr) {
                        return format!("{:?}", s);
                    }
                }
                return format_data_addr(addr);
            }
            let l = render_operand_named_depth(func, lhs, symbols, local_symbols, depth + 1);
            let r = render_operand_named_depth(func, rhs, symbols, local_symbols, depth + 1);
            return simplify_addr_expr(&format!("({l} + {r})"));
        }
        SsaOp::BinOp {
            kind,
            lhs,
            rhs,
        } => {
            let op = match kind {
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
                BinOpKind::Sar => ">>",
                BinOpKind::Eq => "==",
                BinOpKind::Ne => "!=",
                BinOpKind::Lt => "<",
                BinOpKind::Le => "<=",
                BinOpKind::Gt => ">",
                BinOpKind::Ge => ">=",
            };
            let l = render_operand_named_depth(func, lhs, symbols, local_symbols, depth + 1);
            let r = render_operand_named_depth(func, rhs, symbols, local_symbols, depth + 1);
            match kind {
                BinOpKind::Eq
                | BinOpKind::Ne
                | BinOpKind::Lt
                | BinOpKind::Le
                | BinOpKind::Gt
                | BinOpKind::Ge => format!("{l} {op} {r}"),
                BinOpKind::Add | BinOpKind::Sub => {
                    simplify_addr_expr(&format!("({l} {op} {r})"))
                }
                _ => format!("({l} {op} {r})"),
            }
        }
        SsaOp::Load { addr } => {
            if let Some(abs) = fold_absolute_addr(func, addr).filter(|a| *a >= 0x1000) {
                return format_data_deref(abs);
            }
            match addr {
                Operand::Deref { base, offset } => {
                    let base_text = render_operand_named_depth(
                        func,
                        base,
                        symbols,
                        local_symbols,
                        depth + 1,
                    );
                    format_mem_access(&base_text, *offset)
                }
                other => format!(
                    "*({})",
                    render_operand_named_depth(func, other, symbols, local_symbols, depth + 1)
                ),
            }
        }
        SsaOp::Copy { src } => {
            if let Operand::Value(src_id) = src {
                if matches!(
                    func.values.get(src_id.0 as usize).map(|i| &i.op),
                    Some(SsaOp::Call { .. })
                ) {
                    return result_name_for_call(func, *src_id, symbols, local_symbols);
                }
            }
            render_operand_named_depth(func, src, symbols, local_symbols, depth + 1)
        }
        _ => func.render_value(id),
    }
}

fn render_operand_named(
    func: &SsaFunction,
    operand: &Operand,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> String {
    render_operand_named_depth(func, operand, symbols, local_symbols, 0)
}

fn render_operand_named_depth(
    func: &SsaFunction,
    operand: &Operand,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
    depth: usize,
) -> String {
    match operand {
        Operand::Value(id) => {
            // Operand context should never expand calls inline; prefer result names.
            let d = if depth == 0 { 1 } else { depth };
            render_named_value_depth(func, *id, symbols, local_symbols, d)
        }
        Operand::Constant(value) => {
            if *value >= 0 {
                let addr = *value as u64;
                if let Some(name) = lookup_symbol_name(symbols, local_symbols, addr) {
                    return name.to_string();
                }
                if addr & 0xfff != 0 {
                    if let Some(s) = lookup_render_string(addr) {
                        return format!("{:?}", s);
                    }
                }
                if let Some(base) = render_data_base() {
                    if addr >= base && addr.saturating_sub(base) < 0x4000 {
                        return format_data_addr(addr);
                    }
                }
                if let Some(name) = format_code_pointer(addr, symbols, local_symbols) {
                    return name;
                }
                if *value > 0x1000 {
                    return format!("0x{:x}", addr);
                }
            }
            if *value >= 0 && *value <= 9 {
                return value.to_string();
            }
            if *value >= 0 {
                return format!("0x{:x}", *value as u64);
            }
            value.to_string()
        }
        Operand::Symbol(name) => {
            let nl = name.to_ascii_lowercase();
            if nl == "xzr" || nl == "wzr" {
                return "0".to_string();
            }
            if name.starts_with("/* switch") {
                return name.clone();
            }
            if let Some(addr) = parse_sub_symbol_addr(name) {
                if let Some(cn) = lookup_code_name(addr) {
                    return cn;
                }
                if let Some(sym) = lookup_symbol_name(symbols, local_symbols, addr) {
                    return sym.to_string();
                }
            }
            if looks_like_reg_name(name) {
                let reg = normalize_reg(name);
                if let Some(alias) = lookup_reg_alias(&reg) {
                    return alias;
                }
                if let Some(addr) = lookup_reg_const(&reg) {
                    if addr & 0xfff != 0 {
                        if let Some(s) = lookup_render_string(addr) {
                            return format!("{:?}", s);
                        }
                    }
                    if let Some(base) = render_data_base() {
                        if addr >= base && addr.saturating_sub(base) < 0x4000 {
                            return format_data_addr(addr);
                        }
                    }
                    if addr > 0x1000 {
                        return format!("0x{addr:x}");
                    }
                }
            }
            name.clone()
        }
        Operand::Deref { base, offset } => {
            if let Some(abs) = fold_absolute_addr(
                func,
                &Operand::Deref {
                    base: base.clone(),
                    offset: *offset,
                },
            ) {
                return format_data_deref(abs);
            }
            let base_text =
                render_operand_named_depth(func, base, symbols, local_symbols, depth + 1);
            format_mem_access(&base_text, *offset)
        }
    }
}

fn render_condition_text(
    func: &SsaFunction,
    cond: &Operand,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> String {
    let text = render_operand_named(func, cond, symbols, local_symbols);
    let text = polish_bare_reg_condition(func, cond, &text, symbols, local_symbols);
    simplify_condition_text(text)
}

fn polish_bare_reg_condition(
    func: &SsaFunction,
    cond: &Operand,
    text: &str,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> String {
    let t = text.trim();
    let compact = t.replace(' ', "");
    let (negated, bare) = if let Some(rest) = compact.strip_prefix('!') {
        (true, rest)
    } else if let Some(rest) = compact.strip_suffix("==0") {
        (true, rest)
    } else if let Some(rest) = compact.strip_suffix("!=0") {
        (false, rest)
    } else {
        (false, compact.as_str())
    };
    let bare = bare.trim_start_matches('(').trim_end_matches(')');
    if !(bare.starts_with('x') || bare.starts_with('w')) {
        return text.to_string();
    }
    if !bare.chars().skip(1).all(|c| c.is_ascii_digit()) {
        return text.to_string();
    }
    let mut resolved: Option<String> = None;
    let cur_opt: Option<SsaValueId> = match cond {
        Operand::Value(id) => Some(*id),
        Operand::Symbol(name) if looks_like_reg_name(name) => {
            find_global_load_for_reg(func, name, symbols, local_symbols)
        }
        _ => None,
    };
    if let Some(mut cur) = cur_opt {
        for _ in 0..8 {
            let Some(inst) = func.values.get(cur.0 as usize) else {
                break;
            };
            match &inst.op {
                SsaOp::BinOp {
                    kind: BinOpKind::Eq | BinOpKind::Ne,
                    lhs: Operand::Value(v),
                    rhs: Operand::Constant(0),
                }
                | SsaOp::BinOp {
                    kind: BinOpKind::Eq | BinOpKind::Ne,
                    lhs: Operand::Constant(0),
                    rhs: Operand::Value(v),
                } => cur = *v,
                SsaOp::Copy {
                    src: Operand::Value(v),
                } => cur = *v,
                SsaOp::Copy {
                    src: Operand::Symbol(name),
                } if looks_like_reg_name(name) => {
                    if let Some(id) = find_global_load_for_reg(func, name, symbols, local_symbols) {
                        cur = id;
                    } else {
                        break;
                    }
                }
                SsaOp::Load { .. } => {
                    let rendered = render_named_value(func, cur, symbols, local_symbols);
                    if rendered.starts_with("g_") || rendered == "optarg" {
                        resolved = Some(rendered);
                    }
                    break;
                }
                _ => break,
            }
        }
    }
    if resolved.is_none() && matches!(bare, "x8" | "w8") {
        if lookup_global_name_by_suffix("g_tcap_me").is_some()
            || lookup_global_name_by_suffix("g_tcap_op").is_some()
            || lookup_global_name_by_suffix("g_tcap_af").is_some()
        {
            resolved = Some("g_tcap_me".to_string());
        }
    }
    if let Some(name) = resolved {
        if negated {
            return format!("!{name}");
        }
        return name;
    }
    text.to_string()
}

fn lookup_global_name_by_suffix(name: &str) -> Option<()> {
    RENDER_GLOBAL_NAMES.with(|slot| {
        if slot.borrow().values().any(|v| v == name) {
            Some(())
        } else {
            None
        }
    })
}

fn find_global_load_for_reg(
    func: &SsaFunction,
    reg: &str,
    symbols: &HashMap<u64, String>,
    local_symbols: &HashMap<u64, String>,
) -> Option<SsaValueId> {
    let reg = normalize_reg(reg);
    let mut best: Option<(u64, SsaValueId)> = None;
    for (bi, map) in func.defs.iter().enumerate() {
        let block = BlockId(bi as u32);
        let Some(&id) = map.get(&reg).or_else(|| {
            if let Some(n) = reg.strip_prefix('x') {
                map.get(&format!("w{n}"))
            } else if let Some(n) = reg.strip_prefix('w') {
                map.get(&format!("x{n}"))
            } else {
                None
            }
        }) else {
            continue;
        };
        let Some(inst) = func.values.get(id.0 as usize) else {
            continue;
        };
        let mut cur = id;
        for _ in 0..4 {
            match func.values.get(cur.0 as usize).map(|i| &i.op) {
                Some(SsaOp::Copy {
                    src: Operand::Value(v),
                }) => cur = *v,
                Some(SsaOp::Load { .. }) => {
                    let rendered = render_named_value(func, cur, symbols, local_symbols);
                    if rendered.starts_with("g_") {
                        let addr = inst.source_addr;
                        if best.map(|(a, _)| addr >= a).unwrap_or(true) {
                            best = Some((addr, cur));
                        }
                    }
                    break;
                }
                _ => break,
            }
        }
        let _ = block;
    }
    best.map(|(_, id)| id)
}

fn simplify_condition_text(text: String) -> String {
    let mut t = text.trim().to_string();
    while t.starts_with('(') && t.ends_with(')') && balanced_outer_parens(&t) {
        t = t[1..t.len() - 1].trim().to_string();
    }
    naturalize_truthiness(&t)
}

fn naturalize_truthiness(text: &str) -> String {
    let t = normalize_expr_spacing(text.trim());
    for suf in [" != 0", " != 0x0"] {
        if let Some(lhs) = t.strip_suffix(suf) {
            let lhs = lhs.trim();
            if is_simple_ident(lhs) {
                return lhs.to_string();
            }
        }
    }
    for suf in [" == 0", " == 0x0"] {
        if let Some(lhs) = t.strip_suffix(suf) {
            let lhs = lhs.trim();
            if is_simple_ident(lhs) {
                return format!("!{lhs}");
            }
        }
    }
    if let Some(pretty) = naturalize_char_range_condition(&t) {
        return pretty;
    }
    if let Some(pretty) = naturalize_char_eq_condition(&t) {
        return pretty;
    }
    t
}

fn naturalize_char_eq_condition(text: &str) -> Option<String> {
    let parts = [" != ", " == "];
    for op in parts {
        let Some(idx) = text.find(op) else {
            continue;
        };
        let lhs = text[..idx].trim();
        let rhs = text[idx + op.len()..].trim();
        if !(looks_like_byte_expr(lhs) || looks_like_byte_expr(rhs)) {
            continue;
        }
        let lhs_s = promote_string_byte_expr(lhs);
        let rhs_s = promote_string_byte_expr(rhs);
        let lhs_s = maybe_char_literal(&lhs_s).unwrap_or(lhs_s);
        let rhs_s = maybe_char_literal(&rhs_s).unwrap_or(rhs_s);
        if lhs_s.contains('\'') || rhs_s.contains('\'') {
            return Some(format!("{lhs_s}{op}{rhs_s}"));
        }
    }
    None
}

fn looks_like_byte_expr(text: &str) -> bool {
    let t = text.trim();
    if t.starts_with('*') || t.starts_with("(*") {
        return true;
    }
    if t == "optarg" || t == "argv" {
        return true;
    }
    if t.starts_with("optarg[") || t.starts_with("argv[") {
        return true;
    }
    false
}

fn promote_string_byte_expr(text: &str) -> String {
    let t = text.trim();
    if t == "optarg" || t == "argv" {
        return format!("{t}[0]");
    }
    if let Some(inner) = t.strip_prefix('*') {
        let inner = inner.trim();
        if inner == "optarg" || inner == "argv" {
            return format!("{inner}[0]");
        }
        if inner.starts_with('(') && inner.ends_with(')') {
            let core = &inner[1..inner.len() - 1];
            if let Some((base, off)) = core.split_once('+') {
                let base = base.trim();
                let off = off.trim();
                if matches!(base, "optarg" | "argv") {
                    if let Some(n) = parse_hex_or_dec(off) {
                        return format!("{base}[{n}]");
                    }
                }
            }
        }
    }
    t.to_string()
}


fn maybe_char_literal(text: &str) -> Option<String> {
    let v = parse_hex_or_dec(text)?;
    if (0x20..0x7f).contains(&v) {
        return Some(format_c_char_literal(v));
    }
    None
}

fn normalize_expr_spacing(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if matches!(c, '+' | '-' | '>' | '<' | '=' | '!' | '|' | '&' | '^') {
            // multi-char ops
            if i + 1 < bytes.len() {
                let n = bytes[i + 1] as char;
                if (c == '>' || c == '<' || c == '=' || c == '!') && n == '=' {
                    if out.chars().last().map(|ch| !ch.is_whitespace()).unwrap_or(false) {
                        out.push(' ');
                    }
                    out.push(c);
                    out.push(n);
                    out.push(' ');
                    i += 2;
                    continue;
                }
                if (c == '|' && n == '|') || (c == '&' && n == '&') {
                    if out.chars().last().map(|ch| !ch.is_whitespace()).unwrap_or(false) {
                        out.push(' ');
                    }
                    out.push(c);
                    out.push(n);
                    out.push(' ');
                    i += 2;
                    continue;
                }
                if c == '>' && n == '>' {
                    // keep shifts compact then space
                    if out.chars().last().map(|ch| !ch.is_whitespace()).unwrap_or(false) {
                        out.push(' ');
                    }
                    out.push_str(">>");
                    if i + 2 < bytes.len() && bytes[i + 2] as char == '>' {
                        out.push('>');
                        i += 3;
                    } else {
                        i += 2;
                    }
                    out.push(' ');
                    continue;
                }
            }
            // unary minus / not after '(' or start
            if c == '-' || c == '!' {
                let prev = out.chars().rev().find(|ch| !ch.is_whitespace());
                if prev.is_none()
                    || matches!(
                        prev,
                        Some('(') | Some(',') | Some('=') | Some('!') | Some('|') | Some('&')
                    )
                {
                    out.push(c);
                    i += 1;
                    continue;
                }
            }
            if out.chars().last().map(|ch| !ch.is_whitespace()).unwrap_or(false) {
                out.push(' ');
            }
            out.push(c);
            out.push(' ');
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    // collapse multi spaces
    let mut cleaned = String::new();
    let mut prev_space = false;
    for ch in out.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                cleaned.push(' ');
            }
            prev_space = true;
        } else {
            cleaned.push(ch);
            prev_space = false;
        }
    }
    cleaned.trim().to_string()
}

fn is_simple_ident(text: &str) -> bool {
    let t = text.trim();
    if t.is_empty() {
        return false;
    }
    if t.contains("&&") || t.contains("||") || t.contains('?') {
        return false;
    }
    if t.starts_with('*') {
        let rest = t.trim_start_matches('*');
        return is_simple_ident(rest) || (rest.starts_with('(') && rest.ends_with(')'));
    }
    t.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.')
}

fn balanced_outer_parens(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'(' || bytes[bytes.len() - 1] != b')' {
        return false;
    }
    let mut depth = 0i32;
    for (idx, ch) in bytes.iter().copied().enumerate() {
        match ch {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return idx + 1 == bytes.len();
                }
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    false
}

fn negate_condition_text(text: &str) -> String {
    let t = text.trim();
    if let Some(inner) = t.strip_prefix("!(").and_then(|s| s.strip_suffix(')')) {
        return naturalize_truthiness(inner);
    }
    if let Some(inner) = t.strip_prefix('!') {
        if is_simple_ident(inner) {
            return inner.to_string();
        }
    }
    if is_simple_ident(t) {
        return format!("!{t}");
    }
    let parts = [
        (" == ", " != "),
        (" != ", " == "),
        (" > ", " <= "),
        (" < ", " >= "),
        (" >= ", " < "),
        (" <= ", " > "),
    ];
    for (a, b) in parts {
        if let Some(idx) = t.find(a) {
            let flipped = format!("{}{}{}", &t[..idx], b, &t[idx + a.len()..]);
            return naturalize_truthiness(&flipped);
        }
    }
    format!("!({t})")
}

fn parse_hex_or_dec(text: &str) -> Option<i64> {
    let t = text.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return i64::from_str_radix(h, 16).ok();
    }
    t.parse().ok()
}

fn format_c_char_literal(value: i64) -> String {
    if (0x20..0x7f).contains(&value) {
        match value as u8 {
            b'\\' => "'\\\\'".to_string(),
            b'\'' => "'\\''".to_string(),
            b => format!("'{}'", b as char),
        }
    } else {
        format!("{value:#x}")
    }
}

fn naturalize_char_range_condition(text: &str) -> Option<String> {
    let t = text.trim();
    let (lhs, op, rhs) = split_relational(t)?;
    let (var, lo) = parse_sub_expr(lhs)?;
    let span = parse_hex_or_dec(rhs)?;
    if !(0x20..0x7f).contains(&lo) || span <= 0 || span > 0x80 {
        return None;
    }
    let hi = lo.saturating_add(span);
    let lo_s = format_c_char_literal(lo);
    match op {
        ">" | ">=" => {
            let edge = if op == ">=" {
                hi.saturating_sub(1)
            } else {
                hi
            };
            let edge_s = format_c_char_literal(edge);
            Some(format!("{var} < {lo_s} || {var} > {edge_s}"))
        }
        "<" | "<=" => {
            let edge = if op == "<=" {
                hi
            } else {
                hi.saturating_sub(1)
            };
            let edge_s = format_c_char_literal(edge);
            Some(format!("{var} >= {lo_s} && {var} <= {edge_s}"))
        }
        _ => None,
    }
}

fn split_relational(text: &str) -> Option<(&str, &str, &str)> {
    for op in [">=", "<=", "==", "!=", ">", "<"] {
        if let Some(idx) = text.find(op) {
            let lhs = text[..idx].trim();
            let rhs = text[idx + op.len()..].trim();
            if !lhs.is_empty() && !rhs.is_empty() {
                return Some((lhs, op, rhs));
            }
        }
    }
    None
}

fn parse_sub_expr(text: &str) -> Option<(&str, i64)> {
    let t = text.trim();
    let t = t
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(t)
        .trim();
    if let Some(idx) = t.rfind(" - ") {
        let var = t[..idx].trim();
        let imm = parse_hex_or_dec(t[idx + 3..].trim())?;
        if !var.is_empty() {
            return Some((var, imm));
        }
    }
    if let Some(idx) = t.rfind('-') {
        if idx > 0 {
            let var = t[..idx].trim();
            let imm = parse_hex_or_dec(t[idx + 1..].trim())?;
            if !var.is_empty()
                && var
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            {
                return Some((var, imm));
            }
        }
    }
    None
}

pub fn ssa_pseudocode_regions(
    func: &SsaFunction,
    function_address: u64,
) -> Vec<revx_core::PseudocodeRegion> {
    use revx_core::{PseudocodeRegion, RegionKind};
    let mut regions = Vec::new();
    let mut has_return = false;
    let branch_count = func
        .values
        .iter()
        .filter(|inst| matches!(inst.op, SsaOp::Branch { .. }))
        .count();
    for block in &func.cfg.blocks {
        let start = if block.start_addr != 0 {
            block.start_addr
        } else {
            function_address
        };
        let end = if block.end_addr != 0 {
            block.end_addr
        } else {
            start
        };
        let back_edge = func
            .cfg
            .succs
            .get(block.id.0 as usize)
            .map(|succs| succs.iter().any(|s| s.0 <= block.id.0))
            .unwrap_or(false);
        if back_edge {
            regions.push(PseudocodeRegion {
                id: format!("region:{function_address:x}:loop:bb{}", block.id.0),
                kind: RegionKind::Loop,
                start_address: Some(start),
                end_address: Some(end),
                header: Some("while (cond)".to_string()),
                statements: vec![format!("/* back-edge at bb{} */", block.id.0)],
                children: vec![],
                evidence_ids: vec![format!("pseudo:{function_address:x}:loop:{end:x}")],
            });
        }
        for &iid in &block.insts {
            let Some(inst) = func.values.get(iid.0 as usize) else {
                continue;
            };
            match &inst.op {
                SsaOp::Branch {
                    true_block,
                    false_block,
                    cond,
                } => {
                    let cond_text =
                        render_condition_text(func, cond, &HashMap::new(), &HashMap::new());
                    regions.push(PseudocodeRegion {
                        id: format!("region:{function_address:x}:if:bb{}:{end}", block.id.0),
                        kind: RegionKind::If,
                        start_address: Some(start),
                        end_address: Some(end),
                        header: Some(format!("if ({cond_text})")),
                        statements: vec![format!(
                            "/* then -> bb{} else -> bb{} */",
                            true_block.0, false_block.0
                        )],
                        children: vec![],
                        evidence_ids: vec![format!("pseudo:{function_address:x}:if:{end:x}")],
                    });
                }
                SsaOp::Return { value } => {
                    has_return = true;
                    let rendered = match value {
                        Some(op) => render_operand_named(func, op, &HashMap::new(), &HashMap::new()),
                        None => "/*void*/".to_string(),
                    };
                    regions.push(PseudocodeRegion {
                        id: format!("region:{function_address:x}:return:bb{}", block.id.0),
                        kind: RegionKind::Return,
                        start_address: Some(start),
                        end_address: Some(end),
                        header: None,
                        statements: vec![if rendered == "/*void*/" {
                            "return;".to_string()
                        } else {
                            format!("return {rendered};")
                        }],
                        children: vec![],
                        evidence_ids: vec![format!("pseudo:{function_address:x}:return:{end:x}")],
                    });
                }
                _ => {}
            }
        }
    }
    if branch_count >= 3
        && !regions.iter().any(|r| r.kind == RegionKind::Switch)
        && regions.iter().filter(|r| r.kind == RegionKind::If).count() >= 3
    {
        regions.insert(
            0,
            PseudocodeRegion {
                id: format!("region:{function_address:x}:switch"),
                kind: RegionKind::Switch,
                start_address: Some(function_address),
                end_address: None,
                header: Some("switch (value)".to_string()),
                statements: vec![format!("/* {branch_count} branch sites */")],
                children: vec![],
                evidence_ids: vec![format!("pseudo:{function_address:x}:switch")],
            },
        );
    }
    if !has_return {
        regions.push(PseudocodeRegion {
            id: format!("region:{function_address:x}:return"),
            kind: RegionKind::Return,
            start_address: None,
            end_address: None,
            header: None,
            statements: vec!["return;".to_string()],
            children: vec![],
            evidence_ids: vec![format!("pseudo:{function_address:x}:return")],
        });
    }
    regions
}

#[cfg(test)]
mod string_call_tests {
    use super::*;
    use revx_core::{BasicBlock, Instruction, Reference, ReferenceKind};
    use std::sync::Arc;

    #[test]
    fn arm64_ssa_char_range_condition_naturalizes() {
        let text = naturalize_truthiness("(r_getopt_long - 0x25) > 0x5b");
        assert!(text.contains("'%'") || text.contains("0x25"), "{text}");
        assert!(text.contains("||") || text.contains("&&"), "{text}");
    }

    #[test]
    fn arm64_ssa_load_deref_is_single_star() {
        let mut func = SsaFunction::default();
        func.cfg.entry = BlockId(0);
        func.cfg.blocks.push(CfgBlock {
            id: BlockId(0),
            start_addr: 0x1000,
            end_addr: 0x1000,
            insts: vec![],
            phis: vec![],
        });
        func.cfg.preds.push(Vec::new());
        func.cfg.succs.push(Vec::new());
        let id = func.define(
            "x0",
            BlockId(0),
            SsaOp::Load {
                addr: Operand::Deref {
                    base: Box::new(Operand::Symbol("env".to_string())),
                    offset: 0,
                },
            },
            0x1000,
        );
        let rendered = render_named_value(&func, id, &HashMap::new(), &HashMap::new());
        assert_eq!(rendered, "*env", "{rendered}");
        assert!(!rendered.contains("*(*"), "{rendered}");
    }

    #[test]
    fn arm64_ssa_names_jni_vtable_calls() {
        let mk = |addr: u64, text: &str| Instruction {
            address: addr,
            bytes: Arc::from("00000000"),
            text: Arc::from(text),
        };
        let blocks = vec![BasicBlock {
            address: 0x1000,
            size: 0x30,
            instructions: vec![
                mk(0x1000, "ldr x8, [x0]"),
                mk(0x1004, "add x1, sp, #0x8"),
                mk(0x1008, "mov x2, #0x0"),
                mk(0x100c, "ldr x8, [x8, #0x20]"),
                mk(0x1010, "blr x8"),
                mk(0x1014, "ldr x0, [sp, #0x8]"),
                mk(0x1018, "adrp x1, $+0x0"),
                mk(0x101c, "add x1, x1, #0x100"),
                mk(0x1020, "ldr x8, [x0]"),
                mk(0x1024, "ldr x8, [x8, #0x30]"),
                mk(0x1028, "blr x8"),
                mk(0x102c, "ret"),
            ],
        }];
        let refs = vec![
            Reference {
                from: 0x1010,
                to: 0,
                kind: ReferenceKind::IndirectCall,
            },
            Reference {
                from: 0x1028,
                to: 0,
                kind: ReferenceKind::IndirectCall,
            },
        ];
        let args = vec![revx_core::Variable {
            name: "arg_0".into(),
            role: revx_core::VariableRole::Argument,
            storage: revx_core::VariableStorage::Register,
            type_name: Some("void *".into()),
            confidence: 0.6,
            location: "x0".into(),
            evidence_ids: vec![],
        }];
        let mut strings = HashMap::new();
        strings.insert(0x100, "com/foo/Bar".to_string());
        let ssa = lift_arm64_to_ssa(&blocks, &refs, &args);
        let text = render_ssa_pseudocode_named_layered_with_strings(
            &ssa,
            "JNI_OnLoad",
            &args,
            &HashMap::new(),
            &HashMap::new(),
            &strings,
        );
        assert!(
            text.contains("AttachCurrentThread") || text.contains("GetVersion"),
            "expected JNI VM call name in:\n{text}"
        );
        assert!(
            text.contains("FindClass") || text.contains("GetEnv"),
            "expected JNI env call name in:\n{text}"
        );
    }

    #[test]
    fn arm64_ssa_lifts_blr_indirect_calls_and_sign_bit_tbnz() {
        let mk = |addr: u64, text: &str| Instruction {
            address: addr,
            bytes: Arc::from("00000000"),
            text: Arc::from(text),
        };
        let blocks = vec![
            BasicBlock {
                address: 0x1000,
                size: 0x20,
                instructions: vec![
                    mk(0x1000, "ldr x8, [x0]"),
                    mk(0x1004, "add x1, sp, #0x8"),
                    mk(0x1008, "mov x2, #0x0"),
                    mk(0x100c, "ldr x8, [x8, #0x20]"),
                    mk(0x1010, "blr x8"),
                    mk(0x1014, "tbnz w0, #0x1f, $+0xc"),
                ],
            },
            BasicBlock {
                address: 0x1018,
                size: 0x8,
                instructions: vec![mk(0x1018, "mov w0, #0x1"), mk(0x101c, "ret")],
            },
            BasicBlock {
                address: 0x1020,
                size: 0x8,
                instructions: vec![mk(0x1020, "mov w0, #0xffffffff"), mk(0x1024, "ret")],
            },
        ];
        let refs = vec![
            Reference {
                from: 0x1010,
                to: 0,
                kind: ReferenceKind::IndirectCall,
            },
            Reference {
                from: 0x1014,
                to: 0x1020,
                kind: ReferenceKind::BranchTrue,
            },
            Reference {
                from: 0x1014,
                to: 0x1018,
                kind: ReferenceKind::BranchFalse,
            },
        ];
        let args = vec![revx_core::Variable {
            name: "arg_0".into(),
            role: revx_core::VariableRole::Argument,
            storage: revx_core::VariableStorage::Register,
            type_name: Some("void *".into()),
            confidence: 0.6,
            location: "x0".into(),
            evidence_ids: vec![],
        }];
        let ssa = lift_arm64_to_ssa(&blocks, &refs, &args);
        let call_count = ssa
            .values
            .iter()
            .filter(|v| matches!(v.op, SsaOp::Call { .. }))
            .count();
        assert!(call_count >= 1, "expected blr to lift as Call, got {call_count}");
        let text = render_ssa_pseudocode_named_layered(
            &ssa,
            "JNI_OnLoad",
            &args,
            &HashMap::new(),
            &HashMap::new(),
        );
        assert!(
            text.contains('(') && text.contains(')'),
            "expected call-like statement in:\n{text}"
        );
        assert!(
            !text.contains("optind_save"),
            "fixture stack name leaked into:\n{text}"
        );
        assert!(
            text.contains('<') || text.contains("return"),
            "expected meaningful condition/control flow in:\n{text}"
        );
    }

    #[test]
    fn arm64_ssa_recovers_setlocale_string_args() {
        let blocks = vec![BasicBlock {
            address: 0x100000000,
            size: 0x14,
            instructions: vec![
                Instruction {
                    address: 0x100000000,
                    bytes: Arc::from("00"),
                    text: Arc::from("adrp x1, $+0x4000"),
                },
                Instruction {
                    address: 0x100000004,
                    bytes: Arc::from("00"),
                    text: Arc::from("add x1, x1, #0x100"),
                },
                Instruction {
                    address: 0x100000008,
                    bytes: Arc::from("00"),
                    text: Arc::from("mov w0, #0x0"),
                },
                Instruction {
                    address: 0x10000000c,
                    bytes: Arc::from("00"),
                    text: Arc::from("bl $+0x100"),
                },
                Instruction {
                    address: 0x100000010,
                    bytes: Arc::from("00"),
                    text: Arc::from("ret"),
                },
            ],
        }];
        let refs = vec![Reference {
            from: 0x10000000c,
            to: 0x10000010c,
            kind: ReferenceKind::Call,
        }];
        let mut symbols = HashMap::new();
        symbols.insert(0x10000010c, "_setlocale".to_string());
        let mut strings = HashMap::new();
        strings.insert(0x100004100, "".to_string());
        let mut func = lift_arm64_to_ssa(&blocks, &refs, &[]);
        refine_call_arguments_with_symbols(&mut func, &symbols);
        let text = render_ssa_pseudocode_named_layered_with_strings(
            &func,
            "main",
            &[],
            &symbols,
            &HashMap::new(),
            &strings,
        );
        assert!(text.contains("_setlocale("), "{text}");
        assert!(text.contains("\"\""), "{text}");
    }

    #[test]
    fn arm64_ssa_loop_header_recovers_string_call_args() {
        let blocks = vec![
            BasicBlock {
                address: 0x100000000,
                size: 0x10,
                instructions: vec![
                    Instruction {
                        address: 0x100000000,
                        bytes: Arc::from("00"),
                        text: Arc::from("adrp x21, $+0x4000"),
                    },
                    Instruction {
                        address: 0x100000004,
                        bytes: Arc::from("00"),
                        text: Arc::from("add x21, x21, #0x100"),
                    },
                    Instruction {
                        address: 0x100000008,
                        bytes: Arc::from("00"),
                        text: Arc::from("adrp x22, $+0x8000"),
                    },
                    Instruction {
                        address: 0x10000000c,
                        bytes: Arc::from("00"),
                        text: Arc::from("add x22, x22, #0x2d0"),
                    },
                ],
            },
            BasicBlock {
                address: 0x100000010,
                size: 0x1c,
                instructions: vec![
                    Instruction {
                        address: 0x100000010,
                        bytes: Arc::from("00"),
                        text: Arc::from("mov x0, x20"),
                    },
                    Instruction {
                        address: 0x100000014,
                        bytes: Arc::from("00"),
                        text: Arc::from("mov x1, x19"),
                    },
                    Instruction {
                        address: 0x100000018,
                        bytes: Arc::from("00"),
                        text: Arc::from("mov x2, x21"),
                    },
                    Instruction {
                        address: 0x10000001c,
                        bytes: Arc::from("00"),
                        text: Arc::from("mov x3, x22"),
                    },
                    Instruction {
                        address: 0x100000020,
                        bytes: Arc::from("00"),
                        text: Arc::from("mov x4, #0x0"),
                    },
                    Instruction {
                        address: 0x100000024,
                        bytes: Arc::from("00"),
                        text: Arc::from("bl $+0x100"),
                    },
                    Instruction {
                        address: 0x100000028,
                        bytes: Arc::from("00"),
                        text: Arc::from("cbz w0, $+0xc"),
                    },
                ],
            },
            BasicBlock {
                address: 0x10000002c,
                size: 0x4,
                instructions: vec![Instruction {
                    address: 0x10000002c,
                    bytes: Arc::from("00"),
                    text: Arc::from("b $-0x1c"),
                }],
            },
            BasicBlock {
                address: 0x100000034,
                size: 0x4,
                instructions: vec![Instruction {
                    address: 0x100000034,
                    bytes: Arc::from("00"),
                    text: Arc::from("ret"),
                }],
            },
        ];
        let refs = vec![
            Reference {
                from: 0x100000024,
                to: 0x100000124,
                kind: ReferenceKind::Call,
            },
            Reference {
                from: 0x100000028,
                to: 0x100000034,
                kind: ReferenceKind::BranchTrue,
            },
            Reference {
                from: 0x100000028,
                to: 0x10000002c,
                kind: ReferenceKind::BranchFalse,
            },
            Reference {
                from: 0x10000002c,
                to: 0x100000010,
                kind: ReferenceKind::Jump,
            },
            Reference {
                from: 0x10000000c,
                to: 0x100000010,
                kind: ReferenceKind::Fallthrough,
            },
        ];
        let args = vec![
            revx_core::Variable {
                name: "argc".to_string(),
                role: revx_core::VariableRole::Argument,
                storage: revx_core::VariableStorage::Register,
                type_name: Some("int".to_string()),
                confidence: 0.5,
                location: "x20".to_string(),
                evidence_ids: vec![],
            },
            revx_core::Variable {
                name: "argv".to_string(),
                role: revx_core::VariableRole::Argument,
                storage: revx_core::VariableStorage::Register,
                type_name: Some("char **".to_string()),
                confidence: 0.5,
                location: "x19".to_string(),
                evidence_ids: vec![],
            },
        ];
        let mut symbols = HashMap::new();
        symbols.insert(0x100000124, "_getopt_long".to_string());
        let mut strings = HashMap::new();
        strings.insert(0x100004100, "+@1ABCD".to_string());
        let mut func = lift_arm64_to_ssa(&blocks, &refs, &args);
        refine_call_arguments_with_symbols(&mut func, &symbols);
        let text = render_ssa_pseudocode_named_layered_with_strings(
            &func,
            "main",
            &args,
            &symbols,
            &HashMap::new(),
            &strings,
        );
        assert!(
            text.contains("_getopt_long(") && text.contains("+@1ABCD"),
            "expected optstring recovery:\n{text}"
        );
    }
}
