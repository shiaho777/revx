//! Structured Dalvik decode, basic block construction, and SSA lifting.

#![allow(unused)]

use crate::{CodeItem, DexFile};
use revx_analysis::ssa::{
    BinOpKind, BlockId, Cfg, CfgBlock, Operand, SsaFunction, SsaInstruction, SsaOp, SsaValueId,
    UnaryOpKind,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone)]
pub enum Insn {
    Nop,
    Move {
        dst: u16,
        src: u16,
    },
    MoveResult {
        dst: u16,
    },
    MoveException {
        dst: u16,
    },
    Return {
        reg: Option<u16>,
    },
    Const {
        dst: u16,
        value: i64,
    },
    ConstString {
        dst: u16,
        idx: u32,
    },
    ConstClass {
        dst: u16,
        idx: u32,
    },
    ConstMethodHandle {
        dst: u16,
        idx: u32,
    },
    ConstMethodType {
        dst: u16,
        idx: u32,
    },
    MonitorEnter {
        reg: u16,
    },
    MonitorExit {
        reg: u16,
    },
    CheckCast {
        reg: u16,
        type_idx: u32,
    },
    InstanceOf {
        dst: u16,
        src: u16,
        type_idx: u32,
    },
    ArrayLength {
        dst: u16,
        arr: u16,
    },
    NewInstance {
        dst: u16,
        type_idx: u32,
    },
    NewArray {
        dst: u16,
        size: u16,
        type_idx: u32,
    },
    FilledNewArray {
        regs: Vec<u16>,
        type_idx: u32,
    },
    FillArrayData {
        arr: u16,
        payload_off: u32,
    },
    Throw {
        reg: u16,
    },
    Goto {
        target: u32,
    },
    PackedSwitch {
        reg: u16,
        payload_off: u32,
    },
    SparseSwitch {
        reg: u16,
        payload_off: u32,
    },
    Cmp {
        dst: u16,
        lhs: u16,
        rhs: u16,
        kind: CmpKind,
    },
    If {
        lhs: u16,
        rhs: u16,
        cond: BinOpKind,
        target: u32,
    },
    IfZ {
        reg: u16,
        cond: BinOpKind,
        target: u32,
    },
    ArrayGet {
        dst: u16,
        arr: u16,
        idx: u16,
        wide: bool,
    },
    ArrayPut {
        src: u16,
        arr: u16,
        idx: u16,
        wide: bool,
    },
    FieldGet {
        dst: u16,
        obj: u16,
        field_idx: u32,
    },
    FieldPut {
        src: u16,
        obj: u16,
        field_idx: u32,
    },
    StaticGet {
        dst: u16,
        field_idx: u32,
    },
    StaticPut {
        src: u16,
        field_idx: u32,
    },
    Invoke {
        kind: InvokeKind,
        regs: Vec<u16>,
        method_idx: u32,
    },
    InvokeRange {
        kind: InvokeKind,
        start: u16,
        count: u8,
        method_idx: u32,
    },
    InvokePolymorphic {
        regs: Vec<u16>,
        method_idx: u32,
        proto_idx: u32,
    },
    InvokePolymorphicRange {
        start: u16,
        count: u8,
        method_idx: u32,
        proto_idx: u32,
    },
    InvokeCustom {
        regs: Vec<u16>,
        callsite_idx: u32,
    },
    InvokeCustomRange {
        start: u16,
        count: u8,
        callsite_idx: u32,
    },
    Unary {
        dst: u16,
        src: u16,
        kind: UnaryOpKind,
    },
    Binary {
        dst: u16,
        lhs: u16,
        rhs: u16,
        kind: BinOpKind,
    },
    BinaryLit {
        dst: u16,
        src: u16,
        lit: i32,
        kind: BinOpKind,
    },
    Binary2Addr {
        dst: u16,
        src: u16,
        kind: BinOpKind,
    },
    Convert {
        dst: u16,
        src: u16,
        from: &'static str,
        to: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpKind {
    LtFloat,
    GtFloat,
    LtDouble,
    GtDouble,
    Long,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvokeKind {
    Virtual,
    Super,
    Direct,
    Static,
    Interface,
}

impl InvokeKind {}

fn u16_at(units: &[u16], i: usize) -> u16 {
    units.get(i).copied().unwrap_or(0)
}

fn i16_at(units: &[u16], i: usize) -> i16 {
    u16_at(units, i) as i16
}

fn u32_at(units: &[u16], i: usize) -> u32 {
    let lo = u16_at(units, i) as u32;
    let hi = u16_at(units, i + 1) as u32;
    lo | (hi << 16)
}

fn i32_at(units: &[u16], i: usize) -> i32 {
    u32_at(units, i) as i32
}

fn branch_target(off: usize, delta: i64) -> u32 {
    (off as i64).wrapping_add(delta) as u32
}

const fn binop(op: u8) -> Option<BinOpKind> {
    Some(match op {
        0x90 | 0xb0 | 0xd0 | 0xd8 => BinOpKind::Add,
        0x91 | 0xb1 => BinOpKind::Sub,
        0x92 | 0xb2 | 0xd2 | 0xda => BinOpKind::Mul,
        0x93 | 0xb3 | 0xd3 | 0xdb => BinOpKind::Div,
        0x94 | 0xb4 | 0xd4 | 0xdc => BinOpKind::Mod,
        0x95 | 0xb5 | 0xd5 | 0xdd => BinOpKind::And,
        0x96 | 0xb6 | 0xd6 | 0xde => BinOpKind::Or,
        0x97 | 0xb7 | 0xd7 | 0xdf => BinOpKind::Xor,
        0x98 | 0xb8 | 0xe0 => BinOpKind::Shl,
        0x99 | 0xb9 | 0xe1 => BinOpKind::Shr,
        0x9a | 0xba | 0xe2 => BinOpKind::Sar,
        _ => return None,
    })
}

const fn cond_kind(op: u8) -> Option<BinOpKind> {
    Some(match op {
        0x32 => BinOpKind::Eq,
        0x33 => BinOpKind::Ne,
        0x34 => BinOpKind::Lt,
        0x35 => BinOpKind::Ge,
        0x36 => BinOpKind::Gt,
        0x37 => BinOpKind::Le,
        0x38 => BinOpKind::Eq,
        0x39 => BinOpKind::Ne,
        0x3a => BinOpKind::Lt,
        0x3b => BinOpKind::Ge,
        0x3c => BinOpKind::Gt,
        0x3d => BinOpKind::Le,
        _ => return None,
    })
}

pub fn decode_insn_structured(units: &[u16], off: usize) -> Option<(Insn, usize)> {
    let w0 = u16_at(units, off);
    let op = (w0 & 0xff) as u8;
    let b1 = (w0 >> 8) as u8;
    let a = (b1 & 0x0f) as u16;
    let b = (b1 >> 4) as u16;
    let aa = b1 as u16;
    let insn = match op {
        0x00 => Insn::Nop,
        0x01 | 0x04 | 0x07 => Insn::Move { dst: a, src: b },
        0x02 | 0x05 | 0x08 => {
            return Some((
                Insn::Move {
                    dst: aa,
                    src: u16_at(units, off + 1),
                },
                2,
            ));
        }
        0x03 | 0x06 | 0x09 => {
            return Some((
                Insn::Move {
                    dst: u16_at(units, off + 1),
                    src: u16_at(units, off + 2),
                },
                3,
            ));
        }
        0x0a..=0x0c => Insn::MoveResult { dst: aa },
        0x0d => Insn::MoveException { dst: aa },
        0x0e => Insn::Return { reg: None },
        0x0f..=0x11 => Insn::Return { reg: Some(aa) },
        0x12 => {
            let lit = ((b as i8) << 4 >> 4) as i64;
            Insn::Const { dst: a, value: lit }
        }
        0x13 | 0x16 => {
            return Some((
                Insn::Const {
                    dst: aa,
                    value: i16_at(units, off + 1) as i64,
                },
                2,
            ));
        }
        0x14 | 0x17 => {
            return Some((
                Insn::Const {
                    dst: aa,
                    value: i32_at(units, off + 1) as i64,
                },
                3,
            ));
        }
        0x15 | 0x19 => {
            let lit = (u16_at(units, off + 1) as i64) << 48 >> 32;
            return Some((
                Insn::Const {
                    dst: aa,
                    value: lit,
                },
                2,
            ));
        }
        0x18 => {
            let lo = u32_at(units, off + 1) as u64;
            let hi = u32_at(units, off + 3) as u64;
            return Some((
                Insn::Const {
                    dst: aa,
                    value: (lo | (hi << 32)) as i64,
                },
                5,
            ));
        }
        0x1a => {
            return Some((
                Insn::ConstString {
                    dst: aa,
                    idx: u16_at(units, off + 1) as u32,
                },
                2,
            ));
        }
        0x1b => {
            return Some((
                Insn::ConstString {
                    dst: aa,
                    idx: u32_at(units, off + 1),
                },
                3,
            ));
        }
        0x1c => {
            return Some((
                Insn::ConstClass {
                    dst: aa,
                    idx: u16_at(units, off + 1) as u32,
                },
                2,
            ));
        }
        0x1d => Insn::MonitorEnter { reg: aa },
        0x1e => Insn::MonitorExit { reg: aa },
        0x1f => {
            return Some((
                Insn::CheckCast {
                    reg: aa,
                    type_idx: u16_at(units, off + 1) as u32,
                },
                2,
            ));
        }
        0x20 => {
            return Some((
                Insn::InstanceOf {
                    dst: a,
                    src: b,
                    type_idx: u16_at(units, off + 1) as u32,
                },
                2,
            ));
        }
        0x21 => Insn::ArrayLength { dst: a, arr: b },
        0x22 => {
            return Some((
                Insn::NewInstance {
                    dst: aa,
                    type_idx: u16_at(units, off + 1) as u32,
                },
                2,
            ));
        }
        0x23 => {
            return Some((
                Insn::NewArray {
                    dst: a,
                    size: b,
                    type_idx: u16_at(units, off + 1) as u32,
                },
                2,
            ));
        }
        0x24 => {
            let count = b;
            let idx = u16_at(units, off + 1) as u32;
            let w3 = u16_at(units, off + 2);
            let nibbles = [
                (w3 & 0xf),
                ((w3 >> 4) & 0xf),
                ((w3 >> 8) & 0xf),
                ((w3 >> 12) & 0xf),
                a,
            ];
            let regs: Vec<u16> = nibbles.iter().take(count as usize).copied().collect();
            return Some((
                Insn::FilledNewArray {
                    regs,
                    type_idx: idx,
                },
                3,
            ));
        }
        0x25 => {
            let count = b1 as u16;
            let idx = u16_at(units, off + 1) as u32;
            let start = u16_at(units, off + 2);
            let regs: Vec<u16> = (start..start + count).collect();
            return Some((
                Insn::FilledNewArray {
                    regs,
                    type_idx: idx,
                },
                3,
            ));
        }
        0x26 => {
            let delta = i32_at(units, off + 1);
            return Some((
                Insn::FillArrayData {
                    arr: aa,
                    payload_off: branch_target(off, delta as i64),
                },
                3,
            ));
        }
        0x27 => Insn::Throw { reg: aa },
        0x28 => {
            let t = branch_target(off, (b1 as i8) as i64);
            Insn::Goto { target: t }
        }
        0x29 => {
            let t = branch_target(off, i16_at(units, off + 1) as i64);
            return Some((Insn::Goto { target: t }, 2));
        }
        0x2a => {
            let t = branch_target(off, i32_at(units, off + 1) as i64);
            return Some((Insn::Goto { target: t }, 3));
        }
        0x2b => {
            let delta = i32_at(units, off + 1);
            return Some((
                Insn::PackedSwitch {
                    reg: aa,
                    payload_off: branch_target(off, delta as i64),
                },
                3,
            ));
        }
        0x2c => {
            let delta = i32_at(units, off + 1);
            return Some((
                Insn::SparseSwitch {
                    reg: aa,
                    payload_off: branch_target(off, delta as i64),
                },
                3,
            ));
        }
        0x2d..=0x31 => {
            let kind = match op {
                0x2d => CmpKind::LtFloat,
                0x2e => CmpKind::GtFloat,
                0x2f => CmpKind::LtDouble,
                0x30 => CmpKind::GtDouble,
                _ => CmpKind::Long,
            };
            let bb = (u16_at(units, off + 1) & 0xff);
            let cc = (u16_at(units, off + 1) >> 8);
            return Some((
                Insn::Cmp {
                    dst: aa,
                    lhs: bb,
                    rhs: cc,
                    kind,
                },
                2,
            ));
        }
        0x32..=0x37 => {
            let kind = cond_kind(op)?;
            let t = branch_target(off, i16_at(units, off + 1) as i64);
            return Some((
                Insn::If {
                    lhs: a,
                    rhs: b,
                    cond: kind,
                    target: t,
                },
                2,
            ));
        }
        0x38..=0x3d => {
            let kind = cond_kind(op)?;
            let t = branch_target(off, i16_at(units, off + 1) as i64);
            return Some((
                Insn::IfZ {
                    reg: aa,
                    cond: kind,
                    target: t,
                },
                2,
            ));
        }
        0x44..=0x4a => {
            let wide = op == 0x45;
            let arr = (u16_at(units, off + 1) & 0xff);
            let idx = (u16_at(units, off + 1) >> 8);
            return Some((
                Insn::ArrayGet {
                    dst: aa,
                    arr,
                    idx,
                    wide,
                },
                2,
            ));
        }
        0x4b..=0x51 => {
            let wide = op == 0x4c;
            let arr = (u16_at(units, off + 1) & 0xff);
            let idx = (u16_at(units, off + 1) >> 8);
            return Some((
                Insn::ArrayPut {
                    src: aa,
                    arr,
                    idx,
                    wide,
                },
                2,
            ));
        }
        0x52..=0x58 => {
            return Some((
                Insn::FieldGet {
                    dst: a,
                    obj: b,
                    field_idx: u16_at(units, off + 1) as u32,
                },
                2,
            ));
        }
        0x59..=0x5f => {
            return Some((
                Insn::FieldPut {
                    src: a,
                    obj: b,
                    field_idx: u16_at(units, off + 1) as u32,
                },
                2,
            ));
        }
        0x60..=0x66 => {
            return Some((
                Insn::StaticGet {
                    dst: aa,
                    field_idx: u16_at(units, off + 1) as u32,
                },
                2,
            ));
        }
        0x67..=0x6d => {
            return Some((
                Insn::StaticPut {
                    src: aa,
                    field_idx: u16_at(units, off + 1) as u32,
                },
                2,
            ));
        }
        0x6e..=0x72 => {
            let kind = match op {
                0x6e => InvokeKind::Virtual,
                0x6f => InvokeKind::Super,
                0x70 => InvokeKind::Direct,
                0x71 => InvokeKind::Static,
                _ => InvokeKind::Interface,
            };
            let count = b;
            let idx = u16_at(units, off + 1) as u32;
            let w3 = u16_at(units, off + 2);
            let nibbles = [
                (w3 & 0xf),
                ((w3 >> 4) & 0xf),
                ((w3 >> 8) & 0xf),
                ((w3 >> 12) & 0xf),
                a,
            ];
            let regs: Vec<u16> = nibbles.iter().take(count as usize).copied().collect();
            return Some((
                Insn::Invoke {
                    kind,
                    regs,
                    method_idx: idx,
                },
                3,
            ));
        }
        0x74..=0x78 => {
            let kind = match op {
                0x74 => InvokeKind::Virtual,
                0x75 => InvokeKind::Super,
                0x76 => InvokeKind::Direct,
                0x77 => InvokeKind::Static,
                _ => InvokeKind::Interface,
            };
            let count = b1;
            let idx = u16_at(units, off + 1) as u32;
            let start = u16_at(units, off + 2);
            return Some((
                Insn::InvokeRange {
                    kind,
                    start,
                    count,
                    method_idx: idx,
                },
                3,
            ));
        }
        0x7b | 0x7d | 0x7f | 0x80 => Insn::Unary {
            dst: a,
            src: b,
            kind: UnaryOpKind::Neg,
        },
        0x7c | 0x7e => Insn::Unary {
            dst: a,
            src: b,
            kind: UnaryOpKind::Not,
        },
        0x81..=0x8f => {
            let (from, to) = match op {
                0x81 => ("int", "long"),
                0x82 => ("int", "float"),
                0x83 => ("int", "double"),
                0x84 => ("long", "int"),
                0x85 => ("long", "float"),
                0x86 => ("long", "double"),
                0x87 => ("float", "int"),
                0x88 => ("float", "long"),
                0x89 => ("float", "double"),
                0x8a => ("double", "int"),
                0x8b => ("double", "long"),
                0x8c => ("double", "float"),
                0x8d => ("int", "byte"),
                0x8e => ("int", "char"),
                _ => ("int", "short"),
            };
            Insn::Convert {
                dst: a,
                src: b,
                from,
                to,
            }
        }
        0x90..=0x9a | 0xa6..=0xaf => {
            let kind = binop(op)?;
            let lhs = (u16_at(units, off + 1) & 0xff);
            let rhs = (u16_at(units, off + 1) >> 8);
            return Some((
                Insn::Binary {
                    dst: aa,
                    lhs,
                    rhs,
                    kind,
                },
                2,
            ));
        }
        0x9b..=0xa5 => {
            let kind = match op {
                0x9b => BinOpKind::Add,
                0x9c => BinOpKind::Sub,
                0x9d => BinOpKind::Mul,
                0x9e => BinOpKind::Div,
                0x9f => BinOpKind::Mod,
                0xa0 => BinOpKind::And,
                0xa1 => BinOpKind::Or,
                0xa2 => BinOpKind::Xor,
                0xa3 => BinOpKind::Shl,
                0xa4 => BinOpKind::Shr,
                _ => BinOpKind::Sar,
            };
            let lhs = (u16_at(units, off + 1) & 0xff);
            let rhs = (u16_at(units, off + 1) >> 8);
            return Some((
                Insn::Binary {
                    dst: aa,
                    lhs,
                    rhs,
                    kind,
                },
                2,
            ));
        }
        0xb0..=0xc5 => {
            let kind = match op {
                0xb0 => BinOpKind::Add,
                0xb1 => BinOpKind::Sub,
                0xb2 => BinOpKind::Mul,
                0xb3 => BinOpKind::Div,
                0xb4 => BinOpKind::Mod,
                0xb5 => BinOpKind::And,
                0xb6 => BinOpKind::Or,
                0xb7 => BinOpKind::Xor,
                0xb8 => BinOpKind::Shl,
                0xb9 => BinOpKind::Shr,
                0xba => BinOpKind::Sar,
                0xbb => BinOpKind::Add,
                0xbc => BinOpKind::Sub,
                0xbd => BinOpKind::Mul,
                0xbe => BinOpKind::Div,
                0xbf => BinOpKind::Mod,
                0xc0 => BinOpKind::And,
                0xc1 => BinOpKind::Or,
                0xc2 => BinOpKind::Xor,
                0xc3 => BinOpKind::Shl,
                0xc4 => BinOpKind::Shr,
                _ => BinOpKind::Sar,
            };
            return Some((
                Insn::Binary2Addr {
                    dst: a,
                    src: b,
                    kind,
                },
                1,
            ));
        }
        0xc6..=0xcf => {
            let kind = match op {
                0xc6 => BinOpKind::Add,
                0xc7 => BinOpKind::Sub,
                0xc8 => BinOpKind::Mul,
                0xc9 => BinOpKind::Div,
                0xca => BinOpKind::Mod,
                0xcb => BinOpKind::Add,
                0xcc => BinOpKind::Sub,
                0xcd => BinOpKind::Mul,
                0xce => BinOpKind::Div,
                _ => BinOpKind::Mod,
            };
            return Some((
                Insn::Binary2Addr {
                    dst: a,
                    src: b,
                    kind,
                },
                1,
            ));
        }
        0xd0 | 0xd2..=0xd7 => {
            let kind = binop(op)?;
            return Some((
                Insn::BinaryLit {
                    dst: a,
                    src: b,
                    lit: i16_at(units, off + 1) as i32,
                    kind,
                },
                2,
            ));
        }
        0xd1 => {
            return Some((
                Insn::BinaryLit {
                    dst: a,
                    src: b,
                    lit: i16_at(units, off + 1) as i32,
                    kind: BinOpKind::Sub,
                },
                2,
            ));
        }
        0xd8..=0xe2 => {
            let kind = binop(op)?;
            let w1 = u16_at(units, off + 1);
            let src = (w1 & 0xff);
            let lit = ((w1 >> 8) as u8 as i8) as i32;
            return Some((
                Insn::BinaryLit {
                    dst: aa,
                    src,
                    lit,
                    kind,
                },
                2,
            ));
        }
        0xfa => {
            let count = b;
            let meth = u16_at(units, off + 1) as u32;
            let w3 = u16_at(units, off + 2);
            let proto = u16_at(units, off + 3) as u32;
            let nibbles = [
                (w3 & 0xf),
                ((w3 >> 4) & 0xf),
                ((w3 >> 8) & 0xf),
                ((w3 >> 12) & 0xf),
                a,
            ];
            let regs: Vec<u16> = nibbles.iter().take(count as usize).copied().collect();
            return Some((
                Insn::InvokePolymorphic {
                    regs,
                    method_idx: meth,
                    proto_idx: proto,
                },
                4,
            ));
        }
        0xfb => {
            let count = b1;
            let meth = u16_at(units, off + 1) as u32;
            let start = u16_at(units, off + 2);
            let proto = u16_at(units, off + 3) as u32;
            return Some((
                Insn::InvokePolymorphicRange {
                    start,
                    count,
                    method_idx: meth,
                    proto_idx: proto,
                },
                4,
            ));
        }
        0xfc => {
            let count = b;
            let idx = u16_at(units, off + 1) as u32;
            let w3 = u16_at(units, off + 2);
            let nibbles = [
                (w3 & 0xf),
                ((w3 >> 4) & 0xf),
                ((w3 >> 8) & 0xf),
                ((w3 >> 12) & 0xf),
                a,
            ];
            let regs: Vec<u16> = nibbles.iter().take(count as usize).copied().collect();
            return Some((
                Insn::InvokeCustom {
                    regs,
                    callsite_idx: idx,
                },
                3,
            ));
        }
        0xfd => {
            let count = b1;
            let idx = u16_at(units, off + 1) as u32;
            let start = u16_at(units, off + 2);
            return Some((
                Insn::InvokeCustomRange {
                    start,
                    count,
                    callsite_idx: idx,
                },
                3,
            ));
        }
        0xfe => {
            return Some((
                Insn::ConstMethodHandle {
                    dst: aa,
                    idx: u16_at(units, off + 1) as u32,
                },
                2,
            ));
        }
        0xff => {
            return Some((
                Insn::ConstMethodType {
                    dst: aa,
                    idx: u16_at(units, off + 1) as u32,
                },
                2,
            ));
        }
        _ => Insn::Nop,
    };
    Some((insn, 1))
}

pub fn decode_all(code: &CodeItem) -> BTreeMap<u32, (Insn, usize)> {
    let mut map = BTreeMap::new();
    let mut off = 0usize;
    while off < code.insns.len() {
        match decode_insn_structured(&code.insns, off) {
            Some((insn, size)) => {
                map.insert(off as u32, (insn, size));
                off += size.max(1);
            }
            None => break,
        }
    }
    map
}

pub struct DexBasicBlock {
    pub start: u32,
    pub end: u32,
    pub edges: Vec<u32>,
}

pub fn build_basic_blocks(
    code: &CodeItem,
    insns: &BTreeMap<u32, (Insn, usize)>,
) -> BTreeMap<u32, DexBasicBlock> {
    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    leaders.insert(0);
    for (&off, (insn, size)) in insns {
        let next = off + *size as u32;
        match insn {
            Insn::Goto { target } => {
                leaders.insert(*target);
            }
            Insn::If { target, .. } | Insn::IfZ { target, .. } => {
                leaders.insert(*target);
                leaders.insert(next);
            }
            Insn::PackedSwitch { payload_off, .. } | Insn::SparseSwitch { payload_off, .. } => {
                if let Some(payload) =
                    crate::insns::decode_payload(&code.insns, *payload_off as usize)
                {
                    match payload {
                        crate::insns::Payload::PackedSwitch { targets, .. } => {
                            for t in &targets {
                                leaders.insert(off.wrapping_add(*t as u32));
                            }
                        }
                        crate::insns::Payload::SparseSwitch { targets, .. } => {
                            for t in &targets {
                                leaders.insert(off.wrapping_add(*t as u32));
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    let leaders_vec: Vec<u32> = leaders.into_iter().collect();
    let mut blocks = BTreeMap::new();
    for (i, &start) in leaders_vec.iter().enumerate() {
        let end = if i + 1 < leaders_vec.len() {
            leaders_vec[i + 1]
        } else {
            code.insns.len() as u32
        };
        if start >= code.insns.len() as u32 {
            continue;
        }
        let mut edges = Vec::new();
        let mut last_off = None;
        for (&off, (insn, _)) in insns.range(start..end) {
            last_off = Some((off, insn));
        }
        if let Some((off, insn)) = last_off {
            match insn {
                Insn::Goto { target } => edges.push(*target),
                Insn::If { target, .. } | Insn::IfZ { target, .. } => {
                    edges.push(*target);
                    edges.push(end);
                }
                Insn::PackedSwitch { payload_off, .. } | Insn::SparseSwitch { payload_off, .. } => {
                    if let Some(payload) =
                        crate::insns::decode_payload(&code.insns, *payload_off as usize)
                    {
                        match payload {
                            crate::insns::Payload::PackedSwitch { targets, .. } => {
                                for t in &targets {
                                    edges.push(off.wrapping_add(*t as u32));
                                }
                            }
                            crate::insns::Payload::SparseSwitch { targets, .. } => {
                                for t in &targets {
                                    edges.push(off.wrapping_add(*t as u32));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Insn::Return { .. } | Insn::Throw { .. } => {}
                _ => edges.push(end),
            }
        } else {
            edges.push(end);
        }
        edges.retain(|&e| (e as usize) < code.insns.len() || e == end);
        blocks.insert(start, DexBasicBlock { start, end, edges });
    }
    blocks
}

pub struct DexLiftContext<'a> {
    pub dex: &'a DexFile,
    pub code: &'a CodeItem,
    pub method_idx: u32,
}

impl<'a> DexLiftContext<'a> {
    pub fn new(dex: &'a DexFile, code: &'a CodeItem, method_idx: u32) -> Self {
        Self {
            dex,
            code,
            method_idx,
        }
    }
}

pub struct DexMethodLifter<'a> {
    ctx: DexLiftContext<'a>,
    func: SsaFunction,
    block_ids: BTreeMap<u32, BlockId>,
    reg_values: HashMap<u16, SsaValueId>,
    block_defs: HashMap<BlockId, HashMap<u16, SsaValueId>>,
    pending_call_result: Option<SsaValueId>,
    pending_call_type: Option<String>,
    value_types: crate::types::ValueTypes,
}

impl<'a> DexMethodLifter<'a> {
    pub fn new(ctx: DexLiftContext<'a>) -> Self {
        let cfg = Cfg {
            entry: BlockId(0),
            ..Default::default()
        };
        Self {
            ctx,
            func: SsaFunction::new(cfg),
            block_ids: BTreeMap::new(),
            reg_values: HashMap::new(),
            block_defs: HashMap::new(),
            pending_call_result: None,
            pending_call_type: None,
            value_types: HashMap::new(),
        }
    }

    fn set_type(&mut self, id: SsaValueId, ty: &str) {
        let java = crate::types::java_type(ty);
        self.value_types.insert(id, java);
    }

    fn method_return_type(&self, method_idx: u32) -> Option<String> {
        let m = self.ctx.dex.methods.get(method_idx as usize)?;
        let p = self.ctx.dex.protos.get(m.proto as usize)?;
        Some(p.return_type.clone())
    }

    fn field_type(&self, field_idx: u32) -> Option<String> {
        self.ctx
            .dex
            .fields
            .get(field_idx as usize)
            .map(|f| f.ty.clone())
    }

    fn array_element_type(&self, arr: u16) -> Option<String> {
        let id = self.reg_values.get(&arr)?;
        let desc = self.value_types.get(id)?;
        let elem = desc.trim_end_matches("[]");
        if elem == desc {
            return None;
        }
        Some(elem.to_string())
    }

    fn block_id(&mut self, addr: u32) -> BlockId {
        if let Some(&id) = self.block_ids.get(&addr) {
            return id;
        }
        let id = BlockId(self.func.cfg.blocks.len() as u32);
        self.block_ids.insert(addr, id);
        self.func.cfg.blocks.push(CfgBlock {
            id,
            start_addr: addr as u64,
            end_addr: addr as u64,
            insts: Vec::new(),
            phis: Vec::new(),
        });
        self.func.cfg.preds.push(Vec::new());
        self.func.cfg.succs.push(Vec::new());
        id
    }

    fn define(&mut self, reg: u16, block: BlockId, op: SsaOp) -> SsaValueId {
        let id = self.func.new_value_id();
        let inst = SsaInstruction {
            id,
            op,
            source_addr: 0,
            block,
        };
        self.func.cfg.block_mut(block).insts.push(id);
        self.func.values.push(inst);
        self.reg_values.insert(reg, id);
        self.block_defs.entry(block).or_default().insert(reg, id);
        id
    }

    fn value(&self, reg: u16) -> Operand {
        if let Some(&id) = self.reg_values.get(&reg) {
            Operand::Value(id)
        } else {
            Operand::Symbol(format!("v{reg}"))
        }
    }

    fn push_inst(&mut self, block: BlockId, op: SsaOp) -> SsaValueId {
        let id = self.func.new_value_id();
        let inst = SsaInstruction {
            id,
            op,
            source_addr: 0,
            block,
        };
        self.func.cfg.block_mut(block).insts.push(id);
        self.func.values.push(inst);
        id
    }

    fn build_cfg(&mut self, blocks: &BTreeMap<u32, DexBasicBlock>) {
        let mut id_map: HashMap<u32, BlockId> = HashMap::new();
        for (i, (&addr, _)) in blocks.iter().enumerate() {
            id_map.insert(addr, BlockId(i as u32));
        }
        let n = id_map.len();
        let mut cfg = Cfg {
            entry: BlockId(0),
            ..Default::default()
        };
        for (&addr, blk) in blocks.iter() {
            let id = id_map[&addr];
            cfg.blocks.push(CfgBlock {
                id,
                start_addr: addr as u64,
                end_addr: blk.end as u64,
                insts: Vec::new(),
                phis: Vec::new(),
            });
        }
        cfg.preds = vec![Vec::new(); n];
        cfg.succs = vec![Vec::new(); n];
        for (&addr, blk) in blocks.iter() {
            let from = id_map[&addr];
            for &edge in &blk.edges {
                if let Some(&to) = id_map.get(&edge) {
                    cfg.succs[from.0 as usize].push(to);
                    cfg.preds[to.0 as usize].push(from);
                }
            }
        }
        self.func.cfg = cfg;
        self.block_ids = id_map.into_iter().collect();
    }

    pub fn lift(mut self) -> (SsaFunction, crate::types::ValueTypes) {
        let insns = decode_all(self.ctx.code);
        let blocks = build_basic_blocks(self.ctx.code, &insns);
        self.build_cfg(&blocks);

        // Parameter types from the method's proto (instance methods: p0 is the receiver).
        let is_static = {
            let mut found = false;
            for class in &self.ctx.dex.classes {
                let Some(cd) = &class.class_data else {
                    continue;
                };
                for m in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
                    if m.method_idx == self.ctx.method_idx {
                        found = m.access_flags & 0x0008 != 0;
                    }
                }
            }
            found
        };
        let param_types: Vec<String> = self
            .ctx
            .dex
            .protos
            .get(
                self.ctx
                    .dex
                    .methods
                    .get(self.ctx.method_idx as usize)
                    .map(|m| m.proto as usize)
                    .unwrap_or(0),
            )
            .map(|p| p.parameters.clone())
            .unwrap_or_default();

        let registers = self.ctx.code.registers_size;
        let ins = self.ctx.code.ins_size;
        for i in 0..ins {
            let reg = registers - ins + i;
            let name = format!("p{i}");
            let id = self.func.new_value_id();
            let inst = SsaInstruction {
                id,
                op: SsaOp::Copy {
                    src: Operand::Symbol(name),
                },
                source_addr: 0,
                block: BlockId(0),
            };
            self.func.cfg.block_mut(BlockId(0)).insts.push(id);
            self.func.values.push(inst);
            let ty = if !is_static && i == 0 {
                self.ctx
                    .dex
                    .methods
                    .get(self.ctx.method_idx as usize)
                    .map(|m| m.class.clone())
                    .unwrap_or_default()
            } else {
                param_types
                    .get(if is_static { i } else { i - 1 } as usize)
                    .cloned()
                    .unwrap_or_default()
            };
            if !ty.is_empty() {
                self.set_type(id, &ty);
            }
            self.reg_values.insert(reg, id);
            self.block_defs
                .entry(BlockId(0))
                .or_default()
                .insert(reg, id);
        }

        let order = self.reverse_post_order();
        let mut visited = BTreeSet::new();
        for &bid in &order {
            if !visited.insert(bid) {
                continue;
            }
            let block_addr = self.func.cfg.blocks[bid.0 as usize].start_addr as u32;
            let block_end = self.func.cfg.blocks[bid.0 as usize].end_addr as u32;

            if bid != BlockId(0) {
                self.merge_predecessor_regs(bid);
            }

            let mut cur_off = block_addr;
            while cur_off < block_end {
                let Some((insn, size)) = insns.get(&cur_off) else {
                    break;
                };
                self.lift_insn(bid, cur_off, insn);
                cur_off += *size as u32;
            }
        }

        (self.func, self.value_types)
    }

    fn reverse_post_order(&self) -> Vec<BlockId> {
        let n = self.func.cfg.blocks.len();
        let mut visited = vec![false; n];
        let mut post: Vec<BlockId> = Vec::with_capacity(n);
        let mut stack: Vec<(BlockId, usize)> = vec![(BlockId(0), 0)];
        visited[0] = true;
        while let Some(&mut (bid, ref mut next)) = stack.last_mut() {
            let succs = self
                .func
                .cfg
                .succs
                .get(bid.0 as usize)
                .cloned()
                .unwrap_or_default();
            if *next < succs.len() {
                let succ = succs[*next];
                *next += 1;
                if !visited[succ.0 as usize] {
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

    fn merge_predecessor_regs(&mut self, block: BlockId) {
        let preds = self.func.cfg.predecessors(block).to_vec();
        if preds.is_empty() {
            return;
        }
        let mut common: HashMap<u16, Vec<SsaValueId>> = HashMap::new();
        for pred in &preds {
            if let Some(defs) = self.block_defs.get(pred) {
                for (&reg, &id) in defs {
                    common.entry(reg).or_default().push(id);
                }
            }
        }
        for (reg, ids) in common {
            if ids.len() == preds.len() {
                let first = ids[0];
                if ids.iter().all(|&id| id == first) {
                    self.reg_values.insert(reg, first);
                } else {
                    let phi_id = self.func.new_value_id();
                    let incoming: Vec<(BlockId, SsaValueId)> =
                        preds.iter().map(|&p| (p, first)).collect();
                    let phi = SsaInstruction {
                        id: phi_id,
                        op: SsaOp::Phi { incoming },
                        source_addr: 0,
                        block,
                    };
                    self.func.cfg.block_mut(block).phis.push(phi_id);
                    self.func.values.push(phi);
                    self.reg_values.insert(reg, phi_id);
                    self.block_defs
                        .entry(block)
                        .or_default()
                        .insert(reg, phi_id);
                }
            }
        }
    }

    fn lift_insn(&mut self, block: BlockId, _addr: u32, insn: &Insn) {
        match insn {
            Insn::Nop => {}
            Insn::Move { dst, src } => {
                let val = self.value(*src);
                self.define(*dst, block, SsaOp::Copy { src: val });
            }
            Insn::MoveResult { dst } => {
                let val = self
                    .pending_call_result
                    .map(Operand::Value)
                    .unwrap_or_else(|| Operand::Symbol("?call_result".to_string()));
                self.define(*dst, block, SsaOp::Copy { src: val });
                self.pending_call_result = None;
            }
            Insn::MoveException { dst } => {
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol("__exception".to_string()),
                        args: vec![],
                    },
                );
                self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Value(id),
                    },
                );
            }
            Insn::Return { reg } => {
                let value = reg.map(|r| self.value(r));
                self.push_inst(block, SsaOp::Return { value });
            }
            Insn::Const { dst, value } => {
                let id = self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Constant(*value),
                    },
                );
                let t = if *value < i32::MIN as i64 || *value > u32::MAX as i64 {
                    "J"
                } else {
                    "I"
                };
                self.set_type(id, t);
            }
            Insn::ConstString { dst, idx } => {
                let s = crate::insns::escape_string(self.ctx.dex.string_value(*idx));
                let id = self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Symbol(format!("\"{s}\"")),
                    },
                );
                self.set_type(id, "Ljava/lang/String;");
            }
            Insn::ConstClass { dst, idx } => {
                let t = self.ctx.dex.type_name(*idx);
                self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Symbol(format!("{t}.class")),
                    },
                );
            }
            Insn::ConstMethodHandle { dst, idx } => {
                let sig = self.ctx.dex.method_signature(*idx);
                self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Symbol(format!("{sig}::handle")),
                    },
                );
            }
            Insn::ConstMethodType { dst, idx } => {
                let proto = self
                    .ctx
                    .dex
                    .protos
                    .get(*idx as usize)
                    .map(|p| format!("({}){}", p.parameters.join(""), p.return_type))
                    .unwrap_or_default();
                self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Symbol(proto),
                    },
                );
            }
            Insn::MonitorEnter { reg } => {
                let val = self.value(*reg);
                self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol("monitorEnter".to_string()),
                        args: vec![val],
                    },
                );
            }
            Insn::MonitorExit { reg } => {
                let val = self.value(*reg);
                self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol("monitorExit".to_string()),
                        args: vec![val],
                    },
                );
            }
            Insn::CheckCast { reg, type_idx } => {
                let val = self.value(*reg);
                let t = self.ctx.dex.type_name(*type_idx);
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(format!("({t})")),
                        args: vec![val],
                    },
                );
                self.define(
                    *reg,
                    block,
                    SsaOp::Copy {
                        src: Operand::Value(id),
                    },
                );
            }
            Insn::InstanceOf { dst, src, type_idx } => {
                let val = self.value(*src);
                let t = self.ctx.dex.type_name(*type_idx);
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(format!("instanceof {t}")),
                        args: vec![val],
                    },
                );
                let copy_id = self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Value(id),
                    },
                );
                self.set_type(id, "Z");
                self.set_type(copy_id, "Z");
            }
            Insn::ArrayLength { dst, arr } => {
                let val = self.value(*arr);
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol("arrayLength".to_string()),
                        args: vec![val],
                    },
                );
                self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Value(id),
                    },
                );
            }
            Insn::NewInstance { dst, type_idx } => {
                let t = self.ctx.dex.type_name(*type_idx);
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(format!("new {t}")),
                        args: vec![],
                    },
                );
                let copy_id = self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Value(id),
                    },
                );
                self.set_type(id, &t);
                self.set_type(copy_id, &t);
            }
            Insn::NewArray {
                dst,
                size,
                type_idx,
            } => {
                let size_val = self.value(*size);
                let t = self.ctx.dex.type_name(*type_idx);
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(format!("new {t}[]")),
                        args: vec![size_val],
                    },
                );
                let copy_id = self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Value(id),
                    },
                );
                self.set_type(id, &t);
                self.set_type(copy_id, &t);
            }
            Insn::FilledNewArray { regs, type_idx } => {
                let t = self.ctx.dex.type_name(*type_idx);
                let args: Vec<Operand> = regs.iter().map(|&r| self.value(r)).collect();
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(format!("new {t}[]")),
                        args,
                    },
                );
                self.pending_call_result = Some(id);
            }
            Insn::FillArrayData { arr, .. } => {
                let val = self.value(*arr);
                self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol("fillArrayData".to_string()),
                        args: vec![val],
                    },
                );
            }
            Insn::Throw { reg } => {
                let val = self.value(*reg);
                self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol("throw".to_string()),
                        args: vec![val],
                    },
                );
            }
            Insn::Goto { target } => {
                let tid = self.block_id_for_addr(*target);
                self.push_inst(block, SsaOp::Jump { target: tid });
            }
            Insn::PackedSwitch { reg, .. } | Insn::SparseSwitch { reg, .. } => {
                let val = self.value(*reg);
                self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol("__switch".to_string()),
                        args: vec![val],
                    },
                );
            }
            Insn::Cmp {
                dst,
                lhs,
                rhs,
                kind,
            } => {
                let l = self.value(*lhs);
                let r = self.value(*rhs);
                let name = match kind {
                    CmpKind::LtFloat => "cmpl_float",
                    CmpKind::GtFloat => "cmpg_float",
                    CmpKind::LtDouble => "cmpl_double",
                    CmpKind::GtDouble => "cmpg_double",
                    CmpKind::Long => "cmp_long",
                };
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(name.to_string()),
                        args: vec![l, r],
                    },
                );
                self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Value(id),
                    },
                );
            }
            Insn::If {
                lhs,
                rhs,
                cond,
                target,
            } => {
                let l = self.value(*lhs);
                let r = self.value(*rhs);
                let tid = self.block_id_for_addr(*target);
                let fid =
                    self.block_id_for_addr(self.func.cfg.blocks[block.0 as usize].end_addr as u32);
                let cond_id = self.push_inst(
                    block,
                    SsaOp::BinOp {
                        kind: *cond,
                        lhs: l,
                        rhs: r,
                    },
                );
                self.push_inst(
                    block,
                    SsaOp::Branch {
                        cond: Operand::Value(cond_id),
                        true_block: tid,
                        false_block: fid,
                    },
                );
            }
            Insn::IfZ { reg, cond, target } => {
                let v = self.value(*reg);
                let tid = self.block_id_for_addr(*target);
                let fid =
                    self.block_id_for_addr(self.func.cfg.blocks[block.0 as usize].end_addr as u32);
                let cond_id = self.push_inst(
                    block,
                    SsaOp::BinOp {
                        kind: *cond,
                        lhs: v,
                        rhs: Operand::Constant(0),
                    },
                );
                self.push_inst(
                    block,
                    SsaOp::Branch {
                        cond: Operand::Value(cond_id),
                        true_block: tid,
                        false_block: fid,
                    },
                );
            }
            Insn::ArrayGet { dst, arr, idx, .. } => {
                let a = self.value(*arr);
                let i = self.value(*idx);
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol("__aget".to_string()),
                        args: vec![a, i],
                    },
                );
                let copy_id = self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Value(id),
                    },
                );
                if let Some(elem) = self.array_element_type(*arr) {
                    self.set_type(id, &elem);
                    self.set_type(copy_id, &elem);
                }
            }
            Insn::ArrayPut { src, arr, idx, .. } => {
                let s = self.value(*src);
                let a = self.value(*arr);
                let i = self.value(*idx);
                self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol("__aput".to_string()),
                        args: vec![a, i, s],
                    },
                );
            }
            Insn::FieldGet {
                dst,
                obj,
                field_idx,
            } => {
                let o = self.value(*obj);
                let field = self.ctx.dex.field_reference(*field_idx);
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(format!("__iget:{field}")),
                        args: vec![o],
                    },
                );
                let copy_id = self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Value(id),
                    },
                );
                if let Some(t) = self.field_type(*field_idx) {
                    self.set_type(id, &t);
                    self.set_type(copy_id, &t);
                }
            }
            Insn::FieldPut {
                src,
                obj,
                field_idx,
            } => {
                let s = self.value(*src);
                let o = self.value(*obj);
                let field = self.ctx.dex.field_reference(*field_idx);
                self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(format!("__iput:{field}")),
                        args: vec![o, s],
                    },
                );
            }
            Insn::StaticGet { dst, field_idx } => {
                let field = self.ctx.dex.field_reference(*field_idx);
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(format!("__sget:{field}")),
                        args: vec![],
                    },
                );
                let copy_id = self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Value(id),
                    },
                );
                if let Some(t) = self.field_type(*field_idx) {
                    self.set_type(id, &t);
                    self.set_type(copy_id, &t);
                }
            }
            Insn::StaticPut { src, field_idx } => {
                let s = self.value(*src);
                let field = self.ctx.dex.field_reference(*field_idx);
                self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(format!("__sput:{field}")),
                        args: vec![s],
                    },
                );
            }
            Insn::Invoke {
                kind,
                regs,
                method_idx,
            } => {
                let sig = self.ctx.dex.method_signature(*method_idx);
                let args: Vec<Operand> = regs.iter().map(|&r| self.value(r)).collect();
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(invoke_target(*kind, &sig)),
                        args,
                    },
                );
                self.pending_call_result = Some(id);
                self.pending_call_type = self.method_return_type(*method_idx);
            }
            Insn::InvokeRange {
                kind,
                start,
                count,
                method_idx,
            } => {
                let sig = self.ctx.dex.method_signature(*method_idx);
                let args: Vec<Operand> = (*start..*start + *count as u16)
                    .map(|r| self.value(r))
                    .collect();
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(invoke_target(*kind, &sig)),
                        args,
                    },
                );
                self.pending_call_result = Some(id);
                self.pending_call_type = self.method_return_type(*method_idx);
            }
            Insn::InvokePolymorphic {
                regs,
                method_idx,
                proto_idx,
            } => {
                let sig = self.ctx.dex.method_signature(*method_idx);
                let args: Vec<Operand> = regs.iter().map(|&r| self.value(r)).collect();
                let _ = proto_idx;
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(format!("@v:{sig}")),
                        args,
                    },
                );
                self.pending_call_result = Some(id);
            }
            Insn::InvokePolymorphicRange {
                start,
                count,
                method_idx,
                proto_idx,
            } => {
                let sig = self.ctx.dex.method_signature(*method_idx);
                let args: Vec<Operand> = (*start..*start + *count as u16)
                    .map(|r| self.value(r))
                    .collect();
                let _ = proto_idx;
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(format!("@v:{sig}")),
                        args,
                    },
                );
                self.pending_call_result = Some(id);
            }
            Insn::InvokeCustom { regs, callsite_idx } => {
                let args: Vec<Operand> = regs.iter().map(|&r| self.value(r)).collect();
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(format!("@cs:{callsite_idx}")),
                        args,
                    },
                );
                self.pending_call_result = Some(id);
            }
            Insn::InvokeCustomRange {
                start,
                count,
                callsite_idx,
            } => {
                let args: Vec<Operand> = (*start..*start + *count as u16)
                    .map(|r| self.value(r))
                    .collect();
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(format!("@cs:{callsite_idx}")),
                        args,
                    },
                );
                self.pending_call_result = Some(id);
            }
            Insn::Unary { dst, src, kind } => {
                let s = self.value(*src);
                let id = self.push_inst(
                    block,
                    SsaOp::UnaryOp {
                        kind: *kind,
                        src: s,
                    },
                );
                self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Value(id),
                    },
                );
            }
            Insn::Binary {
                dst,
                lhs,
                rhs,
                kind,
            } => {
                let l = self.value(*lhs);
                let r = self.value(*rhs);
                let id = self.push_inst(
                    block,
                    SsaOp::BinOp {
                        kind: *kind,
                        lhs: l,
                        rhs: r,
                    },
                );
                self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Value(id),
                    },
                );
            }
            Insn::BinaryLit {
                dst,
                src,
                lit,
                kind,
            } => {
                let s = self.value(*src);
                let id = self.push_inst(
                    block,
                    SsaOp::BinOp {
                        kind: *kind,
                        lhs: s,
                        rhs: Operand::Constant(*lit as i64),
                    },
                );
                self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Value(id),
                    },
                );
            }
            Insn::Binary2Addr { dst, src, kind } => {
                let cur = self.value(*dst);
                let s = self.value(*src);
                let id = self.push_inst(
                    block,
                    SsaOp::BinOp {
                        kind: *kind,
                        lhs: cur,
                        rhs: s,
                    },
                );
                self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Value(id),
                    },
                );
            }
            Insn::Convert { dst, src, from, to } => {
                let s = self.value(*src);
                let id = self.push_inst(
                    block,
                    SsaOp::Call {
                        target: Operand::Symbol(format!("({to})({from})")),
                        args: vec![s],
                    },
                );
                self.define(
                    *dst,
                    block,
                    SsaOp::Copy {
                        src: Operand::Value(id),
                    },
                );
            }
        }
    }

    fn block_id_for_addr(&mut self, addr: u32) -> BlockId {
        if let Some(&id) = self.block_ids.get(&addr) {
            return id;
        }
        self.block_id(addr)
    }
}

pub fn lift_method_to_ssa(
    dex: &DexFile,
    code: &CodeItem,
    method_idx: u32,
) -> (SsaFunction, crate::types::ValueTypes) {
    let ctx = DexLiftContext::new(dex, code, method_idx);
    DexMethodLifter::new(ctx).lift()
}

fn invoke_target(kind: InvokeKind, sig: &str) -> String {
    let prefix = match kind {
        InvokeKind::Virtual => "@v:",
        InvokeKind::Super => "@p:",
        InvokeKind::Direct => "@d:",
        InvokeKind::Static => "@s:",
        InvokeKind::Interface => "@i:",
    };
    format!("{prefix}{sig}")
}
