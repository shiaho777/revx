use yaxpeax_arm::armv8::a64::{Instruction, Operand, Opcode, SizeCode};

const XREGS: [&str; 31] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
    "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26",
    "x27", "x28", "x29", "x30",
];
const WREGS: [&str; 31] = [
    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10", "w11", "w12", "w13",
    "w14", "w15", "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23", "w24", "w25", "w26",
    "w27", "w28", "w29", "w30",
];

#[inline]
fn push_reg(out: &mut String, size: SizeCode, reg: u16) {
    if reg >= 31 {
        match size {
            SizeCode::X => out.push_str("xzr"),
            SizeCode::W => out.push_str("wzr"),
        }
        return;
    }
    match size {
        SizeCode::X => out.push_str(XREGS[reg as usize]),
        SizeCode::W => out.push_str(WREGS[reg as usize]),
    }
}

#[inline]
fn push_reg_sp(out: &mut String, size: SizeCode, reg: u16) {
    if reg >= 31 {
        match size {
            SizeCode::X => out.push_str("sp"),
            SizeCode::W => out.push_str("wsp"),
        }
        return;
    }
    push_reg(out, size, reg);
}

#[inline]
fn push_hex_digits(out: &mut String, mut v: u64) {
    if v == 0 {
        out.push('0');
        return;
    }
    let mut buf = [0u8; 16];
    let mut i = 16usize;
    while v != 0 {
        i -= 1;
        buf[i] = b"0123456789abcdef"[(v & 0xf) as usize];
        v >>= 4;
    }
    out.push_str(unsafe { std::str::from_utf8_unchecked(&buf[i..]) });
}

#[inline]
fn push_imm_hex(out: &mut String, imm: i64) {
    out.push('#');
    if imm < 0 {
        out.push('-');
        out.push_str("0x");
        push_hex_digits(out, (-imm) as u64);
    } else {
        out.push_str("0x");
        push_hex_digits(out, imm as u64);
    }
}

#[inline]
fn push_uimm_hex(out: &mut String, imm: u64) {
    out.push('#');
    out.push_str("0x");
    push_hex_digits(out, imm);
}


#[inline]
fn shift_style_name(style: yaxpeax_arm::armv8::a64::ShiftStyle) -> &'static str {
    use yaxpeax_arm::armv8::a64::ShiftStyle::*;
    match style {
        LSL => "lsl",
        LSR => "lsr",
        ASR => "asr",
        ROR => "ror",
        UXTB => "uxtb",
        UXTH => "uxth",
        UXTW => "uxtw",
        UXTX => "uxtx",
        SXTB => "sxtb",
        SXTH => "sxth",
        SXTW => "sxtw",
        SXTX => "sxtx",
    }
}

#[inline]
fn push_operand(out: &mut String, op: &Operand) -> bool {
    match *op {
        Operand::Register(size, reg) => {
            push_reg(out, size, reg);
            true
        }
        Operand::RegisterOrSP(size, reg) => {
            push_reg_sp(out, size, reg);
            true
        }
        Operand::Immediate(i) => {
            push_imm_hex(out, i as i64);
            true
        }
        Operand::Imm16(i) => {
            push_uimm_hex(out, i as u64);
            true
        }
        Operand::Imm64(i) => {
            push_uimm_hex(out, i);
            true
        }
        Operand::ImmShift(i, shift) => {
            if shift == 0 {
                push_uimm_hex(out, i as u64);
            } else {
                push_uimm_hex(out, i as u64);
                out.push_str(", lsl #");
                push_hex_digits(out, shift as u64);
            }
            true
        }
        Operand::PCOffset(offs) => {
            if offs < 0 {
                out.push_str("$-0x");
                push_hex_digits(out, (-offs) as u64);
            } else {
                out.push_str("$+0x");
                push_hex_digits(out, offs as u64);
            }
            true
        }
        Operand::RegPreIndex(reg, offset, wback) => {
            out.push('[');
            push_reg_sp(out, SizeCode::X, reg);
            if offset != 0 || wback {
                out.push_str(", ");
                push_imm_hex(out, offset as i64);
            }
            out.push(']');
            if wback {
                out.push('!');
            }
            true
        }
        Operand::RegPostIndex(reg, offset) => {
            out.push('[');
            push_reg_sp(out, SizeCode::X, reg);
            out.push_str("], ");
            push_imm_hex(out, offset as i64);
            true
        }
        Operand::RegRegOffset(reg, index_reg, index_size, extend, amount) => {
            out.push('[');
            push_reg_sp(out, SizeCode::X, reg);
            out.push_str(", ");
            push_reg(out, index_size, index_reg);
            let show_shift = amount != 0
                || !matches!(extend, yaxpeax_arm::armv8::a64::ShiftStyle::LSL);
            if show_shift {
                out.push_str(", ");
                out.push_str(shift_style_name(extend));
                if amount != 0
                    || matches!(
                        extend,
                        yaxpeax_arm::armv8::a64::ShiftStyle::LSL
                            | yaxpeax_arm::armv8::a64::ShiftStyle::LSR
                            | yaxpeax_arm::armv8::a64::ShiftStyle::ASR
                            | yaxpeax_arm::armv8::a64::ShiftStyle::ROR
                    )
                {
                    out.push_str(" #");
                    push_hex_digits(out, amount as u64);
                }
            }
            out.push(']');
            true
        }
        Operand::RegShift(style, amt, size, reg) => {
            push_reg(out, size, reg);
            if amt != 0 || !matches!(style, yaxpeax_arm::armv8::a64::ShiftStyle::LSL) {
                out.push_str(", ");
                out.push_str(shift_style_name(style));
                out.push_str(" #");
                push_hex_digits(out, amt as u64);
            }
            true
        }
        Operand::RegPostIndexReg(reg, index_reg) => {
            out.push('[');
            push_reg_sp(out, SizeCode::X, reg);
            out.push_str("], ");
            push_reg(out, SizeCode::X, index_reg);
            true
        }
        Operand::RegisterPair(size, reg) => {
            push_reg(out, size, reg);
            out.push_str(", ");
            push_reg(out, size, reg.wrapping_add(1));
            true
        }
        Operand::ConditionCode(cond) => {
            const CONDS: [&str; 16] = [
                "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt",
                "le", "al", "nv",
            ];
            out.push_str(CONDS[(cond as usize) & 15]);
            true
        }
        Operand::Nothing => true,
        _ => false,
    }
}

#[inline]
fn push_op2(out: &mut String, mnemonic: &str, a: &Operand, b: &Operand) -> bool {
    out.push_str(mnemonic);
    out.push(' ');
    if !push_operand(out, a) {
        return false;
    }
    out.push_str(", ");
    push_operand(out, b)
}

#[inline]
fn push_op3(out: &mut String, mnemonic: &str, a: &Operand, b: &Operand, c: &Operand) -> bool {
    out.push_str(mnemonic);
    out.push(' ');
    if !push_operand(out, a) {
        return false;
    }
    out.push_str(", ");
    if !push_operand(out, b) {
        return false;
    }
    out.push_str(", ");
    push_operand(out, c)
}

pub fn format_inst_fast(inst: &Instruction, out: &mut String) -> bool {
    out.clear();
    let ops = &inst.operands;
    match inst.opcode {
        Opcode::RET => {
            out.push_str("ret");
            true
        }
        Opcode::PACIASP => {
            out.push_str("paciasp");
            true
        }
        Opcode::HINT => {
            if matches!(ops[0], Operand::Imm16(0) | Operand::Immediate(0)) {
                out.push_str("nop");
                return true;
            }
            false
        }
        Opcode::MOVZ => {
            if let (Operand::Register(size, rd), Operand::ImmShift(imm, shift)) = (ops[0], ops[1]) {
                let mut val = (imm as u64) << shift;
                if size == SizeCode::W {
                    val &= 0xffff_ffff;
                }
                out.push_str("mov ");
                push_reg(out, size, rd);
                out.push_str(", ");
                push_uimm_hex(out, val);
                return true;
            }
            false
        }
        Opcode::MOVN => {
            if let (Operand::Register(size, rd), Operand::ImmShift(imm, shift)) = (ops[0], ops[1]) {
                let mut val = !((imm as u64) << shift);
                if size == SizeCode::W {
                    val &= 0xffff_ffff;
                }
                out.push_str("mov ");
                push_reg(out, size, rd);
                out.push_str(", ");
                push_uimm_hex(out, val);
                return true;
            }
            false
        }
        Opcode::ORR => {
            if let Operand::Register(_, 31) = ops[1] {
                if let Operand::Immediate(0) = ops[2] {
                    return push_op2(out, "mov", &ops[0], &ops[1]);
                }
                if let Operand::RegShift(style, amt, size, r) = ops[2] {
                    if matches!(style, yaxpeax_arm::armv8::a64::ShiftStyle::LSL) && amt == 0 {
                        out.push_str("mov ");
                        if !push_operand(out, &ops[0]) {
                            return false;
                        }
                        out.push_str(", ");
                        push_reg(out, size, r);
                        return true;
                    }
                }
                return push_op2(out, "mov", &ops[0], &ops[2]);
            }
            if ops[1] == ops[2] {
                return push_op2(out, "mov", &ops[0], &ops[1]);
            }
            push_op3(out, "orr", &ops[0], &ops[1], &ops[2])
        }
        Opcode::ADD => {
            if let Operand::Immediate(0) = ops[2] {
                if matches!(ops[0], Operand::RegisterOrSP(_, 31))
                    || matches!(ops[1], Operand::RegisterOrSP(_, 31))
                {
                    return push_op2(out, "mov", &ops[0], &ops[1]);
                }
            }
            if let Operand::RegShift(style, amt, size, reg) = ops[2] {
                if matches!(style, yaxpeax_arm::armv8::a64::ShiftStyle::LSL) && amt == 0 {
                    return push_op3(
                        out,
                        "add",
                        &ops[0],
                        &ops[1],
                        &Operand::Register(size, reg),
                    );
                }
            }
            push_op3(out, "add", &ops[0], &ops[1], &ops[2])
        }
        Opcode::ADDS => {
            if let Operand::Register(_, 31) = ops[0] {
                return push_op2(out, "cmn", &ops[1], &ops[2]);
            }
            push_op3(out, "adds", &ops[0], &ops[1], &ops[2])
        }
        Opcode::SUB => {
            if let Operand::Register(_, 31) = ops[1] {
                return push_op2(out, "neg", &ops[0], &ops[2]);
            }
            push_op3(out, "sub", &ops[0], &ops[1], &ops[2])
        }
        Opcode::SUBS => {
            if let Operand::Register(_, 31) = ops[0] {
                return push_op2(out, "cmp", &ops[1], &ops[2]);
            }
            if let Operand::Register(_, 31) = ops[1] {
                return push_op2(out, "negs", &ops[0], &ops[2]);
            }
            push_op3(out, "subs", &ops[0], &ops[1], &ops[2])
        }
        Opcode::AND => push_op3(out, "and", &ops[0], &ops[1], &ops[2]),
        Opcode::ANDS => {
            if let Operand::Register(_, 31) = ops[0] {
                return push_op2(out, "tst", &ops[1], &ops[2]);
            }
            push_op3(out, "ands", &ops[0], &ops[1], &ops[2])
        }
        Opcode::EOR => push_op3(out, "eor", &ops[0], &ops[1], &ops[2]),
        Opcode::MUL => push_op3(out, "mul", &ops[0], &ops[1], &ops[2]),
        Opcode::LSLV => push_op3(out, "lsl", &ops[0], &ops[1], &ops[2]),
        Opcode::LSRV => push_op3(out, "lsr", &ops[0], &ops[1], &ops[2]),
        Opcode::ASRV => push_op3(out, "asr", &ops[0], &ops[1], &ops[2]),
        Opcode::BL => {
            out.push_str("bl ");
            push_operand(out, &ops[0])
        }
        Opcode::B => {
            out.push_str("b ");
            push_operand(out, &ops[0])
        }
        Opcode::BR => {
            out.push_str("br ");
            push_operand(out, &ops[0])
        }
        Opcode::BLR => {
            out.push_str("blr ");
            push_operand(out, &ops[0])
        }
        Opcode::CBZ => {
            out.push_str("cbz ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            push_operand(out, &ops[1])
        }
        Opcode::CBNZ => {
            out.push_str("cbnz ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            push_operand(out, &ops[1])
        }
        Opcode::TBZ | Opcode::TBNZ => {
            let mnem = if matches!(inst.opcode, Opcode::TBZ) {
                "tbz"
            } else {
                "tbnz"
            };
            out.push_str(mnem);
            out.push(' ');
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            push_operand(out, &ops[2])
        }
        Opcode::Bcc(cond) => {
            const CONDS: [&str; 16] = [
                "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt",
                "le", "al", "nv",
            ];
            out.push('b');
            out.push('.');
            out.push_str(CONDS[(cond as usize) & 15]);
            out.push(' ');
            push_operand(out, &ops[0])
        }
        Opcode::ADR => push_op2(out, "adr", &ops[0], &ops[1]),
        Opcode::ADRP => push_op2(out, "adrp", &ops[0], &ops[1]),
        Opcode::LDR => push_op2(out, "ldr", &ops[0], &ops[1]),
        Opcode::LDRB => push_op2(out, "ldrb", &ops[0], &ops[1]),
        Opcode::LDRH => push_op2(out, "ldrh", &ops[0], &ops[1]),
        Opcode::LDRSB => push_op2(out, "ldrsb", &ops[0], &ops[1]),
        Opcode::LDRSH => push_op2(out, "ldrsh", &ops[0], &ops[1]),
        Opcode::LDRSW => push_op2(out, "ldrsw", &ops[0], &ops[1]),
        Opcode::STR => push_op2(out, "str", &ops[0], &ops[1]),
        Opcode::STRB => push_op2(out, "strb", &ops[0], &ops[1]),
        Opcode::STRH => push_op2(out, "strh", &ops[0], &ops[1]),
        Opcode::LDUR => push_op2(out, "ldur", &ops[0], &ops[1]),
        Opcode::STUR => push_op2(out, "stur", &ops[0], &ops[1]),
        Opcode::LDP => push_op3(out, "ldp", &ops[0], &ops[1], &ops[2]),
        Opcode::STP => push_op3(out, "stp", &ops[0], &ops[1], &ops[2]),
        Opcode::CSEL => {
            out.push_str("csel ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[2]) {
                return false;
            }
            out.push_str(", ");
            push_operand(out, &ops[3])
        }
        Opcode::CSINC => {
            if let (
                Operand::Register(_, _),
                Operand::Register(_, n),
                Operand::Register(_, m),
                Operand::ConditionCode(cond),
            ) = (ops[0], ops[1], ops[2], ops[3])
            {
                if n == 31 && m == 31 && cond < 0b1110 {
                    out.push_str("cset ");
                    if !push_operand(out, &ops[0]) {
                        return false;
                    }
                    out.push_str(", ");
                    return push_operand(out, &Operand::ConditionCode(cond ^ 1));
                }
                if n == m && cond < 0b1110 {
                    out.push_str("cinc ");
                    if !push_operand(out, &ops[0]) {
                        return false;
                    }
                    out.push_str(", ");
                    if !push_operand(out, &ops[1]) {
                        return false;
                    }
                    out.push_str(", ");
                    return push_operand(out, &Operand::ConditionCode(cond ^ 1));
                }
            }
            out.push_str("csinc ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[2]) {
                return false;
            }
            out.push_str(", ");
            push_operand(out, &ops[3])
        }
        Opcode::MOVK => {
            out.push_str("movk ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            push_operand(out, &ops[1])
        }
        Opcode::BIC => push_op3(out, "bic", &ops[0], &ops[1], &ops[2]),
        Opcode::EON => push_op3(out, "eon", &ops[0], &ops[1], &ops[2]),
        Opcode::ORN => {
            if let Operand::Register(_, 31) = ops[1] {
                return push_op2(out, "mvn", &ops[0], &ops[2]);
            }
            push_op3(out, "orn", &ops[0], &ops[1], &ops[2])
        }
        Opcode::ADC => push_op3(out, "adc", &ops[0], &ops[1], &ops[2]),
        Opcode::SBC => {
            if let Operand::Register(_, 31) = ops[1] {
                return push_op2(out, "ngc", &ops[0], &ops[2]);
            }
            push_op3(out, "sbc", &ops[0], &ops[1], &ops[2])
        }
        Opcode::MADD => {
            if matches!(ops[3], Operand::Register(_, 31)) {
                return push_op3(out, "mul", &ops[0], &ops[1], &ops[2]);
            }
            out.push_str("madd ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[2]) {
                return false;
            }
            out.push_str(", ");
            push_operand(out, &ops[3])
        }
        Opcode::UBFM => format_ubfm(out, ops),
        Opcode::SBFM => format_sbfm(out, ops),
        Opcode::BFM => format_bfm(out, ops),
        Opcode::MSUB => {
            if matches!(ops[3], Operand::Register(_, 31)) {
                return push_op3(out, "mneg", &ops[0], &ops[1], &ops[2]);
            }
            out.push_str("msub ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[2]) {
                return false;
            }
            out.push_str(", ");
            push_operand(out, &ops[3])
        }
        Opcode::SDIV => push_op3(out, "sdiv", &ops[0], &ops[1], &ops[2]),
        Opcode::UDIV => push_op3(out, "udiv", &ops[0], &ops[1], &ops[2]),
        Opcode::CLZ => push_op2(out, "clz", &ops[0], &ops[1]),
        Opcode::CLS => push_op2(out, "cls", &ops[0], &ops[1]),
        Opcode::RBIT => push_op2(out, "rbit", &ops[0], &ops[1]),
        Opcode::REV => push_op2(out, "rev", &ops[0], &ops[1]),
        Opcode::REV16 => push_op2(out, "rev16", &ops[0], &ops[1]),
        Opcode::REV32 => push_op2(out, "rev32", &ops[0], &ops[1]),
        Opcode::RORV => push_op3(out, "ror", &ops[0], &ops[1], &ops[2]),
        Opcode::EXTR => {
            if ops[1] == ops[2] {
                return push_op3(out, "ror", &ops[0], &ops[1], &ops[3]);
            }
            out.push_str("extr ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[2]) {
                return false;
            }
            out.push_str(", ");
            push_operand(out, &ops[3])
        }
        Opcode::BICS => push_op3(out, "bics", &ops[0], &ops[1], &ops[2]),
        Opcode::ADCS => push_op3(out, "adcs", &ops[0], &ops[1], &ops[2]),
        Opcode::SBCS => {
            if let Operand::Register(_, 31) = ops[1] {
                return push_op2(out, "ngcs", &ops[0], &ops[2]);
            }
            push_op3(out, "sbcs", &ops[0], &ops[1], &ops[2])
        }
        Opcode::CSNEG => {
            if ops[1] == ops[2] {
                if let Operand::ConditionCode(cond) = ops[3] {
                    out.push_str("cneg ");
                    if !push_operand(out, &ops[0]) {
                        return false;
                    }
                    out.push_str(", ");
                    if !push_operand(out, &ops[1]) {
                        return false;
                    }
                    out.push_str(", ");
                    return push_operand(out, &Operand::ConditionCode(cond ^ 1));
                }
            }
            out.push_str("csneg ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[2]) {
                return false;
            }
            out.push_str(", ");
            push_operand(out, &ops[3])
        }
        Opcode::CSINV => {
            if let (Operand::Register(_, 31), Operand::Register(_, 31), Operand::ConditionCode(cond)) =
                (ops[1], ops[2], ops[3])
            {
                out.push_str("csetm ");
                if !push_operand(out, &ops[0]) {
                    return false;
                }
                out.push_str(", ");
                return push_operand(out, &Operand::ConditionCode(cond ^ 1));
            }
            if ops[1] == ops[2] {
                if let Operand::ConditionCode(cond) = ops[3] {
                    out.push_str("cinv ");
                    if !push_operand(out, &ops[0]) {
                        return false;
                    }
                    out.push_str(", ");
                    if !push_operand(out, &ops[1]) {
                        return false;
                    }
                    out.push_str(", ");
                    return push_operand(out, &Operand::ConditionCode(cond ^ 1));
                }
            }
            out.push_str("csinv ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[2]) {
                return false;
            }
            out.push_str(", ");
            push_operand(out, &ops[3])
        }
        Opcode::CCMP => {
            out.push_str("ccmp ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[2]) {
                return false;
            }
            out.push_str(", ");
            push_operand(out, &ops[3])
        }
        Opcode::CCMN => {
            out.push_str("ccmn ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[2]) {
                return false;
            }
            out.push_str(", ");
            push_operand(out, &ops[3])
        }
        Opcode::LDPSW => push_op3(out, "ldpsw", &ops[0], &ops[1], &ops[2]),
        Opcode::STNP => push_op3(out, "stnp", &ops[0], &ops[1], &ops[2]),
        Opcode::LDNP => push_op3(out, "ldnp", &ops[0], &ops[1], &ops[2]),
        Opcode::LDURB => push_op2(out, "ldurb", &ops[0], &ops[1]),
        Opcode::LDURH => push_op2(out, "ldurh", &ops[0], &ops[1]),
        Opcode::LDURSB => push_op2(out, "ldursb", &ops[0], &ops[1]),
        Opcode::LDURSH => push_op2(out, "ldursh", &ops[0], &ops[1]),
        Opcode::LDURSW => push_op2(out, "ldursw", &ops[0], &ops[1]),
        Opcode::STURB => push_op2(out, "sturb", &ops[0], &ops[1]),
        Opcode::STURH => push_op2(out, "sturh", &ops[0], &ops[1]),
        Opcode::SVC => {
            out.push_str("svc ");
            push_operand(out, &ops[0])
        }
        Opcode::BRK => {
            out.push_str("brk ");
            push_operand(out, &ops[0])
        }
        Opcode::MRS => push_op2(out, "mrs", &ops[0], &ops[1]),
        Opcode::MSR => push_op2(out, "msr", &ops[0], &ops[1]),
        Opcode::SMULH => push_op3(out, "smulh", &ops[0], &ops[1], &ops[2]),
        Opcode::UMULH => push_op3(out, "umulh", &ops[0], &ops[1], &ops[2]),
        Opcode::SMADDL => {
            if matches!(ops[3], Operand::Register(_, 31)) {
                return push_op3(out, "smull", &ops[0], &ops[1], &ops[2]);
            }
            out.push_str("smaddl ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[2]) {
                return false;
            }
            out.push_str(", ");
            push_operand(out, &ops[3])
        }
        Opcode::UMADDL => {
            if matches!(ops[3], Operand::Register(_, 31)) {
                return push_op3(out, "umull", &ops[0], &ops[1], &ops[2]);
            }
            out.push_str("umaddl ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[2]) {
                return false;
            }
            out.push_str(", ");
            push_operand(out, &ops[3])
        }
        _ => false,
    }
}

fn format_ubfm(out: &mut String, ops: &[Operand; 4]) -> bool {
    if let (
        Operand::Register(SizeCode::W, _),
        Operand::Register(SizeCode::W, _),
        Operand::Immediate(0),
        Operand::Immediate(imms),
    ) = (ops[0], ops[1], ops[2], ops[3])
    {
        if imms == 7 {
            return push_op2(out, "uxtb", &ops[0], &ops[1]);
        }
        if imms == 15 {
            return push_op2(out, "uxth", &ops[0], &ops[1]);
        }
    }
    if let (
        Operand::Register(size, _),
        Operand::Register(_, _),
        Operand::Immediate(immr),
        Operand::Immediate(imms),
    ) = (ops[0], ops[1], ops[2], ops[3])
    {
        let width: u32 = if size == SizeCode::X { 64 } else { 32 };
        if (imms == 63 && size == SizeCode::X) || (imms == 31 && size == SizeCode::W) {
            return push_op3(out, "lsr", &ops[0], &ops[1], &ops[2]);
        }
        if imms.saturating_add(1) == immr {
            let Some(shift) = width.checked_sub(imms).and_then(|v| v.checked_sub(1)) else {
                return false;
            };
            out.push_str("lsl ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            push_uimm_hex(out, shift as u64);
            return true;
        }
        if imms < immr {
            let Some(lsb) = width.checked_sub(immr) else {
                return false;
            };
            out.push_str("ubfiz ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            push_uimm_hex(out, lsb as u64);
            out.push_str(", ");
            push_uimm_hex(out, imms.saturating_add(1) as u64);
            return true;
        }
        let Some(w) = imms.checked_sub(immr).map(|v| v.saturating_add(1)) else {
            return false;
        };
        out.push_str("ubfx ");
        if !push_operand(out, &ops[0]) {
            return false;
        }
        out.push_str(", ");
        if !push_operand(out, &ops[1]) {
            return false;
        }
        out.push_str(", ");
        push_uimm_hex(out, immr as u64);
        out.push_str(", ");
        push_uimm_hex(out, w as u64);
        return true;
    }
    false
}

fn format_sbfm(out: &mut String, ops: &[Operand; 4]) -> bool {
    if let (
        Operand::Register(size, _),
        Operand::Register(_, _),
        Operand::Immediate(_immr),
        Operand::Immediate(imms),
    ) = (ops[0], ops[1], ops[2], ops[3])
    {
        if (imms == 63 && size == SizeCode::X) || (imms == 31 && size == SizeCode::W) {
            return push_op3(out, "asr", &ops[0], &ops[1], &ops[2]);
        }
    }
    if let (
        Operand::Register(_, _),
        Operand::Register(_sz, src),
        Operand::Immediate(0),
        Operand::Immediate(imms),
    ) = (ops[0], ops[1], ops[2], ops[3])
    {
        let src_w = Operand::Register(SizeCode::W, src);
        if imms == 7 {
            return push_op2(out, "sxtb", &ops[0], &src_w);
        }
        if imms == 15 {
            return push_op2(out, "sxth", &ops[0], &src_w);
        }
        if imms == 31 {
            return push_op2(out, "sxtw", &ops[0], &src_w);
        }
    }
    if let (
        Operand::Register(size, _),
        Operand::Register(_, _),
        Operand::Immediate(immr),
        Operand::Immediate(imms),
    ) = (ops[0], ops[1], ops[2], ops[3])
    {
        let width: u32 = if size == SizeCode::X { 64 } else { 32 };
        if immr < imms {
            let Some(lsb) = width.checked_sub(imms) else {
                return false;
            };
            out.push_str("sbfiz ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            push_uimm_hex(out, lsb as u64);
            out.push_str(", ");
            push_uimm_hex(out, immr.saturating_add(1) as u64);
            return true;
        }
        let Some(w) = imms.checked_sub(immr).map(|v| v.saturating_add(1)) else {
            return false;
        };
        out.push_str("sbfx ");
        if !push_operand(out, &ops[0]) {
            return false;
        }
        out.push_str(", ");
        if !push_operand(out, &ops[1]) {
            return false;
        }
        out.push_str(", ");
        push_uimm_hex(out, immr as u64);
        out.push_str(", ");
        push_uimm_hex(out, w as u64);
        return true;
    }
    false
}

fn format_bfm(out: &mut String, ops: &[Operand; 4]) -> bool {
    if let (
        Operand::Register(sz, _),
        Operand::Register(_, rn),
        Operand::Immediate(immr),
        Operand::Immediate(imms),
    ) = (ops[0], ops[1], ops[2], ops[3])
    {
        if imms < immr {
            let width = imms.saturating_add(1);
            let mask = if sz == SizeCode::W { 0x1fu32 } else { 0x3fu32 };
            let lsb = ((-(immr as i32)) as u32) & mask;
            if rn == 31 {
                out.push_str("bfc ");
                if !push_operand(out, &ops[0]) {
                    return false;
                }
                out.push_str(", ");
                push_uimm_hex(out, lsb as u64);
                out.push_str(", ");
                push_uimm_hex(out, width as u64);
                return true;
            }
            out.push_str("bfi ");
            if !push_operand(out, &ops[0]) {
                return false;
            }
            out.push_str(", ");
            if !push_operand(out, &ops[1]) {
                return false;
            }
            out.push_str(", ");
            push_uimm_hex(out, lsb as u64);
            out.push_str(", ");
            push_uimm_hex(out, width as u64);
            return true;
        }
        let lsb = immr;
        let Some(width) = imms.checked_sub(lsb).map(|v| v.saturating_add(1)) else {
            return false;
        };
        out.push_str("bfxil ");
        if !push_operand(out, &ops[0]) {
            return false;
        }
        out.push_str(", ");
        if !push_operand(out, &ops[1]) {
            return false;
        }
        out.push_str(", ");
        push_uimm_hex(out, lsb as u64);
        out.push_str(", ");
        push_uimm_hex(out, width as u64);
        return true;
    }
    false
}
