use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction as IcedInstruction,
    IntelFormatter, OpKind,
};
use revx_core::{Instruction, Reference, ReferenceKind, intern_hex, intern_str};
use std::collections::HashSet;

const DEFAULT_MAX_INSTRUCTIONS_PER_FUNCTION: usize = 1024;

pub fn decode(bytes: &[u8], base: u64) -> Vec<Instruction> {
    decode_with_references(bytes, base).0
}

pub fn decode_block(bytes: &[u8], base: u64) -> Vec<Instruction> {
    decode_with_references(bytes, base).0
}

/// Decode one basic block and extract references in a single pass.
pub fn decode_block_with_references(bytes: &[u8], base: u64) -> (Vec<Instruction>, Vec<Reference>) {
    decode_with_references(bytes, base)
}

/// Decode and extract references in a single pass, avoiding the double-decode
/// overhead of calling `decode` + `extract_references`.
/// Stops at the first control-flow terminator (block boundary).
pub fn decode_with_references(bytes: &[u8], base: u64) -> (Vec<Instruction>, Vec<Reference>) {
    let mut decoder = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut decoded = IcedInstruction::default();
    let estimated = (bytes.len() / 4).min(DEFAULT_MAX_INSTRUCTIONS_PER_FUNCTION);
    let mut instructions = Vec::with_capacity(estimated);
    let mut references = Vec::with_capacity(estimated / 8 + 4);
    let mut text = String::with_capacity(64);

    while decoder.can_decode() && instructions.len() < DEFAULT_MAX_INSTRUCTIONS_PER_FUNCTION {
        decoder.decode_out(&mut decoded);
        if decoded.is_invalid() {
            break;
        }
        text.clear();
        formatter.format(&decoded, &mut text);
        text.make_ascii_lowercase();
        let inst_len = decoded.len();
        let start_index = (decoded.ip().saturating_sub(base)) as usize;
        let end_index = start_index.saturating_add(inst_len);
        let inst_bytes = bytes.get(start_index..end_index).unwrap_or_default();
        let address = decoded.ip();
        instructions.push(Instruction {
            address,
            bytes: intern_hex(inst_bytes),
            text: intern_str(text.as_str()),
        });

        extract_references_from_decoded(&decoded, address, &mut references);

        if decoded.is_jmp_short_or_near()
            || decoded.is_jmp_far_indirect()
            || is_indirect_jmp(&decoded)
            || decoded.is_jcc_short_or_near()
            || decoded.mnemonic() == iced_x86::Mnemonic::Ret
            || decoded.mnemonic() == iced_x86::Mnemonic::Int3
            || decoded.mnemonic() == iced_x86::Mnemonic::Ud2
            || decoded.mnemonic() == iced_x86::Mnemonic::Hlt
        {
            break;
        }
    }

    references = dedupe_references(references);
    (instructions, references)
}

pub fn extract_references(instructions: &[Instruction]) -> Vec<Reference> {
    let mut out = Vec::new();
    for inst in instructions {
        let Ok(bytes) = hex::decode(&*inst.bytes) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(64, &bytes, inst.address, DecoderOptions::NONE);
        let decoded = decoder.decode();
        if decoded.is_invalid() {
            continue;
        }

        extract_references_from_decoded(&decoded, inst.address, &mut out);
    }
    dedupe_references(out)
}

/// Extract references from a single decoded x86-64 instruction.
fn extract_references_from_decoded(
    decoded: &IcedInstruction,
    address: u64,
    out: &mut Vec<Reference>,
) {
    if decoded.is_call_near() {
        out.push(Reference {
            from: address,
            to: decoded.near_branch_target(),
            kind: ReferenceKind::Call,
        });
    } else if decoded.is_call_far_indirect() || is_indirect_call(decoded) {
        if let Some(target) = rip_relative_target(decoded) {
            out.push(Reference {
                from: address,
                to: target,
                kind: ReferenceKind::IndirectCall,
            });
        } else {
            out.push(Reference {
                from: address,
                to: 0,
                kind: ReferenceKind::IndirectCall,
            });
        }
    } else if decoded.is_jcc_short_or_near() {
        out.push(Reference {
            from: address,
            to: decoded.near_branch_target(),
            kind: ReferenceKind::BranchTrue,
        });
        let fallthrough = address + decoded.len() as u64;
        out.push(Reference {
            from: address,
            to: fallthrough,
            kind: ReferenceKind::BranchFalse,
        });
    } else if decoded.is_jmp_short_or_near() {
        out.push(Reference {
            from: address,
            to: decoded.near_branch_target(),
            kind: ReferenceKind::Jump,
        });
    } else if decoded.is_jmp_far_indirect() || is_indirect_jmp(decoded) {
        if let Some(target) = rip_relative_target(decoded) {
            out.push(Reference {
                from: address,
                to: target,
                kind: ReferenceKind::IndirectJump,
            });
        } else {
            out.push(Reference {
                from: address,
                to: 0,
                kind: ReferenceKind::IndirectJump,
            });
        }
    } else {
        if let Some(target) = rip_relative_target(decoded) {
            out.push(Reference {
                from: address,
                to: target,
                kind: ReferenceKind::Data,
            });
        }
        if decoded.flow_control() == FlowControl::Next {
            for operand in 0..decoded.op_count() {
                let op_kind = decoded.op_kind(operand);
                if matches!(
                    op_kind,
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                ) {
                    out.push(Reference {
                        from: address,
                        to: decoded.near_branch_target(),
                        kind: ReferenceKind::Branch,
                    });
                }
            }
        }
    }
}

/// Check if instruction is an indirect call (`call reg` or `call [mem]`).
fn is_indirect_call(inst: &IcedInstruction) -> bool {
    inst.mnemonic() == iced_x86::Mnemonic::Call
        && inst.op0_kind() != OpKind::NearBranch16
        && inst.op0_kind() != OpKind::NearBranch32
        && inst.op0_kind() != OpKind::NearBranch64
        && inst.op0_kind() != OpKind::FarBranch16
        && inst.op0_kind() != OpKind::FarBranch32
}

/// Check if instruction is an indirect jump (`jmp reg` or `jmp [mem]`).
fn is_indirect_jmp(inst: &IcedInstruction) -> bool {
    inst.mnemonic() == iced_x86::Mnemonic::Jmp
        && inst.op0_kind() != OpKind::NearBranch16
        && inst.op0_kind() != OpKind::NearBranch32
        && inst.op0_kind() != OpKind::NearBranch64
        && inst.op0_kind() != OpKind::FarBranch16
        && inst.op0_kind() != OpKind::FarBranch32
}

/// Extract RIP-relative memory target address if the instruction uses RIP-relative addressing.
fn rip_relative_target(inst: &IcedInstruction) -> Option<u64> {
    for op_idx in 0..inst.op_count() {
        if inst.op_kind(op_idx) == OpKind::Memory {
            if inst.memory_base() == iced_x86::Register::RIP {
                return Some(inst.memory_displacement64());
            }
        }
    }
    None
}

fn dedupe_references(mut references: Vec<Reference>) -> Vec<Reference> {
    if references.len() <= 1 {
        return references;
    }
    if references.len() <= 16 {
        references.sort_unstable_by_key(|reference| {
            (reference.from, reference.to, reference.kind as u8)
        });
        references.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.kind == b.kind);
        return references;
    }
    let mut seen = HashSet::with_capacity(references.len());
    references.retain(|reference| seen.insert((reference.from, reference.to, reference.kind)));
    references
}
