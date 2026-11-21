use std::ops::Range;

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register, RflagsBits,
};

use super::opcodes::MAX_INSTRUCTION;
pub(crate) use super::opcodes::{CALL_REL32, JUMP_REL32};

pub(crate) const REL32_LEN: usize = 5;
pub(crate) const MAX_CALL_PADDING: u64 = 2; // stub may return two bytes past its call
pub(crate) const STATUS_RFLAGS: u32 = RflagsBits::CF
    | RflagsBits::PF
    | RflagsBits::AF
    | RflagsBits::ZF
    | RflagsBits::SF
    | RflagsBits::OF;

pub(crate) fn decode_one(bits: u32, code: &[u8], at: u64) -> Option<Instruction> {
    let insn = Decoder::with_ip(bits, code, at, DecoderOptions::NONE).decode();
    (!insn.is_invalid()).then_some(insn)
}

// every instruction in range, invalid ones included; none for a range outside the image
pub(crate) fn instructions<'a>(
    image: &'a [u8],
    base: u64,
    bits: u32,
    range: &Range<usize>,
) -> impl Iterator<Item = Instruction> + use<'a> {
    let bytes = image.get(range.clone()).unwrap_or_default();
    Decoder::with_ip(bits, bytes, base + range.start as u64, DecoderOptions::NONE).into_iter()
}

pub(crate) fn near_jump(bits: u32, target: u64) -> Option<Instruction> {
    let code = match bits {
        64 => Code::Jmp_rel32_64,
        _ => Code::Jmp_rel32_32,
    };
    Instruction::with_branch(code, target).ok()
}

pub(crate) fn decode_at(image: &[u8], base: u64, bits: u32, at: u64) -> Option<Instruction> {
    let offset = usize::try_from(at.checked_sub(base)?).ok()?;
    let window = image.get(offset..offset.saturating_add(MAX_INSTRUCTION).min(image.len()))?;
    decode_one(bits, window, at)
}

// a memory operand at one fixed address, absolute or rip-relative (iced resolves those already)
pub(crate) fn fixed_address(insn: &Instruction) -> Option<u64> {
    let fixed = insn.op0_kind() == OpKind::Memory
        && matches!(
            insn.memory_base(),
            Register::None | Register::RIP | Register::EIP
        )
        && insn.memory_index() == Register::None;
    fixed.then(|| insn.memory_displacement64())
}

// a displacement or immediate as the cpu adds it: 32-bit code sign-extends from bit 31
pub(crate) fn signed(value: u64, bits: u32) -> i64 {
    match bits {
        64 => value as i64,
        _ => i64::from(value as u32 as i32),
    }
}

pub(crate) fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate64
    )
}

pub(crate) fn rel32_target(bytes: &[u8], at: usize) -> Option<usize> {
    relative(bytes, at + 1, at + REL32_LEN)
}

pub(crate) fn relative(bytes: &[u8], operand: usize, next: usize) -> Option<usize> {
    let field = bytes.get(operand..operand.checked_add(4)?)?;
    let displacement = i32::from_le_bytes(field.try_into().ok()?);
    next.checked_add_signed(displacement as isize) // from the instruction's end
}

pub(crate) fn set_rel32_target(bytes: &mut [u8], at: usize, target: usize) -> Option<()> {
    let rel = i32::try_from(target as i64 - (at + REL32_LEN) as i64).ok()?;
    bytes
        .get_mut(at + 1..at + REL32_LEN)?
        .copy_from_slice(&rel.to_le_bytes());
    Some(())
}

pub(crate) struct Branch {
    pub(crate) site: usize, // offsets, not addresses
    pub(crate) target: usize,
    pub(crate) call: bool,
}

pub(crate) fn direct_branches(
    image: &[u8],
    base: u64,
    bits: u32,
    code: &[Range<usize>],
    resume: &dyn Fn(&Instruction) -> Option<u64>,
) -> Vec<Branch> {
    let mut branches = Vec::new();
    for range in code {
        let Some(bytes) = image.get(range.clone()) else {
            continue;
        };
        let start = base + range.start as u64;
        let mut decoder = Decoder::with_ip(bits, bytes, start, DecoderOptions::NONE);

        while decoder.can_decode() {
            let insn = decoder.decode(); // in order, e8 inside operands
            let call = insn.flow_control() == FlowControl::Call;
            let jump = insn.flow_control() == FlowControl::UnconditionalBranch;
            if !(call || jump) || !is_near_immediate(&insn) {
                continue;
            }

            if let (Some(site), Some(target)) = (
                insn.ip().checked_sub(base),
                insn.near_branch_target().checked_sub(base),
            ) {
                branches.push(Branch {
                    site: site as usize,
                    target: target as usize,
                    call,
                });
            }

            if let Some(back) = resume(&insn)
                && back > insn.next_ip()
                && back < start + bytes.len() as u64
            {
                decoder.set_ip(back);
                let _ = decoder.set_position((back - start) as usize);
            }
        }
    }
    branches
}

pub(crate) fn is_near_immediate(insn: &Instruction) -> bool {
    matches!(
        insn.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
}

pub(crate) fn retarget(insn: &mut Instruction, target: u64) {
    if !is_near_immediate(insn) {
        return;
    }

    match insn.op0_kind() {
        OpKind::NearBranch64 => insn.set_near_branch64(target),
        OpKind::NearBranch32 => insn.set_near_branch32(target as u32),
        _ => insn.set_near_branch16(target as u16),
    }
}
