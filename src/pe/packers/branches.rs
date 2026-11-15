use std::ops::Range;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};

pub(crate) const CALL_REL32: u8 = 0xE8;
pub(crate) const JUMP_REL32: u8 = 0xE9;
pub(crate) const REL32_LEN: usize = 5;

pub(crate) fn rel32_target(bytes: &[u8], at: usize) -> Option<usize> {
    let rel = i32::from_le_bytes(bytes.get(at + 1..at + REL32_LEN)?.try_into().ok()?);
    (at + REL32_LEN).checked_add_signed(rel as isize)
}

pub(crate) fn set_rel32_target(bytes: &mut [u8], at: usize, target: usize) -> Option<()> {
    let rel = i32::try_from(target as i64 - (at + REL32_LEN) as i64).ok()?;
    bytes
        .get_mut(at + 1..at + REL32_LEN)?
        .copy_from_slice(&rel.to_le_bytes());
    Some(())
}

pub(crate) struct Branch {
    pub(crate) site: usize, // offsets into the image not addresses
    pub(crate) target: usize,
    pub(crate) call: bool,
}

pub(crate) fn direct_branches(
    image: &[u8],
    base: u64,
    bits: u32,
    code: &[Range<usize>],
    resume: &dyn Fn(&Instruction) -> Option<u64>, // where decoding picks up after a call that does not return to its next byte
) -> Vec<Branch> {
    let mut branches = Vec::new();
    for range in code {
        let Some(bytes) = image.get(range.clone()) else {
            continue;
        };
        let start = base + range.start as u64;
        let mut decoder = Decoder::with_ip(bits, bytes, start, DecoderOptions::NONE);

        while decoder.can_decode() {
            let insn = decoder.decode(); // decoded in order since an e8 inside another operand would match as a call
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
                decoder.set_ip(back); // a packer stub may return past padding it put after the call
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
