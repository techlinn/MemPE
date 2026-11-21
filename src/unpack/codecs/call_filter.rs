use crate::unpack::x86::opcodes::{CALL_REL32, JUMP_REL32};

const SITE: usize = 5; // opcode and rel32

#[derive(Clone, Copy)]
pub(crate) enum Stored {
    Le32,
    Be32,
    Le24, // marker byte, then three bytes
    Be24,
}

#[derive(Clone, Copy)]
pub(crate) struct CallFilter {
    pub(crate) marks: Option<[u8; 2]>, // bytes left after a call and a jump
    pub(crate) stored: Stored,
    pub(crate) counted_from: usize, // 0: opcode position, 1: operand's
}

pub(crate) fn undo(code: &mut [u8], end: usize, filter: CallFilter) {
    let end = end.min(code.len());
    let mut at = 0;

    while at + SITE <= end {
        let site = [
            code[at],
            code[at + 1],
            code[at + 2],
            code[at + 3],
            code[at + 4],
        ];
        let branch = match site[0] {
            CALL_REL32 => 0,
            JUMP_REL32 => 1,
            _ => {
                at += 1;
                continue;
            }
        };
        if filter.marks.is_some_and(|marks| marks[branch] != site[1]) {
            at += 1;
            continue;
        }

        let position = match filter.stored {
            Stored::Le32 => u32::from_le_bytes([site[1], site[2], site[3], site[4]]),
            Stored::Be32 => u32::from_be_bytes([site[1], site[2], site[3], site[4]]),
            Stored::Le24 => u32::from_le_bytes([site[2], site[3], site[4], 0]),
            Stored::Be24 => u32::from_be_bytes([0, site[2], site[3], site[4]]),
        };
        let relative = position.wrapping_sub((at + filter.counted_from) as u32);
        code[at + 1..at + SITE].copy_from_slice(&relative.to_le_bytes());
        at += SITE;
    }
}
