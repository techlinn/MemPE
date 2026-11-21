use super::code_references::{absolute_slot, image_offset, rip_relative_slot};
use super::read_pointer;
use crate::pe::PeKind;
use crate::pe::exports::{ExportIndex, Resolved};
use crate::unpack::x86::opcodes::{GROUP_FF, INDIRECT_LEN, JUMP_MODRM, MOV_REG_IMM32, REX_W};

const MAX_THUNK_DEPTH: usize = 4;
const JUMP_INDIRECT: [u8; 2] = [GROUP_FF, JUMP_MODRM];
const JUMP_ACCUMULATOR: [u8; 2] = [GROUP_FF, 0xE0];

pub(super) enum Unresolved {
    OwnImage,
    OtherModule,
    OutsideImage,
    UnknownStub,
    ChainExhausted,
}

pub(super) fn resolve_value<'a>(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    value: usize,
    exports: &'a ExportIndex,
) -> Result<Resolved<'a>, Unresolved> {
    let mut value = value;

    for _ in 0..=MAX_THUNK_DEPTH {
        if let Some(found) = exports.resolve(value) {
            if image_offset(observed_base, memory.len(), value).is_some() {
                return Err(Unresolved::OwnImage);
            }

            return Ok(found);
        }

        let Some(rva) = image_offset(observed_base, memory.len(), value) else {
            return Err(match exports.covers(value) {
                true => Unresolved::OtherModule,
                false => Unresolved::OutsideImage,
            });
        };

        let next = match kind {
            PeKind::Pe32Plus => decode_x64_thunk(memory, observed_base, rva),
            PeKind::Pe32 => decode_x86_thunk(memory, observed_base, rva),
        }
        .ok_or(Unresolved::UnknownStub)?;

        if next == value {
            return Err(Unresolved::ChainExhausted);
        }

        value = next;
    }

    Err(Unresolved::ChainExhausted)
}

fn immediate_jump<'a>(code: &'a [u8], load: &[u8], width: usize) -> Option<&'a [u8]> {
    let immediate = code.strip_prefix(load)?.get(..width)?;
    let jump = code.get(load.len().checked_add(width)?..)?;

    jump.starts_with(&JUMP_ACCUMULATOR).then_some(immediate)
}

fn decode_x64_thunk(memory: &[u8], base: usize, rva: usize) -> Option<usize> {
    let code = memory.get(rva..)?;

    if let Some(jump) = code.get(..INDIRECT_LEN)
        && jump.starts_with(&JUMP_INDIRECT)
    {
        let slot = rip_relative_slot(base, rva, INDIRECT_LEN, &jump[2..])?;
        return read_pointer(memory, slot as usize, 8);
    }

    read_pointer(immediate_jump(code, &[REX_W, MOV_REG_IMM32], 8)?, 0, 8)
}

fn decode_x86_thunk(memory: &[u8], base: usize, rva: usize) -> Option<usize> {
    let code = memory.get(rva..)?;

    if let Some(jump) = code.get(..INDIRECT_LEN)
        && jump.starts_with(&JUMP_INDIRECT)
    {
        return read_pointer(memory, absolute_slot(base, &jump[2..])?, 4);
    }

    read_pointer(immediate_jump(code, &[MOV_REG_IMM32], 4)?, 0, 4)
}
