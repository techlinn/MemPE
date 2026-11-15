use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Instruction,
    InstructionBlock, Mnemonic, OpKind,
};

use super::body::{Body, End};
use super::encodings::{DIRECTIONS, displacement, displacement_size};
use crate::pe::packers::branches::is_near_immediate;

const ALIGNMENT: u64 = 16; // compilers pad a loop head with a long nop up to this boundary
const NOPS: [&[u8]; 9] = [
    &[],
    &[0x90],
    &[0x66, 0x90],
    &[0x0F, 0x1F, 0x00],
    &[0x0F, 0x1F, 0x40, 0x00],
    &[0x0F, 0x1F, 0x44, 0x00, 0x00],
    &[0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00],
    &[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00],
    &[0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
]; // the multi-byte nops intel recommends, which msvc pads with
const OPERAND_SIZE: u8 = 0x66;
const LONGEST_NOP: usize = 15; // msvc stretches the longest one with operand size prefixes to pad up to here in one instruction

const REX: u8 = 0x40;
const PUSH: u8 = 0x50;

#[derive(Clone, Copy)]
pub(super) struct Style {
    reversed: bool, // register to register through the r, r/m opcodes, as msvc writes them, rather than r/m, r
}

impl Style {
    pub(super) fn of(image: &[u8], base: u64, bits: u32, code: &[Range<usize>]) -> Self {
        let mut forward = 0usize;
        let mut reversed = 0usize;
        for range in code {
            let Some(bytes) = image.get(range.clone()) else {
                continue;
            };
            let mut decoder =
                Decoder::with_ip(bits, bytes, base + range.start as u64, DecoderOptions::NONE);
            while decoder.can_decode() {
                let insn = decoder.decode();
                if !between_registers(&insn) {
                    continue;
                }

                forward += usize::from(DIRECTIONS.iter().any(|(rm_r, _)| *rm_r == insn.code()));
                reversed += usize::from(DIRECTIONS.iter().any(|(_, r_rm)| *r_rm == insn.code()));
            }
        }

        Self {
            reversed: reversed > forward,
        }
    }

    fn apply(self, insn: &mut Instruction) {
        let pair = DIRECTIONS
            .iter()
            .find(|(rm_r, r_rm)| *rm_r == insn.code() || *r_rm == insn.code());
        if let Some((rm_r, r_rm)) = pair.filter(|_| between_registers(insn)) {
            insn.set_code(if self.reversed { *r_rm } else { *rm_r });
        }
    }
}

fn between_registers(insn: &Instruction) -> bool {
    insn.op_count() == 2
        && insn.op_kind(0) == OpKind::Register
        && insn.op_kind(1) == OpKind::Register
}

pub(super) enum Piece {
    Code(Vec<Instruction>),
    Jump,    // a block that was nothing but a jump to the next one, as an original jmp becomes
    Padding, // junk alone ahead of a loop head, where the compiler aligned it with a long nop
}

#[derive(Clone, Copy)]
enum Item {
    Label(u64),
    Insn(Instruction),
    Branch(Instruction, u64),
}

pub(super) fn layout(
    body: &Body,
    pieces: &BTreeMap<u64, Piece>,
    bits: u32,
) -> Option<Vec<Instruction>> {
    let mut items = Vec::new();
    let mut placed = BTreeSet::new();
    let mut work = vec![body.entry];

    while let Some(start) = work.pop() {
        let mut at = start;
        loop {
            if !placed.insert(at) {
                items.push(Item::Branch(jump(bits)?, at));
                break;
            }

            let block = body.blocks.get(&at)?;
            items.push(Item::Label(at));
            match (pieces.get(&at)?, &block.end) {
                (Piece::Jump, End::Next(next)) => {
                    items.push(Item::Branch(jump(bits)?, *next));
                    work.insert(0, *next); // and what it jumps over, last queued, comes next as the compiler laid it
                    break;
                }
                (Piece::Code(code), _) => items.extend(code.iter().copied().map(Item::Insn)),
                (Piece::Padding, _) => items.push(Item::Insn(Instruction::with(Code::Nopd))), // sized on encoding
                (Piece::Jump, _) => {}
            }

            match &block.end {
                End::Next(next) => at = *next,
                End::Branch(branch) => {
                    let target = branch.near_branch_target();
                    match body.blocks.contains_key(&target) {
                        true => {
                            items.push(Item::Branch(*branch, target));
                            work.push(target);
                        }
                        false => items.push(Item::Insn(*branch)),
                    }
                    at = branch.next_ip();
                }
                End::Exit(exit) => {
                    items.push(Item::Insn(*exit));
                    break;
                }
            }
        }
        work.retain(|start| !placed.contains(start));
    }

    resolve(drop_needless_jumps(items), bits)
}

fn drop_needless_jumps(items: Vec<Item>) -> Vec<Item> {
    let falls_into = |index: usize, target: u64| {
        items[index + 1..]
            .iter()
            .take_while(|next| matches!(next, Item::Label(_)))
            .any(|next| matches!(next, Item::Label(label) if *label == target))
    };
    let needless = |index: usize, item: &Item| matches!(item, Item::Branch(insn, target) if insn.mnemonic() == Mnemonic::Jmp && falls_into(index, *target));

    items
        .iter()
        .enumerate()
        .filter(|(index, item)| !needless(*index, item))
        .map(|(_, item)| *item)
        .collect()
}

fn resolve(items: Vec<Item>, bits: u32) -> Option<Vec<Instruction>> {
    let count = items
        .iter()
        .filter(|item| !matches!(item, Item::Label(_)))
        .count() as u64;
    let first = match bits {
        64 => u64::MAX - count,
        _ => u64::from(u32::MAX) - count, // a 32-bit branch keeps 32 bits of its target
    };

    let mut labels = BTreeMap::new();
    let mut code = Vec::new();
    let mut branches = Vec::new();
    for item in items {
        let ip = first + code.len() as u64; // the encoder finds a target by ip, and these are free
        match item {
            Item::Label(label) => {
                labels.insert(label, ip);
            }
            Item::Insn(mut insn) => {
                insn.set_ip(ip);
                code.push(insn);
            }
            Item::Branch(mut insn, target) => {
                insn.set_ip(ip);
                branches.push((code.len(), target));
                code.push(insn);
            }
        }
    }

    for (index, target) in branches {
        let label = *labels.get(&target)?;
        retarget(code.get_mut(index)?, label);
    }
    Some(code)
}

pub(super) fn encode(code: &[Instruction], bits: u32, at: u64, style: Style) -> Option<Vec<u8>> {
    let mut code = code.to_vec();
    for insn in &mut code {
        style.apply(insn);
        shorten_displacement(insn, bits);
    }

    loop {
        let encoded = BlockEncoder::encode(
            bits,
            InstructionBlock::new(&code, at),
            BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
        )
        .ok()?;

        let padding = code
            .iter()
            .position(|insn| insn.mnemonic() == Mnemonic::Nop); // a nop in mutated code only ever aligned a loop
        let Some(index) = padding else {
            return Some(encoded.code_buffer);
        };

        let offset = u64::from(*encoded.new_instruction_offsets.get(index)?);
        let length = ((ALIGNMENT - (at + offset) % ALIGNMENT) % ALIGNMENT) as usize;
        let ip = code.get(index)?.ip();
        let mut replacement = match length {
            0 => Vec::new(),
            length => vec![Instruction::with_declare_byte(&nop(length)).ok()?],
        };
        if let Some(padding) = replacement.first_mut() {
            padding.set_ip(ip);
        } else if let Some(next) = code.get(index + 1).map(Instruction::ip) {
            retarget_all(&mut code, ip, next); // already aligned, so the nop goes and its branches land past it
        }
        code.splice(index..=index, replacement);
    }
}

fn shorten_displacement(insn: &mut Instruction, bits: u32) {
    let addresses = (0..insn.op_count()).any(|operand| insn.op_kind(operand) == OpKind::Memory);
    if addresses {
        let size = displacement_size(displacement(insn, bits), insn.memory_base(), bits);
        insn.set_memory_displ_size(size); // themida's junk pads displacements a compiler writes in one byte
    }
}

pub(super) fn nops(length: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        bytes.extend(nop((length - bytes.len()).min(LONGEST_NOP)));
    }
    bytes
}

fn nop(length: usize) -> Vec<u8> {
    let plain = length.min(NOPS.len() - 1);
    let mut bytes = vec![OPERAND_SIZE; length - plain];
    bytes.extend_from_slice(NOPS[plain]);
    bytes
}

pub(super) fn hot_patchable(code: &mut [Instruction], bits: u32) {
    let Some(first) = code.first_mut() else {
        return;
    };
    let one_byte =
        bits == 64 && first.code() == Code::Push_r64 && first.op0_register().number() < 8;
    if !one_byte {
        return;
    }

    let opcode = PUSH + first.op0_register().number() as u8;
    if let Ok(mut padded) = Instruction::with_declare_byte(&[REX, opcode]) {
        padded.set_ip(first.ip());
        *first = padded; // msvc opens an x64 function with two bytes at least, so it can be hot patched
    }
}

pub(super) fn retarget(insn: &mut Instruction, target: u64) {
    if !is_near_immediate(insn) {
        return;
    }

    match insn.op0_kind() {
        OpKind::NearBranch64 => insn.set_near_branch64(target),
        OpKind::NearBranch32 => insn.set_near_branch32(target as u32),
        _ => insn.set_near_branch16(target as u16),
    }
}

pub(super) fn retarget_all(code: &mut [Instruction], from: u64, to: u64) {
    for insn in code {
        if is_near_immediate(insn) && insn.near_branch_target() == from {
            retarget(insn, to);
        }
    }
}

fn jump(bits: u32) -> Option<Instruction> {
    let code = match bits {
        64 => Code::Jmp_rel32_64,
        _ => Code::Jmp_rel32_32,
    };
    Instruction::with_branch(code, 0).ok()
}
