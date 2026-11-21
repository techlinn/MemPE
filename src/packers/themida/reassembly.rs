use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Range;

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Mnemonic, OpKind,
};

use super::compiler_encodings::DIRECTIONS;
use super::mutated_function::{Body, End};
use crate::unpack::x86::branches::{
    instructions, is_immediate, is_near_immediate, near_jump, retarget,
};
use crate::unpack::x86::opcodes::PUSH_REG;

const ALIGNMENT: u64 = 16; // loop heads padded to this
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
]; // intel's multi-byte nops
const OPERAND_SIZE: u8 = 0x66;
const LONGEST_NOP: usize = 15; // msvc max nop with 66 prefixes

const REX: u8 = 0x40;
const LOW_REGISTERS: u8 = 8; // push 50+r needs no rex

#[derive(Clone, Copy)]
pub(super) struct Style {
    reversed: bool,    // reg-reg direction most of the code uses
    padded_push: bool, // most opening pushes carry a bare rex
}

impl Style {
    pub(super) fn of(
        image: &[u8],
        base: u64,
        bits: u32,
        code: &[Range<usize>],
        function_starts: impl Iterator<Item = usize>,
    ) -> Self {
        let mut forward = 0usize;
        let mut reversed = 0usize;
        let decoded = code
            .iter()
            .flat_map(|range| instructions(image, base, bits, range));
        for insn in decoded.filter(between_registers) {
            forward += usize::from(DIRECTIONS.iter().any(|(rm_r, _)| *rm_r == insn.code()));
            reversed += usize::from(DIRECTIONS.iter().any(|(_, r_rm)| *r_rm == insn.code()));
        }

        let low_push = |byte: &u8| (PUSH_REG..PUSH_REG + LOW_REGISTERS).contains(byte);
        let mut bare = 0usize;
        let mut padded = 0usize;
        for start in function_starts.filter(|_| bits == 64) {
            match image.get(start..).unwrap_or_default() {
                [REX, push, ..] if low_push(push) => padded += 1,
                [push, ..] if low_push(push) => bare += 1,
                _ => {}
            }
        }

        Self {
            reversed: reversed > forward,
            padded_push: padded > bare,
        }
    }

    pub(super) fn apply(self, insn: &mut Instruction) {
        let pair = DIRECTIONS
            .iter()
            .find(|(rm_r, r_rm)| *rm_r == insn.code() || *r_rm == insn.code());
        if let Some((rm_r, r_rm)) = pair.filter(|_| between_registers(insn)) {
            insn.set_code(if self.reversed { *r_rm } else { *rm_r });
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Operand {
    None,
    Register,
    Memory,
    Immediate(Option<i64>), // the small values compilers pick between: 0 and 1 and -1
    Other,
}

// how often the compiler that built this program wrote each instruction form
pub(super) struct Habits(HashMap<(Mnemonic, Operand, Operand), usize>);

impl Habits {
    pub(super) fn of(image: &[u8], base: u64, bits: u32, code: &[Range<usize>]) -> Self {
        let mut forms = HashMap::new();
        let decoded = code
            .iter()
            .flat_map(|range| instructions(image, base, bits, range));
        for insn in decoded.filter(|insn| !insn.is_invalid()) {
            *forms.entry(form(&insn)).or_default() += 1;
        }
        Self(forms)
    }

    pub(super) fn count(&self, insn: &Instruction) -> usize {
        self.0.get(&form(insn)).copied().unwrap_or(0)
    }
}

fn form(insn: &Instruction) -> (Mnemonic, Operand, Operand) {
    let operand = |index: u32| {
        if index >= insn.op_count() {
            return Operand::None;
        }
        match insn.op_kind(index) {
            OpKind::Register => Operand::Register,
            OpKind::Memory => Operand::Memory,
            OpKind::Immediate64 => Operand::Immediate(None),
            kind if is_immediate(kind) => {
                let value = insn.immediate(index) as i64;
                Operand::Immediate((-1..=1).contains(&value).then_some(value))
            }
            _ => Operand::Other,
        }
    };
    (insn.mnemonic(), operand(0), operand(1))
}

fn between_registers(insn: &Instruction) -> bool {
    insn.op_count() == 2
        && insn.op_kind(0) == OpKind::Register
        && insn.op_kind(1) == OpKind::Register
}

pub(super) enum Piece {
    Code(Vec<Instruction>),
    Jump(u64),
    Padding,
}

#[derive(Clone, Copy)]
enum Item {
    Label(u64),
    Insn(Instruction),
    Branch(Instruction, u64),
    Padding,
}

pub(super) struct Laid {
    pub(super) code: Vec<Instruction>,
    pub(super) padding: BTreeSet<u64>, // ips of the nops that only align
}

pub(super) fn lay_out(body: &Body, pieces: &BTreeMap<u64, Piece>, bits: u32) -> Option<Laid> {
    let mut items = Vec::new();
    let mut placed = BTreeSet::new();
    let mut work = vec![body.entry];

    while let Some(start) = work.pop() {
        let mut at = start;
        loop {
            if !placed.insert(at) {
                items.push(Item::Branch(near_jump(bits, 0)?, at));
                break;
            }

            let block = body.blocks.get(&at)?;
            items.push(Item::Label(at));
            match pieces.get(&at)? {
                Piece::Jump(next) => {
                    items.push(Item::Branch(near_jump(bits, 0)?, *next));
                    work.insert(0, *next); // jumped-to blocks go last
                    break;
                }
                Piece::Code(code) => items.extend(code.iter().copied().map(Item::Insn)),
                Piece::Padding => items.push(Item::Padding),
            }

            match &block.end {
                End::Next(next) => at = *next,
                End::Conditional(branch) => {
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
    let needless = |index: usize, item: &Item| match item {
        Item::Branch(insn, target) => {
            insn.mnemonic() == Mnemonic::Jmp && falls_into(index, *target)
        }
        _ => false,
    };

    items
        .iter()
        .enumerate()
        .filter(|(index, item)| !needless(*index, item))
        .map(|(_, item)| *item)
        .collect()
}

fn resolve(items: Vec<Item>, bits: u32) -> Option<Laid> {
    let count = items
        .iter()
        .filter(|item| !matches!(item, Item::Label(_)))
        .count() as u64;
    let first = match bits {
        64 => u64::MAX - count,
        _ => u64::from(u32::MAX) - count, // 32-bit targets wrap
    };

    let mut labels = BTreeMap::new();
    let mut code = Vec::new();
    let mut branches = Vec::new();
    let mut padding = BTreeSet::new();
    for item in items {
        let ip = first + code.len() as u64;
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
            Item::Padding => {
                let mut insn = Instruction::with(Code::Nopd);
                insn.set_ip(ip);
                padding.insert(ip);
                code.push(insn);
            }
        }
    }

    for (index, target) in branches {
        let label = *labels.get(&target)?;
        retarget(code.get_mut(index)?, label);
    }
    Some(Laid { code, padding })
}

pub(super) fn encode(
    code: &[Instruction],
    padding: &BTreeSet<u64>,
    bits: u32,
    at: u64,
) -> Option<Vec<u8>> {
    let mut code = code.to_vec();

    loop {
        let encoded = BlockEncoder::encode(
            bits,
            InstructionBlock::new(&code, at),
            BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
        )
        .ok()?;

        let aligning = code
            .iter()
            .position(|insn| insn.mnemonic() == Mnemonic::Nop && padding.contains(&insn.ip()));
        let Some(index) = aligning else {
            return Some(encoded.code_buffer);
        };

        let offset = u64::from(*encoded.new_instruction_offsets.get(index)?);
        let length = ((ALIGNMENT - (at + offset) % ALIGNMENT) % ALIGNMENT) as usize;
        let ip = code.get(index)?.ip();
        match length {
            0 => {
                let next = code.get(index + 1)?.ip();
                retarget_all(&mut code, ip, next);
                code.remove(index);
            }
            length => {
                let mut filler = Instruction::with_declare_byte(&nop(length)).ok()?;
                filler.set_ip(ip);
                *code.get_mut(index)? = filler;
            }
        }
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

pub(super) fn pad_opening_push(code: &mut [Instruction], style: Style, bits: u32) {
    let Some(first) = code.first_mut() else {
        return;
    };
    let one_byte = bits == 64
        && first.code() == Code::Push_r64
        && first.op0_register().number() < usize::from(LOW_REGISTERS);
    if !(style.padded_push && one_byte) {
        return;
    }

    let opcode = PUSH_REG + first.op0_register().number() as u8;
    if let Ok(mut padded) = Instruction::with_declare_byte(&[REX, opcode]) {
        padded.set_ip(first.ip());
        *first = padded;
    }
}

pub(super) fn retarget_all(code: &mut [Instruction], from: u64, to: u64) {
    for insn in code {
        if is_near_immediate(insn) && insn.near_branch_target() == from {
            retarget(insn, to);
        }
    }
}
