use iced_x86::{Instruction, MemoryOperand, Mnemonic, OpKind};

use super::encodings::{
    Memory, Op, adjust_stack, displacement, displacement_size, exchange, exchange_memory,
    memory_immediate, memory_register, pop, pop_memory, push_immediate, push_memory, push_register,
    register, register_immediate, register_memory, register_register, registers, sign_extend,
    stack_pointer, unary_memory, unary_register, zero_extend_memory, zero_extend_register,
};
use crate::pe::packers::emu::{Probe, Trial};

const STACK_POINTER: usize = 4;
const FLAG_ONLY: [Mnemonic; 3] = [Mnemonic::Cmp, Mnemonic::Test, Mnemonic::Bt]; // their whole effect is the flags a probe ignores
const INVENTED: usize = 2; // the first two themida swaps in and no compiler writes, so even with the flags in use they were inc and not
const EQUIVALENT: [(Mnemonic, i64, Mnemonic); 5] = [
    (Mnemonic::Sub, -1, Mnemonic::Inc),
    (Mnemonic::Xor, -1, Mnemonic::Not),
    (Mnemonic::Add, 1, Mnemonic::Inc),
    (Mnemonic::Sub, 1, Mnemonic::Dec),
    (Mnemonic::Add, -1, Mnemonic::Dec),
]; // where junk follows the flags are dead, so the compiler's shorter instruction is as good
const SMALL_CONSTANTS: [i64; 3] = [0, 1, -1];

const BINARY: [Op; 6] = [Op::Mov, Op::Add, Op::Sub, Op::And, Op::Or, Op::Xor];
const UNARY: [Mnemonic; 4] = [Mnemonic::Inc, Mnemonic::Dec, Mnemonic::Neg, Mnemonic::Not];

pub(super) fn simplify(probe: &Probe<'_>, code: &[Instruction]) -> Option<Vec<Instruction>> {
    if code.len() <= 1 {
        let restored = code
            .iter()
            .map(|insn| canonical(insn, probe.bits, &EQUIVALENT[..INVENTED]).unwrap_or(*insn));
        return Some(restored.collect()); // no junk where the flags are used, though the instruction may still be swapped
    }

    let expected = probe.expected(code)?;
    let stands_in =
        |candidate: &Instruction| probe.matches(&expected, std::slice::from_ref(candidate));
    let offsets = probe.stack_offsets(code)?;
    let unshifted: Vec<Instruction> = code
        .iter()
        .zip(&offsets)
        .map(|(insn, offset)| unshifted(insn, probe.bits, *offset))
        .collect();

    let flag_only = unshifted
        .iter()
        .find(|insn| FLAG_ONLY.contains(&insn.mnemonic()));
    if let Some(compare) = flag_only {
        return stands_in(compare).then(|| vec![*compare]);
    }

    if probe.matches(&expected, &[]) {
        return Some(Vec::new()); // junk alone, where the original was a nop or a jump the layout puts back
    }

    if let Some(kept) = unshifted.iter().find(|insn| stands_in(insn)) {
        let canonical =
            canonical(kept, probe.bits, &EQUIVALENT).filter(|canonical| stands_in(canonical));
        return Some(vec![canonical.unwrap_or(*kept)]);
    }

    let trials = probe.trials(code)?;
    let candidates = Candidates::new(probe.bits, code, &offsets, &trials)?;
    if let Some(found) = candidates
        .all()
        .into_iter()
        .find(|candidate| stands_in(candidate))
    {
        return Some(vec![found]);
    }

    candidates
        .allocation()
        .filter(|candidate| probe.allocates_like(&expected, std::slice::from_ref(candidate)))
        .map(|candidate| vec![candidate])
}

struct Candidates<'a> {
    bits: u32,
    trials: &'a [Trial],
    memories: Vec<Memory>,
    immediates: Vec<i64>,
    stack_delta: i64,
    changed: Vec<usize>,
}

impl<'a> Candidates<'a> {
    fn new(bits: u32, code: &[Instruction], offsets: &[i64], trials: &'a [Trial]) -> Option<Self> {
        let delta = |trial: &Trial| {
            trial.after[STACK_POINTER].wrapping_sub(trial.before[STACK_POINTER]) as i64
        };
        let stack_delta = delta(trials.first()?);
        if trials.iter().any(|trial| delta(trial) != stack_delta) {
            return None; // the stack moves by a different amount each time, so it is no single instruction
        }

        let changed = (0..registers(bits))
            .filter(|reg| *reg != STACK_POINTER)
            .filter(|reg| {
                trials
                    .iter()
                    .any(|trial| trial.before[*reg] != trial.after[*reg])
            })
            .collect();

        let mut memories: Vec<Memory> = Vec::new();
        let mut immediates: Vec<i64> = SMALL_CONSTANTS.to_vec();
        for (insn, offset) in code.iter().zip(offsets) {
            for operand in 0..insn.op_count() {
                match insn.op_kind(operand) {
                    OpKind::Memory => {
                        let memory = memory_of(insn, bits, *offset);
                        let known = memories.iter().any(|seen| {
                            seen.size == memory.size && same_operand(&seen.operand, &memory.operand)
                        });
                        if !known {
                            memories.push(memory);
                        }
                    }
                    kind if is_immediate(kind) => immediates.push(insn.immediate(operand) as i64),
                    _ => {}
                }
            }
        }
        immediates.sort_unstable();
        immediates.dedup();

        Some(Self {
            bits,
            trials,
            memories,
            immediates,
            stack_delta,
            changed,
        })
    }

    fn all(&self) -> Vec<Instruction> {
        let width = (self.bits / 8) as i64;
        let mut found = Vec::new();

        match (self.stack_delta, self.changed.as_slice()) {
            (delta, []) if delta == -width => self.pushes(&mut found),
            (delta, [reg]) if delta == width => found.extend(self.pop_register(*reg)),
            (delta, []) if delta == width => {
                for memory in self
                    .memories
                    .iter()
                    .filter(|memory| memory.size as i64 == width)
                {
                    found.extend(pop_memory(self.bits, memory));
                }
            }
            (0, []) => self.stores(&mut found),
            (delta, []) if delta > 0 => found.extend(adjust_stack(self.bits, delta)),
            (0, [reg]) => {
                self.register_writes(*reg, &mut found);
                for memory in &self.memories {
                    found.extend(exchange_memory(self.bits, *reg, memory));
                }
            }
            (0, [first, second]) => {
                for size in sizes(self.bits) {
                    found.extend(exchange(self.bits, *first, *second, size));
                }
            }
            _ => {}
        }

        found
    }

    fn allocation(&self) -> Option<Instruction> {
        (self.stack_delta < 0 && self.changed.is_empty())
            .then(|| adjust_stack(self.bits, self.stack_delta))
            .flatten() // a frame allocated, its contents left undefined
    }

    fn pushes(&self, found: &mut Vec<Instruction>) {
        let width = (self.bits / 8) as usize;
        let pushed: Vec<u64> = self.trials.iter().map(|trial| trial.top_after).collect();

        for reg in (0..registers(self.bits)).filter(|reg| *reg != STACK_POINTER) {
            let same = self
                .trials
                .iter()
                .zip(&pushed)
                .all(|(trial, value)| mask(trial.before[reg], width) == *value);
            if same {
                found.extend(push_register(self.bits, reg));
            }
        }

        if pushed.windows(2).all(|pair| pair[0] == pair[1]) {
            found.extend(push_immediate(self.bits, pushed[0] as i64));
        }
        for memory in self.memories.iter().filter(|memory| memory.size == width) {
            found.extend(push_memory(self.bits, memory));
        }
    }

    fn pop_register(&self, reg: usize) -> Option<Instruction> {
        let width = (self.bits / 8) as usize;
        self.trials
            .iter()
            .all(|trial| mask(trial.after[reg], width) == trial.top_before)
            .then(|| pop(self.bits, reg))
            .flatten()
    }

    fn stores(&self, found: &mut Vec<Instruction>) {
        for memory in &self.memories {
            for op in BINARY {
                for reg in (0..registers(self.bits)).filter(|reg| *reg != STACK_POINTER) {
                    found.extend(memory_register(self.bits, op, memory, reg));
                }
                for immediate in &self.immediates {
                    found.extend(memory_immediate(op, memory, *immediate));
                }
            }
            for unary in UNARY {
                found.extend(unary_memory(unary, memory));
            }
        }
    }

    fn register_writes(&self, reg: usize, found: &mut Vec<Instruction>) {
        let Some(smallest) = self.written_size(reg) else {
            return;
        };
        for size in sizes(self.bits)
            .into_iter()
            .filter(|size| *size >= smallest)
        {
            self.register_writes_of(reg, size, found); // the probe's edge states rule out the widths that are wrong
        }
    }

    fn register_writes_of(&self, reg: usize, size: usize, found: &mut Vec<Instruction>) {
        let values = |trial: &Trial| (mask(trial.before[reg], size), mask(trial.after[reg], size));

        for unary in UNARY {
            found.extend(unary_register(self.bits, unary, reg, size));
        }

        let constant = |operand: fn(u64, u64) -> u64| {
            self.constant(|trial| {
                let (old, new) = values(trial);
                mask(operand(old, new), size) // modulo the width, as the operation wraps
            })
        };
        let derived = [
            (Op::Mov, constant(|_, new| new)),
            (Op::Add, constant(|old, new| new.wrapping_sub(old))),
            (Op::Sub, constant(|old, new| old.wrapping_sub(new))),
            (Op::Xor, constant(|old, new| old ^ new)),
            (Op::And, Some(self.and_mask(&values))),
            (Op::Or, Some(self.or_mask(&values))),
        ];
        for (op, value) in derived {
            if let Some(value) = value {
                found.extend(register_immediate(
                    self.bits,
                    op,
                    reg,
                    size,
                    sign_extend(value, size),
                ));
            }
        }

        for op in BINARY {
            for other in (0..registers(self.bits)).filter(|other| *other != reg) {
                found.extend(register_register(self.bits, op, reg, other, size));
            }
            for memory in self.memories.iter().filter(|memory| memory.size == size) {
                found.extend(register_memory(self.bits, op, reg, memory));
            }
        }
        for memory in self.memories.iter().filter(|memory| memory.size < size) {
            found.extend(zero_extend_memory(self.bits, reg, size, memory));
        }
        for other in (0..registers(self.bits)).filter(|other| *other != reg) {
            for from in [1, 2].into_iter().filter(|from| *from < size) {
                found.extend(zero_extend_register(self.bits, reg, size, other, from));
            }
        }
    }

    fn written_size(&self, reg: usize) -> Option<usize> {
        let touched = self.trials.iter().fold(0, |bits, trial| {
            bits | (trial.before[reg] ^ trial.after[reg])
        });
        let cleared_high = self.trials.iter().all(|trial| trial.after[reg] >> 32 == 0);

        Some(match touched {
            0 => return None,
            bits if bits <= 0xFF => 1,
            bits if bits <= 0xFFFF => 2,
            _ if self.bits == 32 || cleared_high => 4, // a 32-bit write clears the upper half on x64
            _ => 8,
        })
    }

    fn constant(&self, value: impl Fn(&Trial) -> u64) -> Option<u64> {
        let first = value(self.trials.first()?);
        self.trials
            .iter()
            .all(|trial| value(trial) == first)
            .then_some(first)
    }

    fn and_mask(&self, values: &dyn Fn(&Trial) -> (u64, u64)) -> u64 {
        self.trials.iter().fold(u64::MAX, |kept, trial| {
            let (old, new) = values(trial);
            kept & !(old & !new) // a bit that was set and got cleared is a zero in the mask
        })
    }

    fn or_mask(&self, values: &dyn Fn(&Trial) -> (u64, u64)) -> u64 {
        self.trials.iter().fold(0, |set, trial| {
            let (old, new) = values(trial);
            set | (new & !old) // a bit that was clear and got set is a one in the mask
        })
    }
}

fn canonical(
    insn: &Instruction,
    bits: u32,
    forms: &[(Mnemonic, i64, Mnemonic)],
) -> Option<Instruction> {
    if insn.op_count() != 2 || insn.op0_kind() != OpKind::Register || !is_immediate(insn.op1_kind())
    {
        return None;
    }

    let reg = insn.op0_register();
    let size = reg.size();
    let immediate = sign_extend(insn.immediate(1), size);
    let (.., unary) = forms
        .iter()
        .find(|(mnemonic, value, _)| *mnemonic == insn.mnemonic() && *value == immediate)?;

    let index = (0..16).find(|index| register(*index, size, bits) == Some(reg))?;
    unary_register(bits, *unary, index, size)
}

fn is_immediate(kind: OpKind) -> bool {
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

fn unshifted(insn: &Instruction, bits: u32, stack_offset: i64) -> Instruction {
    let mut original = *insn;
    let reads_stack = (0..insn.op_count()).any(|operand| insn.op_kind(operand) == OpKind::Memory)
        && insn.memory_base() == stack_pointer(bits);
    if reads_stack {
        let displacement =
            displacement(insn, bits).wrapping_add(addressing_offset(insn, bits, stack_offset));
        original.set_memory_displacement64(displacement as u64); // as the original saw the stack, before the junk moved it
        original.set_memory_displ_size(displacement_size(displacement, insn.memory_base(), bits));
    }
    original
}

fn addressing_offset(insn: &Instruction, bits: u32, stack_offset: i64) -> i64 {
    match insn.mnemonic() {
        Mnemonic::Pop => stack_offset + i64::from(bits / 8), // pop works out its destination after it moves the stack
        _ => stack_offset,
    }
}

fn memory_of(insn: &Instruction, bits: u32, stack_offset: i64) -> Memory {
    let base = insn.memory_base();
    let displacement = match base == stack_pointer(bits) {
        true => displacement(insn, bits).wrapping_add(addressing_offset(insn, bits, stack_offset)),
        false => displacement(insn, bits), // a rip-relative one is already the absolute target
    };
    let size = insn.memory_size().size();

    Memory {
        operand: MemoryOperand::new(
            base,
            insn.memory_index(),
            insn.memory_index_scale(),
            displacement,
            displacement_size(displacement, base, bits),
            false,
            insn.segment_prefix(),
        ),
        size,
    }
}

fn same_operand(left: &MemoryOperand, right: &MemoryOperand) -> bool {
    left.base == right.base
        && left.index == right.index
        && left.scale == right.scale
        && left.displacement == right.displacement
        && left.segment_prefix == right.segment_prefix
}

fn sizes(bits: u32) -> Vec<usize> {
    match bits {
        64 => vec![4, 8, 2, 1], // the width a compiler picks first, where another would leave the same result
        _ => vec![4, 2, 1],
    }
}

fn mask(value: u64, size: usize) -> u64 {
    match size {
        8 => value,
        size => value & ((1u64 << (size * 8)) - 1),
    }
}
