use std::cell::OnceCell;
use std::cmp::Reverse;

use iced_x86::{Instruction, MemoryOperand, Mnemonic, OpKind};

use super::compiler_encodings::{
    Memory, Op, adjust_stack, displacement_size, exchange, exchange_memory, memory_immediate,
    memory_register, pop, pop_memory, push_immediate, push_memory, push_register,
    register_immediate, register_memory, register_register, sign_extend, stack_pointer,
    unary_memory, unary_register, zero_extend_memory, zero_extend_register,
};
use super::reassembly::Habits;
use crate::unpack::x86::branches::{is_immediate, signed};
use crate::unpack::x86::{FlagsAfter, Outcomes, Probe, RSP, Trial, gpr_count, mask};

const FLAG_ONLY: [Mnemonic; 3] = [Mnemonic::Cmp, Mnemonic::Test, Mnemonic::Bt];
const SMALL_CONSTANTS: [i64; 3] = [0, 1, -1];

const BINARY: [Op; 8] = [
    Op::Mov,
    Op::Add,
    Op::Sub,
    Op::And,
    Op::Or,
    Op::Xor,
    Op::Adc,
    Op::Sbb,
];
const UNARY: [Mnemonic; 4] = [Mnemonic::Inc, Mnemonic::Dec, Mnemonic::Neg, Mnemonic::Not];

#[derive(Default)]
pub(super) struct Simplified {
    pub(super) code: Vec<Instruction>,
    pub(super) flags_dead: bool, // matched on registers and memory: themida's junk leaves other flags
    pub(super) alternatives: Vec<Instruction>, // the lone instruction's equals, most likely first
    pub(super) flag_free: Vec<Instruction>, // equal but for flags: for where no flag is read before all are set
}

impl Simplified {
    fn kept(code: Vec<Instruction>) -> Self {
        Self {
            code,
            flags_dead: false,
            alternatives: Vec::new(),
            flag_free: Vec::new(),
        }
    }

    fn choosing(equals: Vec<Instruction>) -> Option<Self> {
        let equals = distinct(equals);
        Some(Self {
            code: vec![*equals.first()?],
            flags_dead: false,
            alternatives: equals,
            flag_free: Vec::new(),
        })
    }

    fn with_flags_dead(self) -> Self {
        Self {
            flags_dead: true,
            ..self
        }
    }
}

pub(super) fn simplify(
    probe: &Probe<'_>,
    code: &[Instruction],
    habits: &Habits,
) -> Option<Simplified> {
    if code.len() <= 1 {
        if code.first().is_none_or(|lone| added(probe, lone)) {
            return Some(Simplified::kept(Vec::new()));
        }
        let kept = Simplified::kept(code.to_vec());
        return Some(match Block::new(probe, code) {
            Some(block) => block.in_the_programs_own_form(kept, habits),
            None => kept,
        });
    }

    let block = Block::new(probe, code)?;
    let found = block
        .exact(habits)
        .or_else(|| block.flags_dead(habits)) // a pushed register is read back; flags of a stack adjustment never are
        .or_else(|| block.allocation())?;

    let mut simplified = block.in_the_programs_own_form(found, habits);
    if simplified.code.len() == 1 && !simplified.flags_dead {
        simplified.flag_free = block
            .matching(FlagsAfter::Dead, habits)
            .map(|looser| looser.alternatives)
            .unwrap_or_default(); // themida's flags match one form, the program may have written another
    }
    Some(simplified)
}

struct Block<'a> {
    probe: &'a Probe<'a>,
    code: &'a [Instruction],
    expected: Outcomes,
    offsets: Vec<i64>,
    unshifted: Vec<Instruction>,
    trials: OnceCell<Option<Vec<Trial>>>,
    built: OnceCell<Option<Vec<Instruction>>>,
}

impl<'a> Block<'a> {
    fn new(probe: &'a Probe<'a>, code: &'a [Instruction]) -> Option<Self> {
        let expected = probe.expected(code)?;
        let offsets = probe.stack_offsets(code)?;
        let unshifted = code
            .iter()
            .zip(&offsets)
            .map(|(insn, offset)| unshifted(insn, probe.bits, *offset))
            .collect();

        Some(Self {
            probe,
            code,
            expected,
            offsets,
            unshifted,
            trials: OnceCell::new(),
            built: OnceCell::new(),
        })
    }

    fn exact(&self, habits: &Habits) -> Option<Simplified> {
        let probe = self.probe;
        let stands_in = |candidate: &Instruction| {
            probe.matches(
                &self.expected,
                std::slice::from_ref(candidate),
                FlagsAfter::Live,
            )
        };

        let mut compares = self
            .unshifted
            .iter()
            .copied()
            .filter(|insn| FLAG_ONLY.contains(&insn.mnemonic()))
            .peekable();
        if compares.peek().is_some() {
            let compare = only(compares.filter(stands_in))?; // junk may hold its own compare
            return Some(Simplified::kept(vec![compare]));
        }

        self.matching(FlagsAfter::Live, habits) // equal forms all run the same: which one is the program's is a question of form
    }

    // themida swaps instructions for ones no compiler writes, keeping only the flags the program reads;
    // a form this program never uses gives way to an equal one it does
    fn in_the_programs_own_form(&self, found: Simplified, habits: &Habits) -> Simplified {
        let [only] = found.code[..] else {
            return found;
        };
        if habits.count(&only) > 0 {
            return found;
        }

        let probe = self.probe;
        let equal = |candidate: &Instruction| {
            habits.count(candidate) > 0
                && probe.matches(
                    &self.expected,
                    std::slice::from_ref(candidate),
                    FlagsAfter::Dead,
                )
        };
        let mut used: Vec<Instruction> = self
            .built()
            .unwrap_or_default()
            .iter()
            .copied()
            .filter(equal)
            .collect();
        used.sort_by_key(|candidate| Reverse(habits.count(candidate)));
        match Simplified::choosing(used) {
            Some(used) => Simplified {
                flags_dead: found.flags_dead,
                ..used
            },
            None => found,
        }
    }

    // themida keeps every flag the program reads, so when none of the block's flags match no later
    // instruction reads them and any stand-in equal on registers and memory runs the same
    fn flags_dead(&self, habits: &Habits) -> Option<Simplified> {
        let probe = self.probe;
        let live = |candidate: &Instruction| {
            probe.matches(
                &self.expected,
                std::slice::from_ref(candidate),
                FlagsAfter::Live,
            )
        };
        let any_live = probe.matches(&self.expected, &[], FlagsAfter::Live)
            || self.unshifted.iter().any(live)
            || self.built()?.iter().any(live);
        if any_live {
            return None; // refused for two fitting readings, not for its flags
        }

        let mut tiers = [FlagsAfter::Conditions, FlagsAfter::Dead]
            .into_iter()
            .filter_map(|flags| self.matching(flags, habits));
        let found = tiers.next()?;
        let equals = match (found.code.len(), tiers.next()) {
            (1, Some(looser)) => [found.alternatives, looser.alternatives].concat(), // dead flags: equal on the rest is enough
            _ => return Some(found.with_flags_dead()),
        };
        Simplified::choosing(equals).map(Simplified::with_flags_dead)
    }

    fn matching(&self, flags: FlagsAfter, habits: &Habits) -> Option<Simplified> {
        let probe = self.probe;
        if probe.matches(&self.expected, &[], flags) {
            return Some(Simplified::kept(Vec::new()));
        }

        let stands_in = |candidate: &Instruction| {
            (flags == FlagsAfter::Live || !added(probe, candidate)) // a flags-only stand-in would just copy the junk's flags
                && probe.matches(&self.expected, std::slice::from_ref(candidate), flags)
        };
        let preferred = |mut found: Vec<Instruction>| {
            found.sort_by_key(|insn| {
                (
                    Reverse(habits.count(insn)),
                    encoded_length(insn, probe.bits),
                ) // the form this program's compiler wrote most
            });
            found
        };

        let mut equals = preferred(self.unshifted.iter().copied().filter(stands_in).collect());
        let built = self
            .built()
            .unwrap_or_default()
            .iter()
            .copied()
            .filter(stands_in)
            .collect();
        equals.extend(preferred(built)); // kept by themida first
        Simplified::choosing(equals)
    }

    fn allocation(&self) -> Option<Simplified> {
        let candidate = self.candidates()?.allocation()?;
        let flags = [FlagsAfter::Live, FlagsAfter::Conditions, FlagsAfter::Dead]
            .into_iter()
            .find(|flags| {
                self.probe.matches_outside_new_frame(
                    &self.expected,
                    std::slice::from_ref(&candidate),
                    *flags,
                )
            })?; // junk in the new frame often leaves junk flags too
        let allocated = Simplified::kept(vec![candidate]);
        Some(match flags {
            FlagsAfter::Live => allocated,
            _ => allocated.with_flags_dead(),
        })
    }

    fn built(&self) -> Option<&[Instruction]> {
        self.built
            .get_or_init(|| self.candidates().map(|candidates| candidates.all()))
            .as_deref()
    }

    fn candidates(&self) -> Option<Candidates<'_>> {
        Candidates::new(self.probe.bits, self.code, &self.offsets, self.trials()?)
    }

    fn trials(&self) -> Option<&[Trial]> {
        self.trials
            .get_or_init(|| self.probe.trials(self.code))
            .as_deref()
    }
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
        let delta = |trial: &Trial| trial.after[RSP].wrapping_sub(trial.before[RSP]) as i64;
        let stack_delta = delta(trials.first()?);
        if trials.iter().any(|trial| delta(trial) != stack_delta) {
            return None; // varying stack delta, not one insn
        }

        let changed = (0..gpr_count(bits))
            .filter(|reg| *reg != RSP)
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
            .flatten()
    }

    fn pushes(&self, found: &mut Vec<Instruction>) {
        let width = (self.bits / 8) as usize;
        let pushed: Vec<u64> = self.trials.iter().map(|trial| trial.top_after).collect();

        for reg in (0..gpr_count(self.bits)).filter(|reg| *reg != RSP) {
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
                for reg in (0..gpr_count(self.bits)).filter(|reg| *reg != RSP) {
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
            self.register_writes_of(reg, size, found);
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
                mask(operand(old, new), size)
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
            for other in (0..gpr_count(self.bits)).filter(|other| *other != reg) {
                found.extend(register_register(self.bits, op, reg, other, size));
            }
            for memory in self.memories.iter().filter(|memory| memory.size == size) {
                found.extend(register_memory(self.bits, op, reg, memory));
            }
        }
        for memory in self.memories.iter().filter(|memory| memory.size < size) {
            found.extend(zero_extend_memory(self.bits, reg, size, memory));
        }
        for other in (0..gpr_count(self.bits)).filter(|other| *other != reg) {
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
            _ if self.bits == 32 || cleared_high => 4, // 32-bit write clears the upper half
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
            kept & !(old & !new)
        })
    }

    fn or_mask(&self, values: &dyn Fn(&Trial) -> (u64, u64)) -> u64 {
        self.trials.iter().fold(0, |set, trial| {
            let (old, new) = values(trial);
            set | (new & !old)
        })
    }
}

// compilers set flags alone only with a compare; any other instruction they write for its result
fn added(probe: &Probe<'_>, lone: &Instruction) -> bool {
    let code = std::slice::from_ref(lone);
    !FLAG_ONLY.contains(&lone.mnemonic())
        && probe
            .expected(code)
            .is_some_and(|expected| probe.matches(&expected, &[], FlagsAfter::Dead))
}

pub(super) fn encoded_length(insn: &Instruction, bits: u32) -> usize {
    iced_x86::Encoder::new(bits)
        .encode(insn, insn.ip())
        .unwrap_or(usize::MAX)
}

pub(super) fn distinct(found: Vec<Instruction>) -> Vec<Instruction> {
    let mut unique = Vec::with_capacity(found.len());
    for insn in found {
        if !unique.contains(&insn) {
            unique.push(insn);
        }
    }
    unique
}

fn only(mut found: impl Iterator<Item = Instruction>) -> Option<Instruction> {
    let first = found.next()?;
    found.all(|other| other == first).then_some(first) // two encodings fit: neither is proven
}

fn unshifted(insn: &Instruction, bits: u32, stack_offset: i64) -> Instruction {
    let mut original = *insn;
    let reads_stack = (0..insn.op_count()).any(|operand| insn.op_kind(operand) == OpKind::Memory)
        && insn.memory_base() == stack_pointer(bits);
    if reads_stack {
        let displacement = signed(insn.memory_displacement64(), bits)
            .wrapping_add(addressing_offset(insn, bits, stack_offset));
        original.set_memory_displacement64(displacement as u64); // as seen before the junk moved the stack
        original.set_memory_displ_size(displacement_size(displacement, insn.memory_base(), bits));
    }
    original
}

fn addressing_offset(insn: &Instruction, bits: u32, stack_offset: i64) -> i64 {
    match insn.mnemonic() {
        Mnemonic::Pop => stack_offset + i64::from(bits / 8), // pop addresses after moving the stack
        _ => stack_offset,
    }
}

fn memory_of(insn: &Instruction, bits: u32, stack_offset: i64) -> Memory {
    let base = insn.memory_base();
    let shift = match base == stack_pointer(bits) {
        true => addressing_offset(insn, bits, stack_offset),
        false => 0, // rip-relative is already absolute
    };
    let displacement = signed(insn.memory_displacement64(), bits).wrapping_add(shift);
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
        64 => vec![4, 8, 2, 1],
        _ => vec![4, 2, 1],
    }
}
