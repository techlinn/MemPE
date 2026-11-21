use std::collections::BTreeMap;
use std::sync::OnceLock;

use iced_x86::{FlowControl, Instruction};

use super::emulator::{
    CARRY_FLAG, Cpu, OVERFLOW_FLAG, RDX, RSP, SIGN_FLAG, STATUS_FLAGS, ZERO_FLAG,
};
use super::written_memory::Overlay;
use super::x87::X87;

const RANDOM_STATES: u64 = 16;
const EDGES: [u64; 3] = [0xFF, 0xFFFF, 0xFFFF_FFFF]; // width boundaries
const EDGE_STATES: u64 = 2 * EDGES.len() as u64;
const SMALL_STATES: u64 = 4; // division safe
const STATES: u64 = RANDOM_STATES + EDGE_STATES + SMALL_STATES;
const MIN_CLEAN_STATES: usize = 8;
const SMALL_VALUE_MASK: u64 = 0xFFFF;
const LIVE_ABOVE: u64 = 0x1100; // caller frame, compared whole
const BELOW: u64 = 0x1000;
const SP_SPREAD: u64 = 16;
const SP_STEP: u64 = 0x100; // keeps the alignment and esp, -16 reads
const MAX_CHANGED_BY_ONE: usize = 4;
const PROBE_STACK_SIZE: u64 = LIVE_ABOVE + SP_SPREAD * SP_STEP + 2 * BELOW;

#[derive(Clone, Copy)]
pub(crate) struct Probe<'a> {
    pub(crate) image: &'a [u8],
    pub(crate) base: u64,
    pub(crate) bits: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlagsAfter {
    Live,
    Conditions, // carry, zero, sign and overflow: what jumps and adc read
    Dead,
}

const CONDITION_FLAGS: u64 = CARRY_FLAG | ZERO_FLAG | SIGN_FLAG | OVERFLOW_FLAG;

struct Outcome {
    regs: [u64; 16],
    xmm: [u128; 16],
    x87: X87,
    flags: u64,
    live_stack: Vec<u8>, // sp..stack end
    allocated: usize,    // bytes below start
    writes: BTreeMap<u64, u8>,
}

impl Outcome {
    fn same(&self, other: &Self, flags: FlagsAfter) -> bool {
        self.same_outside_new_frame(other, flags)
            && self.allocated == other.allocated
            && self.live_stack == other.live_stack
    }

    fn same_outside_new_frame(&self, other: &Self, flags: FlagsAfter) -> bool {
        self.regs == other.regs
            && self.xmm == other.xmm
            && self.x87 == other.x87
            && self.writes == other.writes
            && match flags {
                FlagsAfter::Live => self.flags == other.flags,
                FlagsAfter::Conditions => {
                    self.flags & CONDITION_FLAGS == other.flags & CONDITION_FLAGS
                }
                FlagsAfter::Dead => true,
            }
            && self.live_stack.get(self.allocated..) == other.live_stack.get(other.allocated..)
    }
}

pub(crate) struct Outcomes(Vec<Option<Outcome>>);

pub(crate) struct Trial {
    pub(crate) before: [u64; 16],
    pub(crate) after: [u64; 16],
    pub(crate) top_before: u64,
    pub(crate) top_after: u64,
}

impl Probe<'_> {
    pub(crate) fn expected(&self, code: &[Instruction]) -> Option<Outcomes> {
        let outcomes: Vec<Option<Outcome>> =
            (0..STATES).map(|state| self.outcome(code, state)).collect();
        let clean = outcomes.iter().filter(|outcome| outcome.is_some()).count();
        (clean >= MIN_CLEAN_STATES).then_some(Outcomes(outcomes))
    }

    pub(crate) fn matches(
        &self,
        expected: &Outcomes,
        other: &[Instruction],
        flags: FlagsAfter,
    ) -> bool {
        self.agrees(expected, other, |ran, outcome| ran.same(outcome, flags))
    }

    pub(crate) fn matches_outside_new_frame(
        &self,
        expected: &Outcomes,
        other: &[Instruction],
        flags: FlagsAfter,
    ) -> bool {
        self.agrees(expected, other, |ran, outcome| {
            ran.same_outside_new_frame(outcome, flags) // frame holds junk
        })
    }

    fn agrees(
        &self,
        expected: &Outcomes,
        other: &[Instruction],
        same: impl Fn(&Outcome, &Outcome) -> bool,
    ) -> bool {
        (0..STATES).zip(&expected.0).all(|(state, outcome)| {
            match (self.outcome(other, state), outcome) {
                (Some(ran), Some(outcome)) => same(&ran, outcome),
                (ran, outcome) => ran.is_none() && outcome.is_none(),
            }
        })
    }

    pub(crate) fn trials(&self, code: &[Instruction]) -> Option<Vec<Trial>> {
        let width = (self.bits / 8) as usize;

        let trials: Vec<Trial> = (0..STATES)
            .filter_map(|state| {
                let mut cpu = self.cpu_in_state(state)?;
                let before = cpu.gpr;
                let top_before = cpu.mem(cpu.gpr[RSP], width)?;
                cpu.run_block(code)?;

                Some(Trial {
                    before,
                    after: cpu.gpr,
                    top_before,
                    top_after: cpu.mem(cpu.gpr[RSP], width)?,
                })
            })
            .collect();
        (trials.len() >= MIN_CLEAN_STATES).then_some(trials)
    }

    // after each instruction: whether every state that got there has no more registers changed
    // than one instruction can change (cpuid's four)
    pub(crate) fn settled(&self, code: &[Instruction]) -> Vec<bool> {
        let mut settled = vec![true; code.len()];
        for state in 0..STATES {
            let Some(mut cpu) = self.cpu_in_state(state) else {
                continue;
            };
            let before = cpu.gpr;

            for (after, insn) in settled.iter_mut().zip(code) {
                if cpu.step_in_block(insn).is_none() {
                    break; // what follows is not known from this state
                }
                let changed = (0..cpu.gpr_count())
                    .filter(|reg| *reg != RSP && cpu.gpr[*reg] != before[*reg])
                    .count();
                if changed > MAX_CHANGED_BY_ONE {
                    *after = false;
                }
            }
        }
        settled
    }

    pub(crate) fn stack_offsets(&self, code: &[Instruction]) -> Option<Vec<i64>> {
        let runs = (0..STATES).filter_map(|state| {
            let mut cpu = self.cpu_in_state(state)?;
            let start = cpu.gpr[RSP];
            let mut offsets = Vec::with_capacity(code.len());

            for insn in code {
                offsets.push(cpu.gpr[RSP].wrapping_sub(start) as i64);
                cpu.step_in_block(insn)?;
            }
            Some(offsets)
        });
        let mut clean: Vec<Vec<i64>> = runs.collect();
        if clean.len() < MIN_CLEAN_STATES {
            return None;
        }

        let first = clean.pop()?;
        clean
            .iter()
            .all(|offsets| *offsets == first)
            .then_some(first) // and esp, -16 moves it by state
    }

    fn outcome(&self, code: &[Instruction], state: u64) -> Option<Outcome> {
        let mut cpu = self.cpu_in_state(state)?;
        let start = cpu.gpr[RSP];
        cpu.run_block(code)?;
        if cpu.gpr[RSP].abs_diff(start) > BELOW {
            return None; // sp loaded
        }

        let live_from = usize::try_from(cpu.gpr[RSP].checked_sub(cpu.stack_base)?).ok()?;
        let live_stack = cpu.stack.get(live_from..)?.to_vec(); // pushed live, popped dead
        let flags = cpu.eflags();
        let stack = cpu.stack_base..cpu.stack_base + PROBE_STACK_SIZE;
        let writes = cpu
            .overlay
            .unwrap_or_default()
            .into_writes()
            .filter(|(at, _)| !stack.contains(at))
            .collect();

        Some(Outcome {
            regs: cpu.gpr,
            xmm: cpu.xmm,
            x87: cpu.x87,
            flags,
            live_stack,
            allocated: usize::try_from(start.saturating_sub(cpu.gpr[RSP])).ok()?,
            writes,
        })
    }

    fn cpu_in_state(&self, state: u64) -> Option<Cpu<'_>> {
        let mut cpu = Cpu::with_stack(self.image, self.base, self.bits, PROBE_STACK_SIZE)?;
        let (stack, mut random) = filled_stack(state)?;
        cpu.overlay = Some(Overlay::default());
        cpu.unmapped = Some(stack.unmapped);

        cpu.stack.copy_from_slice(&stack.bytes);
        cpu.set_eflags(random.next() & STATUS_FLAGS)?; // carry-in tells adc from add; abi keeps df clear
        cpu.gpr[RSP] =
            cpu.stack_base + PROBE_STACK_SIZE - LIVE_ABOVE - (state % SP_SPREAD) * SP_STEP; // a constant is no stack pointer
        let kind = Kind::of(state);
        for reg in (0..cpu.gpr_count()).filter(|reg| *reg != RSP) {
            let value = match kind {
                Kind::Xorshift => random.next(),
                Kind::Edge(low, ones) => (random.next() & !low) | if ones { low } else { 0 },
                Kind::Small if reg == RDX => 0, // the dividend's high half
                Kind::Small => (random.next() & SMALL_VALUE_MASK) | 1,
            };
            cpu.gpr[reg] = match self.bits {
                64 => value,
                _ => value & u64::from(u32::MAX),
            };
        }
        for xmm in &mut cpu.xmm {
            *xmm = u128::from(random.next()) | (u128::from(random.next()) << 64);
        }

        Some(cpu)
    }
}

enum Kind {
    Xorshift,
    Edge(u64, bool),
    Small,
}

impl Kind {
    fn of(state: u64) -> Self {
        match state.checked_sub(RANDOM_STATES) {
            None => Self::Xorshift,
            Some(index) if index < EDGE_STATES => {
                Self::Edge(EDGES[(index / 2) as usize], index % 2 == 1)
            }
            Some(_) => Self::Small,
        }
    }
}

impl Cpu<'_> {
    fn run_block(&mut self, code: &[Instruction]) -> Option<()> {
        for insn in code {
            self.step_in_block(insn)?;
        }
        Some(())
    }

    fn step_in_block(&mut self, insn: &Instruction) -> Option<()> {
        match insn.flow_control() {
            FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => self.step(insn), // a call counts as its push
            _ => None,
        }
    }
}

struct FilledStack {
    unmapped: u64,
    bytes: Vec<u8>,
    random: Xorshift, // where the sequence goes on from
}

fn filled_stack(state: u64) -> Option<(&'static FilledStack, Xorshift)> {
    static STACKS: OnceLock<Vec<FilledStack>> = OnceLock::new();
    let stacks = STACKS.get_or_init(|| {
        (0..STATES)
            .map(|state| {
                let mut random = Xorshift::new(state);
                let unmapped = random.next();
                let mut bytes = vec![0; PROBE_STACK_SIZE as usize];
                random.fill(&mut bytes);
                FilledStack {
                    unmapped,
                    bytes,
                    random,
                }
            })
            .collect()
    }); // the same for every probe: filled once
    let stack = stacks.get(usize::try_from(state).ok()?)?;
    Some((stack, Xorshift(stack.random.0)))
}

struct Xorshift(u64);

impl Xorshift {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13; // xorshift64
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let value = self.next().to_le_bytes();
            chunk.copy_from_slice(&value[..chunk.len()]);
        }
    }
}
