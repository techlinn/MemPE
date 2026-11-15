use std::collections::BTreeMap;

use iced_x86::Instruction;

use super::{Cpu, STACK_SIZE};

const RANDOM_STATES: u64 = 16;
const EDGES: [u64; 3] = [0xFF, 0xFFFF, 0xFFFF_FFFF]; // where a carry or borrow tells an operation's width
const EDGE_STATES: u64 = 2 * EDGES.len() as u64;
const SMALL_STATES: u64 = 4; // small values and no high dividend, where a division does not fault
const STATES: u64 = RANDOM_STATES + EDGE_STATES + SMALL_STATES;
const MIN_CLEAN_STATES: usize = 8;
const SMALL: u64 = 0xFFFF;
const DIVIDEND_HIGH: usize = 2;
const LIVE_ABOVE: u64 = 0x100; // stack the code can still see above where it started: its caller's slots
const BELOW: u64 = 0x1000;

#[derive(Clone, Copy)]
pub(in crate::pe::packers) struct Probe<'a> {
    pub(in crate::pe::packers) image: &'a [u8], // program data the code reads stays what the program holds
    pub(in crate::pe::packers) base: u64,
    pub(in crate::pe::packers) bits: u32,
}

#[derive(PartialEq, Eq)]
struct Outcome {
    regs: [u64; 16],
    xmm: [u128; 16],
    live_stack: Vec<u8>, // from where the stack pointer ends up to above where it started, the rest is dead
    allocated: usize, // how much of that is new below where it started, whatever the code left in it
    writes: BTreeMap<u64, u8>,
}

impl Outcome {
    fn same_but_allocated(&self, other: &Self) -> bool {
        self.regs == other.regs
            && self.xmm == other.xmm
            && self.writes == other.writes
            && self.live_stack.get(self.allocated..) == other.live_stack.get(other.allocated..)
    }
}

pub(in crate::pe::packers) struct Expected(Vec<Option<Outcome>>);

pub(in crate::pe::packers) struct Trial {
    pub(in crate::pe::packers) before: [u64; 16],
    pub(in crate::pe::packers) after: [u64; 16],
    pub(in crate::pe::packers) top_before: u64,
    pub(in crate::pe::packers) top_after: u64,
}

impl Probe<'_> {
    pub(in crate::pe::packers) fn expected(&self, code: &[Instruction]) -> Option<Expected> {
        let outcomes: Vec<Option<Outcome>> =
            (0..STATES).map(|state| self.outcome(code, state)).collect();
        let clean = outcomes.iter().filter(|outcome| outcome.is_some()).count();
        (clean >= MIN_CLEAN_STATES).then_some(Expected(outcomes))
    }

    pub(in crate::pe::packers) fn matches(
        &self,
        expected: &Expected,
        other: &[Instruction],
    ) -> bool {
        (0..STATES)
            .zip(&expected.0)
            .all(|(state, outcome)| self.outcome(other, state) == *outcome) // a stand-in faults where the block does, and stops at the first state that differs
    }

    pub(in crate::pe::packers) fn allocates_like(
        &self,
        expected: &Expected,
        other: &[Instruction],
    ) -> bool {
        (0..STATES).zip(&expected.0).all(|(state, outcome)| {
            match (self.outcome(other, state), outcome) {
                (Some(ran), Some(outcome)) => ran.same_but_allocated(outcome), // an allocated frame holds whatever junk the mutated copy left
                (ran, outcome) => ran.is_none() && outcome.is_none(),
            }
        })
    }

    pub(in crate::pe::packers) fn trials(&self, code: &[Instruction]) -> Option<Vec<Trial>> {
        let width = (self.bits / 8) as usize;

        let trials: Vec<Trial> = (0..STATES)
            .filter_map(|state| {
                let mut cpu = self.prepared(state);
                let before = cpu.gpr;
                let top_before = cpu.mem(cpu.gpr[4], width)?;
                cpu.run_straight(code)?;

                Some(Trial {
                    before,
                    after: cpu.gpr,
                    top_before,
                    top_after: cpu.mem(cpu.gpr[4], width)?,
                })
            })
            .collect();
        (trials.len() >= MIN_CLEAN_STATES).then_some(trials)
    }

    pub(in crate::pe::packers) fn stack_offsets(&self, code: &[Instruction]) -> Option<Vec<i64>> {
        (0..STATES).find_map(|state| {
            let mut cpu = self.prepared(state);
            let start = cpu.gpr[4];
            let mut offsets = Vec::with_capacity(code.len());

            for insn in code {
                offsets.push(cpu.gpr[4].wrapping_sub(start) as i64);
                cpu.step(insn)?;
            }
            Some(offsets) // junk moves the stack the same way whatever the registers hold
        })
    }

    fn outcome(&self, code: &[Instruction], state: u64) -> Option<Outcome> {
        let mut cpu = self.prepared(state);
        let start = cpu.gpr[4];
        cpu.run_straight(code)?;
        if cpu.gpr[4].abs_diff(start) > BELOW {
            return None; // the stack pointer loaded from somewhere, which no single instruction of a program does
        }

        let live_stack = (cpu.gpr[4]..start + LIVE_ABOVE) // a push leaves its slot live, a pop leaves its slot dead
            .map(|at| cpu.read_byte(at))
            .collect::<Option<Vec<u8>>>()?;
        let stack = cpu.stack_base..cpu.stack_base + STACK_SIZE;
        let writes = cpu
            .overlay
            .unwrap_or_default()
            .into_iter()
            .filter(|(at, _)| !stack.contains(at))
            .collect();

        Some(Outcome {
            regs: cpu.gpr,
            xmm: cpu.xmm,
            live_stack,
            allocated: usize::try_from(start.saturating_sub(cpu.gpr[4])).ok()?,
            writes,
        })
    }

    fn prepared(&self, state: u64) -> Cpu<'_> {
        let mut cpu = Cpu::new(self.image, self.base, self.bits);
        let mut random = Random::new(state);
        cpu.overlay = Some(BTreeMap::new());
        cpu.unmapped = Some(random.next()); // every address reads as something, so any operand the code forms is valid

        random.fill(&mut cpu.stack);
        cpu.gpr[4] = cpu.stack_base + STACK_SIZE - LIVE_ABOVE - BELOW.min(STACK_SIZE / 2);
        let kind = Kind::of(state);
        for reg in (0..cpu.gpr_count()).filter(|reg| *reg != 4) {
            let value = match kind {
                Kind::Random => random.next(),
                Kind::Edge(low, ones) => (random.next() & !low) | if ones { low } else { 0 },
                Kind::Small if reg == DIVIDEND_HIGH => 0,
                Kind::Small => (random.next() & SMALL) | 1,
            };
            cpu.gpr[reg] = match self.bits {
                64 => value,
                _ => value & u64::from(u32::MAX),
            };
        }
        for xmm in &mut cpu.xmm {
            *xmm = u128::from(random.next()) | (u128::from(random.next()) << 64);
        }

        cpu
    }
}

enum Kind {
    Random,
    Edge(u64, bool),
    Small,
}

impl Kind {
    fn of(state: u64) -> Self {
        match state.checked_sub(RANDOM_STATES) {
            None => Self::Random,
            Some(index) if index < EDGE_STATES => {
                Self::Edge(EDGES[(index / 2) as usize], index % 2 == 1)
            }
            Some(_) => Self::Small,
        }
    }
}

impl Cpu<'_> {
    fn run_straight(&mut self, code: &[Instruction]) -> Option<()> {
        for insn in code {
            self.step(insn)?;
        }
        Some(())
    }
}

struct Random(u64);

impl Random {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13; // xorshift64: states only need to differ, not to be unpredictable
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
