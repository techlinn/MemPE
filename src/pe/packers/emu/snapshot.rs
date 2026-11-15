use std::ops::Range;

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

use super::{Cpu, EXEC_STACK_SIZE, STACK_BASE_32, STACK_BASE_64, WINDOW, mask};
use crate::pe::space::ProcessMemory;

const WRAPPER_BUDGET: usize = 1_000_000; // newer wrappers walk a module's whole export table before they jump
const TRAMPOLINE_BUDGET: usize = 200_000;
const VM_BUDGET: usize = 20_000_000;
const MAX_STUB_DATA: usize = 4_096;
const FRAME_POINTER: usize = 5;
const FRAME_SPACE: u64 = 0x1000;
const MAX_API_CALLS: usize = 16;
const MAX_CALLEE_STEPS: usize = 4_096;
const API_RESULT: u64 = 1;
const STACK_BASES_32: [u64; 5] = [
    STACK_BASE_32,
    0x5000_0000,
    0x3000_0000,
    0x2000_0000,
    0x0800_0000,
];
const STACK_BASES_64: [u64; 3] = [STACK_BASE_64, 0x7FE0_0000_0000, 0x1000_0000_0000];

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::pe::packers) enum Destination {
    Api(u64),
    VirtualMachine,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::pe::packers) enum Handover {
    Pushed,
    Register(u8),
}

#[derive(PartialEq, Eq)]
pub(in crate::pe::packers) struct StubValue {
    pub(in crate::pe::packers) handover: Handover,
    pub(in crate::pe::packers) data: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::pe::packers) struct Landing {
    pub(in crate::pe::packers) address: u64,
    pub(in crate::pe::packers) balanced: bool, // the stack is back where the run began, so it was jumped to and not called
}

#[derive(Clone, Copy)]
pub(in crate::pe::packers) struct Snapshot<'a> {
    pub(in crate::pe::packers) image: &'a [u8],
    pub(in crate::pe::packers) base: u64,
    pub(in crate::pe::packers) bits: u32,
    pub(in crate::pe::packers) memory: &'a ProcessMemory<'a>,
}

impl Snapshot<'_> {
    pub(in crate::pe::packers) fn destination(
        &self,
        start: u64,
        packer: &Range<u64>,
    ) -> Option<Destination> {
        self.agreed(|cpu, seed| cpu.destination(start, packer, seed))
    }

    pub(in crate::pe::packers) fn stub_value(&self, site: u64, length: u64) -> Option<StubValue> {
        let back = site.checked_add(length)?;
        self.agreed(|cpu, seed| cpu.stub_value(site, back, seed))
    }

    pub(in crate::pe::packers) fn native_landings(
        &self,
        start: u64,
        native: &[Range<u64>],
        enough: &dyn Fn(&[Landing]) -> bool,
    ) -> Option<Vec<Landing>> {
        self.agreed(|cpu, seed| cpu.landings(start, native, enough, seed))
    }

    pub(in crate::pe::packers) fn trampoline_target(
        &self,
        start: u64,
        packer: &Range<u64>,
    ) -> Option<u64> {
        self.agreed(|cpu, seed| cpu.trampoline_target(start, packer, seed))
    }

    fn agreed<T: PartialEq>(&self, run: impl Fn(&mut Cpu<'_>, u64) -> Option<T>) -> Option<T> {
        let stack = self.free_stack()?;
        let seeded = |seed| {
            let mut cpu = Cpu::new_exec_at(self.image, self.base, self.bits, stack);
            cpu.outside = Some(self.memory);
            run(&mut cpu, seed)
        };

        let first = seeded(0)?;
        (seeded(1)? == first).then_some(first) // what packer code does to the program does not depend on what the registers held
    }

    fn free_stack(&self) -> Option<u64> {
        let candidates: &[u64] = match self.bits {
            64 => &STACK_BASES_64,
            _ => &STACK_BASES_32,
        };
        let image_end = self.base.saturating_add(self.image.len() as u64);

        candidates.iter().copied().find(|base| {
            let end = base + EXEC_STACK_SIZE;
            let clear_of_image = end <= self.base || image_end <= *base;
            clear_of_image && !self.memory.overlaps(&(*base as usize..end as usize)) // the stack would hide a module loaded there
        })
    }
}

impl Cpu<'_> {
    fn destination(&mut self, start: u64, packer: &Range<u64>, seed: u64) -> Option<Destination> {
        let seeds = self.seed(seed);
        let frame = self.gpr[4];
        let mut decoys = 0;
        self.rip = start;

        for _ in 0..WRAPPER_BUDGET {
            if !self.in_image(self.rip) {
                if self.gpr[4] == frame {
                    let transparent = !self.changed(&seeds).any(|reg| !self.scratch(reg));
                    return transparent.then_some(Destination::Api(self.rip));
                }

                decoys += 1;
                if decoys > MAX_API_CALLS {
                    return None;
                }
                self.return_from_api(frame)?; // an api reached below the entry stack is called to mislead, not imported
                continue;
            }

            let insn = self.fetch()?;
            let spinlock = insn.has_lock_prefix() && insn.mnemonic() == Mnemonic::Cmpxchg;
            if spinlock && packer.contains(&insn.ip()) {
                return Some(Destination::VirtualMachine); // the vm takes its spinlock on the way in, where a runtime's startup takes locks of its own
            }
            self.step(&insn)?;
        }

        None
    }

    fn stub_value(&mut self, site: u64, back: u64, seed: u64) -> Option<StubValue> {
        let width = u64::from(self.bits / 8);
        let seeds = self.seed(seed);
        let frame = self.gpr[4];
        self.rip = site;

        for _ in 0..VM_BUDGET {
            if self.rip == back {
                let changed: Vec<usize> = self.changed(&seeds).collect();
                let (value, handover) = match changed[..] {
                    [] if self.gpr[4] == frame.checked_sub(width)? => {
                        (self.mem(self.gpr[4], width as usize)?, Handover::Pushed)
                    }
                    [only] if self.gpr[4] == frame => (
                        mask(self.gpr[only], width as usize),
                        Handover::Register(u8::try_from(only).ok()?),
                    ),
                    _ => return None,
                };

                let data = (value..)
                    .take(MAX_STUB_DATA)
                    .map_while(|at| self.read_byte(at))
                    .collect();
                return Some(StubValue { handover, data });
            }
            if !self.in_image(self.rip) {
                return None;
            }

            let insn = self.fetch()?;
            self.step(&insn)?;
        }

        None
    }

    fn landings(
        &mut self,
        start: u64,
        native: &[Range<u64>],
        enough: &dyn Fn(&[Landing]) -> bool,
        seed: u64,
    ) -> Option<Vec<Landing>> {
        self.seed(seed);
        let frame = self.gpr[4];
        self.gpr[FRAME_POINTER] = frame.checked_add(FRAME_SPACE)?; // code started mid function reads its locals through the frame pointer
        let mut found = Vec::new();
        let mut inside = true;
        let mut calls = 0;
        self.rip = start;

        for _ in 0..VM_BUDGET {
            let here = native.iter().any(|range| range.contains(&self.rip));
            if here && !inside {
                found.push(Landing {
                    address: self.rip,
                    balanced: self.gpr[4] == frame,
                });
                if enough(&found) {
                    return Some(found);
                }
            }
            inside = here;

            if !self.in_image(self.rip) {
                calls += 1;
                if calls > MAX_API_CALLS {
                    return None;
                }
                self.return_from_api(frame)?;
                continue;
            }

            let insn = self.fetch()?;
            self.step(&insn)?;
        }

        None
    }

    fn trampoline_target(&mut self, start: u64, packer: &Range<u64>, seed: u64) -> Option<u64> {
        let seeds = self.seed(seed);
        let frame = self.gpr[4];
        self.rip = start;

        for step in 0..TRAMPOLINE_BUDGET {
            if step > 0 && !packer.contains(&self.rip) {
                return None; // back in the program before any hand-over: a virtual machine running the code
            }

            let insn = self.fetch()?;
            self.step(&insn)?;

            let handed_over = insn.mnemonic() == Mnemonic::Ret
                && self.gpr[4] == frame
                && self.changed(&seeds).next().is_none()
                && packer.contains(&self.rip);
            if handed_over {
                return Some(self.rip); // an obfuscated push and ret, everything left as the program had it
            }
        }

        None
    }

    fn return_from_api(&mut self, frame: u64) -> Option<()> {
        let width = u64::from(self.bits / 8);
        let sp = self.gpr[4];
        let back = self.mem(sp, width as usize)?;
        if sp >= frame || !self.in_image(back) {
            return None;
        }

        let cleanup = match self.bits {
            64 => 0,
            _ => self.callee_cleanup(self.rip)?,
        };

        self.gpr[4] = sp.checked_add(width)?.checked_add(cleanup)?;
        self.gpr[0] = API_RESULT;
        self.rip = back;
        Some(())
    }

    fn callee_cleanup(&self, entry: u64) -> Option<u64> {
        let mut at = entry;

        for _ in 0..MAX_CALLEE_STEPS {
            let insn = self.decode_at(at)?;
            at = match insn.mnemonic() {
                Mnemonic::Ret => {
                    return Some(match insn.op_count() {
                        0 => 0,
                        _ => u64::from(insn.immediate16()),
                    });
                }
                Mnemonic::Jmp => self.jump_target(&insn)?,
                _ => insn.next_ip(),
            };
        }

        None
    }

    fn jump_target(&self, insn: &Instruction) -> Option<u64> {
        match insn.op0_kind() {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Some(insn.near_branch_target())
            }
            OpKind::Memory if insn.memory_base() == Register::None => {
                self.mem(insn.memory_displacement64(), (self.bits / 8) as usize) // a thunk through the api's own import table
            }
            _ => None,
        }
    }

    fn decode_at(&self, at: u64) -> Option<Instruction> {
        let mut window = [0u8; WINDOW];
        let mut length = 0;
        for (slot, addr) in window.iter_mut().zip(at..) {
            let Some(byte) = self.read_byte(addr) else {
                break;
            };
            *slot = byte;
            length += 1;
        }

        let mut decoder =
            Decoder::with_ip(self.bits, window.get(..length)?, at, DecoderOptions::NONE);
        let insn = decoder.decode();
        (!insn.is_invalid()).then_some(insn)
    }
}
