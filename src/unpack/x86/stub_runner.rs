use std::collections::HashSet;
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, Mnemonic};

use super::branches::{fixed_address, is_near_immediate};
use super::emulator::{
    Cpu, Gpr, R8, R9, R10, R11, RAX, RBP, RCX, RDX, RSP, SEEDS, X64_ARGUMENTS, agreed, exec_bases,
    frame_mark, mask, overlaps,
};
use super::step_budget;
use crate::pe::process_memory::ProcessMemory;

const WRAPPER_BUDGET: usize = 1_000_000; // newer wrappers walk a module's whole export table before they jump
const TRAMPOLINE_BUDGET: usize = 200_000;
const VM_BUDGET: usize = 20_000_000;
const MAX_STUB_DATA: usize = 4_096;
const LOCALS_SPACE: u64 = 0x1000;
const MAX_API_CALLS: usize = 16;
const MAX_VM_API_CALLS: usize = 256;
const WRAPPED_ARGUMENTS: usize = 4;
const MAX_CALLEE_STEPS: usize = 4_096;
const MAX_CALL_DEPTH: usize = 1_024;
const API_RESULT: u64 = 1;
const API_CLOBBER: u64 = 0xC10B_BE4D;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WrapperLeadsTo {
    Api(u64),
    VirtualMachine,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Handover {
    Pushed,
    Register(Gpr),
}

#[derive(PartialEq, Eq)]
pub(crate) struct HiddenValue {
    pub(crate) handover: Handover,
    pub(crate) value: u64,
    pub(crate) data: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Landing {
    pub(crate) address: u64,
    pub(crate) balanced: bool, // jumped to, not called
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Argument {
    Callers(usize), // passed on from the caller's own arguments
    Value(u64),
    Varies, // differs from run to run: past what the api takes
}

pub(crate) struct WrappedCall {
    pub(crate) api: u64,
    pub(crate) arguments: Vec<Argument>,
}

#[derive(Clone, Copy)]
pub(crate) struct StubRunner<'a> {
    pub(crate) image: &'a [u8],
    pub(crate) base: u64,
    pub(crate) bits: u32,
    pub(crate) memory: &'a ProcessMemory<'a>,
}

impl StubRunner<'_> {
    pub(crate) fn destination(&self, start: u64, packer: &Range<u64>) -> Option<WrapperLeadsTo> {
        self.agreed(|cpu, seed| cpu.destination(start, packer, seed))
    }

    // the vm runs its own api calls on its own deeper stack; the wrapped api is the one it jumps to on the caller's frame
    pub(crate) fn through_vm(&self, start: u64) -> Option<u64> {
        self.agreed(|cpu, seed| cpu.through_vm(start, seed))
    }

    pub(crate) fn stub_value(&self, site: u64, length: u64) -> Option<HiddenValue> {
        let back = site.checked_add(length)?;
        self.agreed(|cpu, seed| cpu.stub_value(site, back, seed))
    }

    pub(crate) fn native_landings(
        &self,
        start: u64,
        native: &[Range<u64>],
        enough: &dyn Fn(&[Landing]) -> bool,
    ) -> Option<Vec<Landing>> {
        self.agreed(|cpu, seed| cpu.landings(start, native, enough, seed))
    }

    pub(crate) fn trampoline_target(&self, start: u64, packer: &Range<u64>) -> Option<u64> {
        self.agreed(|cpu, seed| cpu.trampoline_target(start, packer, seed))
    }

    // a wrapper hands its caller the result of the api it wraps: of every api it calls, each answered
    // with a buffer of its own, the one whose answer comes back to the caller is the wrapped one
    pub(crate) fn wrapped_call(&self, start: u64, back: u64) -> Option<WrappedCall> {
        let mut runs = self
            .each_seed(|cpu, seed| cpu.wrapped_call(start, back, seed))
            .into_iter();
        let mut wrapped = runs.next()??;
        for run in runs {
            let run = run?;
            if run.api != wrapped.api {
                return None;
            }
            for (argument, other) in wrapped.arguments.iter_mut().zip(run.arguments) {
                if *argument != other {
                    *argument = Argument::Varies;
                }
            }
        }
        Some(wrapped)
    }

    fn agreed<T: PartialEq>(&self, run: impl Fn(&mut Cpu<'_>, u64) -> Option<T>) -> Option<T> {
        agreed(self.each_seed(run).into_iter())
    }

    fn each_seed<T>(&self, run: impl Fn(&mut Cpu<'_>, u64) -> Option<T>) -> Vec<Option<T>> {
        let taken = |range: &Range<u64>| {
            overlaps(range, self.base, self.image.len() as u64)
                || self
                    .memory
                    .overlaps(&(range.start as usize..range.end as usize))
        };

        let Some((stack, teb)) = exec_bases(self.bits, taken) else {
            return Vec::new();
        };
        let seeded = |seed| {
            let mut cpu = Cpu::new_exec_at(self.image, self.base, self.bits, stack, teb);
            cpu.outside = Some(self.memory);
            run(&mut cpu, seed)
        };

        SEEDS.into_iter().map(seeded).collect()
    }
}

impl Cpu<'_> {
    fn destination(
        &mut self,
        start: u64,
        packer: &Range<u64>,
        seed: u64,
    ) -> Option<WrapperLeadsTo> {
        let seeds = self.poison_registers(seed);
        let frame = self.gpr[RSP];
        let mut decoys = 0;
        self.rip = start;

        for _ in 0..WRAPPER_BUDGET {
            if !self.in_image(self.rip) {
                if self.gpr[RSP] == frame {
                    return self
                        .only_scratch_changed(&seeds)
                        .then_some(WrapperLeadsTo::Api(self.rip));
                }

                decoys += 1;
                if decoys > MAX_API_CALLS {
                    return None;
                }
                self.skip_api_call(frame)?; // decoy call
                continue;
            }

            let insn = self.fetch()?;
            let spinlock = insn.has_lock_prefix() && insn.mnemonic() == Mnemonic::Cmpxchg;
            if spinlock && packer.contains(&insn.ip()) {
                return Some(WrapperLeadsTo::VirtualMachine); // vm entry spinlock
            }
            self.step(&insn)?;
        }

        None
    }

    fn wrapped_call(&mut self, start: u64, back: u64, seed: u64) -> Option<WrappedCall> {
        let width = u64::from(self.bits / 8);
        let seeds = self.poison_registers(seed);
        let frame = self.gpr[RSP].checked_sub(width)?;
        self.gpr[RSP] = frame;
        self.write_mem(frame, width as usize, back)?;

        let callers: Vec<u64> = match self.bits {
            64 => X64_ARGUMENTS.map(|reg| seeds[reg]).to_vec(),
            _ => (1..=WRAPPED_ARGUMENTS as u64)
                .map(|slot| frame_mark(seed, slot, self.bits))
                .collect(),
        };
        if self.bits == 32 {
            for (slot, mark) in (1u64..).zip(&callers) {
                self.write_mem(frame + slot * width, width as usize, *mark)?;
            }
        }
        let argument = |value: u64| {
            let passed = |mark: &u64| *mark == value || mask(*mark, 4) == value; // a 32-bit argument zero-extends
            match callers.iter().position(passed) {
                Some(index) => Argument::Callers(index),
                None => Argument::Value(mask(value, width as usize)),
            }
        };

        let mut answered: Vec<(u64, u64, Vec<Argument>)> = Vec::new();
        self.rip = start;
        for _ in 0..VM_BUDGET {
            if self.rip == back {
                let result = mask(self.gpr[RAX], width as usize);
                let (api, _, arguments) = answered
                    .into_iter()
                    .find(|(_, answer, _)| *answer == result)?;
                return Some(WrappedCall { api, arguments });
            }

            if !self.in_image(self.rip) {
                let sp = self.gpr[RSP];
                let arguments: Vec<Argument> = match self.bits {
                    64 => X64_ARGUMENTS.map(|reg| argument(self.gpr[reg])).to_vec(),
                    _ => (1..=WRAPPED_ARGUMENTS as u64)
                        .map(|slot| Some(argument(self.mem(sp + slot * width, width as usize)?)))
                        .collect::<Option<_>>()?,
                };
                if sp >= frame {
                    return Some(WrappedCall {
                        api: self.rip,
                        arguments,
                    }); // jumped to on the caller's frame
                }

                let result = self.fresh_buffer()?;
                answered.push((self.rip, mask(result, width as usize), arguments));
                if answered.len() > MAX_VM_API_CALLS {
                    return None;
                }
                self.skip_api_call_returning(frame, result)?;
                continue;
            }

            let insn = self.fetch()?;
            self.step(&insn)?;
        }
        None
    }

    fn through_vm(&mut self, start: u64, seed: u64) -> Option<u64> {
        let width = u64::from(self.bits / 8);
        let seeds = self.poison_registers(seed);
        let frame = self.gpr[RSP];
        let argument = frame_mark(seed, 1, self.bits);
        if self.bits == 32 {
            self.write_mem(frame.checked_add(width)?, width as usize, argument)?; // the caller's first argument
        }
        let first_register = self.gpr[RCX];
        let mut api_calls = 0;
        self.rip = start;

        for _ in 0..VM_BUDGET {
            if !self.in_image(self.rip) {
                if self.gpr[RSP] == frame {
                    return self.only_scratch_changed(&seeds).then_some(self.rip);
                }

                let sp = self.gpr[RSP];
                let passes_argument = match self.bits {
                    32 => self.mem(sp.checked_add(width)?, width as usize) == Some(argument),
                    _ => passes_low_half(self.gpr[RCX], first_register),
                };
                let called = self
                    .mem(sp, width as usize)
                    .is_some_and(|back| self.in_image(back));
                if called && passes_argument {
                    return Some(self.rip); // the vm calls it with the caller's own argument
                }

                api_calls += 1;
                if api_calls > MAX_VM_API_CALLS {
                    return None;
                }
                let result = self.fresh_buffer()?; // non-zero for a flag, usable memory for an allocation
                self.skip_api_call_returning(frame, result)?;
                continue;
            }

            let insn = self.fetch()?;
            self.step(&insn)?;
        }

        None
    }

    fn stub_value(&mut self, site: u64, back: u64, seed: u64) -> Option<HiddenValue> {
        let width = u64::from(self.bits / 8);
        let seeds = self.poison_registers(seed);
        let frame = self.gpr[RSP];
        self.rip = site;

        for _ in 0..VM_BUDGET {
            if self.rip == back {
                let changed: Vec<usize> = self.changed(&seeds).collect();
                let (value, handover) = match changed[..] {
                    [] if self.gpr[RSP] == frame.checked_sub(width)? => {
                        (self.mem(self.gpr[RSP], width as usize)?, Handover::Pushed)
                    }
                    [only] if self.gpr[RSP] == frame => (
                        mask(self.gpr[only], width as usize),
                        Handover::Register(Gpr(u8::try_from(only).ok()?)),
                    ),
                    _ => return None,
                };

                let data = (value..)
                    .take(MAX_STUB_DATA)
                    .map_while(|at| self.read_byte(at))
                    .collect();
                return Some(HiddenValue {
                    handover,
                    value,
                    data,
                });
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
        self.poison_registers(seed);
        let frame = self.gpr[RSP];
        self.gpr[RBP] = frame.checked_add(LOCALS_SPACE)?; // mid function locals
        let mut found = Vec::new();
        let mut calls = CallStack::default();
        let mut inside = true;
        let mut api_calls = 0;
        self.rip = start;

        for _ in 0..VM_BUDGET {
            if !self.in_image(self.rip) {
                api_calls += 1;
                if api_calls > MAX_API_CALLS {
                    return None;
                }
                self.skip_api_call(frame)?;
                continue;
            }

            let here = native.iter().any(|range| range.contains(&self.rip));
            if here && !inside && !calls.unwind_to(self.rip, self.gpr[RSP]) {
                found.push(Landing {
                    address: self.rip,
                    balanced: self.gpr[RSP] == frame,
                });
                if enough(&found) {
                    return Some(found);
                }
            }
            inside = here;

            let insn = self.fetch()?;
            let sp = self.gpr[RSP];
            self.step(&insn)?;

            match insn.mnemonic() {
                Mnemonic::Call if here => calls.push(insn.next_ip(), sp)?,
                Mnemonic::Ret if here => {
                    calls.unwind_to(self.rip, self.gpr[RSP]);
                }
                _ => {}
            }
        }

        None
    }

    fn trampoline_target(&mut self, start: u64, packer: &Range<u64>, seed: u64) -> Option<u64> {
        let seeds = self.poison_registers(seed);
        let frame = self.gpr[RSP];
        let mut calls = CallStack::default();
        self.rip = start;

        for step in 0..TRAMPOLINE_BUDGET {
            if step > 0 && !packer.contains(&self.rip) {
                return None; // vm, not trampoline
            }

            let insn = self.fetch()?;
            let sp = self.gpr[RSP];
            self.step(&insn)?;

            match insn.mnemonic() {
                Mnemonic::Call => calls.push(insn.next_ip(), sp)?,
                Mnemonic::Ret if calls.unwind_to(self.rip, self.gpr[RSP]) => continue,
                _ => {}
            } // a call used as a push never returns
            let handed_over = insn.mnemonic() == Mnemonic::Ret
                && self.gpr[RSP] == frame
                && self.changed(&seeds).next().is_none()
                && packer.contains(&self.rip);
            if handed_over {
                return Some(self.rip); // push ret
            }
        }

        None
    }

    fn skip_api_call(&mut self, frame: u64) -> Option<()> {
        self.skip_api_call_returning(frame, API_RESULT)
    }

    fn skip_api_call_returning(&mut self, frame: u64, result: u64) -> Option<()> {
        let width = u64::from(self.bits / 8);
        let sp = self.gpr[RSP];
        let back = self.mem(sp, width as usize)?;
        if sp >= frame || !self.in_image(back) {
            return None;
        }

        let cleanup = match self.bits {
            64 => 0,
            _ => self.stdcall_cleanup(self.rip)?,
        };

        step_budget::note_api_call();
        self.gpr[RSP] = sp.checked_add(width)?.checked_add(cleanup)?;
        self.gpr[RAX] = result;
        let volatile: &[usize] = match self.bits {
            64 => &[RCX, RDX, R8, R9, R10, R11],
            _ => &[RCX, RDX],
        };
        for reg in volatile {
            self.gpr[*reg] = API_CLOBBER; // apis clobber them
        }
        self.rip = back;
        Some(())
    }

    // stdcall pops the same bytes on every return path, so every ret reached must agree
    fn stdcall_cleanup(&self, entry: u64) -> Option<u64> {
        let mut work = vec![entry];
        let mut seen = HashSet::new();
        let mut cleanup = None;

        while let Some(at) = work.pop() {
            if !seen.insert(at) {
                continue;
            }
            if seen.len() > MAX_CALLEE_STEPS {
                return None;
            }

            let Some(insn) = self.decode_at(at) else {
                continue; // a page the capture lacks tells nothing about this path
            };
            match (insn.flow_control(), insn.mnemonic()) {
                (FlowControl::Return, Mnemonic::Ret) => {
                    let popped = match insn.op_count() {
                        0 => 0,
                        _ => u64::from(insn.immediate16()),
                    };
                    if cleanup.replace(popped).is_some_and(|seen| seen != popped) {
                        return None;
                    }
                }
                (FlowControl::UnconditionalBranch | FlowControl::IndirectBranch, Mnemonic::Jmp) => {
                    work.extend(self.static_jump_target(&insn)); // iat thunks followed, a table jump ends this path
                }
                (FlowControl::ConditionalBranch, _) => {
                    work.extend([insn.next_ip(), insn.near_branch_target()]);
                }
                (FlowControl::Call | FlowControl::IndirectCall | FlowControl::Next, _) => {
                    work.push(insn.next_ip()); // a callee returns past its call
                }
                _ => {} // a trap ends this path
            }
        }

        cleanup
    }

    fn static_jump_target(&self, insn: &Instruction) -> Option<u64> {
        if is_near_immediate(insn) {
            return Some(insn.near_branch_target());
        }

        self.mem(fixed_address(insn)?, (self.bits / 8) as usize) // iat thunk
    }
}

#[derive(Default)]
struct CallStack(Vec<Call>);

struct Call {
    returns_to: u64,
    sp: u64,
}

impl CallStack {
    fn push(&mut self, returns_to: u64, sp: u64) -> Option<()> {
        if self.0.len() == MAX_CALL_DEPTH {
            return None;
        }

        self.0.push(Call { returns_to, sp });
        Some(())
    }

    fn unwind_to(&mut self, rip: u64, sp: u64) -> bool {
        let Some(depth) = self
            .0
            .iter()
            .rposition(|call| call.returns_to == rip && sp >= call.sp)
        // stdcall pops its arguments too
        else {
            return false;
        };
        self.0.truncate(depth);
        true
    }
}

// a 32-bit argument loaded into ecx clears rcx's top half; an untouched rcx keeps it, so only a
// value that differs from the caller's but holds its low half was passed on
fn passes_low_half(now: u64, callers: u64) -> bool {
    now != callers && now == callers & u64::from(u32::MAX)
}
