use std::collections::BTreeMap;
use std::ops::Range;

use iced_x86::Instruction;

use super::execute::Width;
use crate::pe::process_memory::ProcessMemory;
use crate::process::os_version;
use crate::unpack::x86::branches::decode_one;
use crate::unpack::x86::branches::{MAX_CALL_PADDING, REL32_LEN};
use crate::unpack::x86::opcodes::MAX_INSTRUCTION;
use crate::unpack::x86::step_budget;
use crate::unpack::x86::written_memory::Overlay;
use crate::unpack::x86::x87::X87;

pub(super) const STUB_STACK_SIZE: u64 = 0x1_0000;
const STACK_BASE_64: u64 = 0x7FF0_0000_0000;
const STACK_BASE_32: u64 = 0x6000_0000;
const LARGEST_INTEGER: usize = 8; // bytes one read or write carries

pub(super) const CARRY_FLAG: u64 = 1 << 0;
pub(super) const RESERVED_FLAG: u64 = 1 << 1; // always set
pub(super) const PARITY_FLAG: u64 = 1 << 2;
pub(super) const ADJUST_FLAG: u64 = 1 << 4;
pub(super) const ZERO_FLAG: u64 = 1 << 6;
pub(super) const SIGN_FLAG: u64 = 1 << 7;
pub(super) const INTERRUPT_FLAG: u64 = 1 << 9; // always set in user mode, popf cannot clear it
pub(super) const DIRECTION_FLAG: u64 = 1 << 10;
pub(super) const OVERFLOW_FLAG: u64 = 1 << 11;
pub(super) const STATUS_FLAGS: u64 =
    CARRY_FLAG | PARITY_FLAG | ADJUST_FLAG | ZERO_FLAG | SIGN_FLAG | OVERFLOW_FLAG;
pub(super) const MODELLED_FLAGS: u64 =
    STATUS_FLAGS | DIRECTION_FLAG | RESERVED_FLAG | INTERRUPT_FLAG;
const PEB_AFTER_TEB: u64 = 0x4000;
const THREAD_BLOCK_SIZE: usize = 0x2000;
const PEB_BEING_DEBUGGED: u64 = 0x02;

const SEH_CHAIN_END: u64 = 0xFFFF_FFFF;

struct TebFields {
    own_address: u64,
    peb: u64,
    stack_top: u64,
    stack_limit: u64,
    peb_image_base: u64,
    peb_os_version: u64,
}

const TEB_64: TebFields = TebFields {
    own_address: 0x30,
    peb: 0x60,
    stack_top: 0x08,
    stack_limit: 0x10,
    peb_image_base: 0x10,
    peb_os_version: 0x118,
};
const TEB_32: TebFields = TebFields {
    own_address: 0x18,
    peb: 0x30,
    stack_top: 0x04,
    stack_limit: 0x08,
    peb_image_base: 0x08,
    peb_os_version: 0xA4,
};

const TEB_BASE_64: u64 = 0x7FFE_0000_0000;
const TEB_BASE_32: u64 = 0x7FFD_8000; // below 4 gb
const SPARE_BASES_64: [u64; 3] = [0x7FE0_0000_0000, 0x1000_0000_0000, 0x0200_0000_0000];
const SPARE_BASES_32: [u64; 4] = [0x5000_0000, 0x3000_0000, 0x2000_0000, 0x0800_0000];
const TEB_LANE: u64 = 0x0100_0000;
const BUFFER_LANE: u64 = 0x0200_0000;
const THREAD_BLOCKS: u64 = PEB_AFTER_TEB + THREAD_BLOCK_SIZE as u64;

pub(super) fn clear_base(
    preferred: u64,
    size: u64,
    lane: u64,
    bits: u32,
    taken: impl Fn(&Range<u64>) -> bool,
) -> Option<u64> {
    let spare: &[u64] = match bits {
        64 => &SPARE_BASES_64,
        _ => &SPARE_BASES_32,
    };

    std::iter::once(preferred)
        .chain(spare.iter().map(|base| base + lane))
        .find(|base| !taken(&(*base..base + size)))
}

fn teb_base(bits: u32) -> u64 {
    match bits {
        64 => TEB_BASE_64,
        _ => TEB_BASE_32,
    }
}

fn stack_base(bits: u32) -> u64 {
    match bits {
        64 => STACK_BASE_64,
        _ => STACK_BASE_32,
    }
}

// a stack and thread blocks for running whole functions
pub(super) fn exec_bases(bits: u32, taken: impl Fn(&Range<u64>) -> bool) -> Option<(u64, u64)> {
    let stack = clear_base(stack_base(bits), FUNCTION_STACK_SIZE, 0, bits, &taken)?;
    let teb = clear_base(teb_base(bits), THREAD_BLOCKS, TEB_LANE, bits, &taken)?;
    Some((stack, teb))
}

pub(super) fn overlaps(range: &Range<u64>, start: u64, length: u64) -> bool {
    range.start < start.saturating_add(length) && start < range.end
}

const BUDGET: usize = 50_000;
const OBSERVE_BUDGET: usize = 200_000;
const STRING_BUDGET: u64 = 1 << 24;
const FUNCTION_STACK_SIZE: u64 = 0x20_0000; // vm frames
const FRAME_SLOTS: u64 = 8; // marked caller slots
const SHORTEST_STUB: usize = 8;

#[derive(Default)]
pub(super) struct Flags {
    pub(super) cf: bool,
    pub(super) of: bool,
    pub(super) sf: bool,
    pub(super) zf: bool,
    pub(super) af: bool,
    pub(super) pf: bool,
    pub(super) df: bool,
}

pub(super) struct Cpu<'a> {
    pub(super) gpr: [u64; 16],
    pub(super) rip: u64,
    pub(super) flags: Flags,
    image: &'a [u8],
    image_base: u64,
    pub(super) stack: Vec<u8>,
    pub(super) stack_base: u64,
    pub(super) bits: u32,
    pub(super) overlay: Option<Overlay>,
    pub(super) thread_block: Option<u64>,
    extra: Vec<Region>,
    pub(super) x87: X87,
    pub(super) xmm: [u128; 16],
    pub(super) string_fuel: u64,
    pub(super) outside: Option<&'a ProcessMemory<'a>>, // read-only
    pub(super) unmapped: Option<u64>,                  // noise seed
    arena: Option<Range<u64>>,                         // what fresh_buffer has left to hand out
}

struct Region {
    base: u64,
    bytes: Vec<u8>,
    modelled: Option<Vec<bool>>, // thread blocks: a field nobody wrote stops the run
}

impl Region {
    fn buffer(base: u64, size: usize) -> Self {
        Self {
            base,
            bytes: vec![0; size],
            modelled: None,
        }
    }

    fn thread_block(base: u64) -> Self {
        Self {
            base,
            bytes: vec![0; THREAD_BLOCK_SIZE],
            modelled: Some(vec![false; THREAD_BLOCK_SIZE]),
        }
    }

    fn offset(&self, addr: u64) -> Option<usize> {
        let offset = usize::try_from(addr.checked_sub(self.base)?).ok()?;
        (offset < self.bytes.len()).then_some(offset)
    }

    fn read(&self, offset: usize) -> Option<u8> {
        let known = match &self.modelled {
            Some(modelled) => *modelled.get(offset)?,
            None => true,
        };
        known.then_some(())?;
        self.bytes.get(offset).copied()
    }

    fn write(&mut self, offset: usize, value: u8) -> Option<()> {
        *self.bytes.get_mut(offset)? = value;
        if let Some(modelled) = &mut self.modelled {
            *modelled.get_mut(offset)? = true;
        }
        Some(())
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Failure {
    Coincidence,
    Budget,
    Unmodelled,
    Mismatch,
}

pub(crate) struct Resolved {
    pub(crate) target: u64,
    pub(crate) flow: Flow,
    pub(crate) end: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    Call,
    Jump,
    Load(Gpr),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gpr(pub(super) u8); // encoding number, 0 to 15

impl Gpr {
    pub(crate) fn number(self) -> u8 {
        self.0
    }
}

pub(crate) fn resolve(
    image: &[u8],
    image_base: u64,
    bits: u32,
    start: u64,
    call_site: u64,
    seed: u64,
    outside: Option<&ProcessMemory<'_>>, // memory the packer allocated, as captured
) -> Result<Resolved, Failure> {
    let mut cpu = Cpu::new(image, image_base, bits).ok_or(Failure::Unmodelled)?;
    cpu.outside = outside;
    cpu.run(start, call_site, seed)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum StubExit {
    Returns(u64),
    TailJumps, // jump to an import
    Unknown,
}

pub(crate) fn stub_exit(
    image: &[u8],
    image_base: u64,
    bits: u32,
    start: u64,
    site: u64,
    outside: Option<&ProcessMemory<'_>>,
) -> StubExit {
    let run = |seed| {
        let resolved = resolve(image, image_base, bits, start, site, seed, outside).ok()?;
        Some((resolved.flow, resolved.end))
    };
    let Some(exit) = agreed(SEEDS.into_iter().map(run)) else {
        return StubExit::Unknown;
    };

    match exit {
        (Flow::Jump, _) => StubExit::TailJumps,
        (_, Some(end)) => StubExit::Returns(end),
        (_, None) => StubExit::Unknown,
    }
}

#[derive(PartialEq)]
struct Behaviour {
    returned: bool,
    left_to: Option<u64>,
    regs: Vec<u64>,
    float_result: u128, // xmm0
    x87: X87,
    backwards: bool,            // df
    outgoing: Vec<Option<u64>>, // stack arguments of the call that left
    writes: BTreeMap<u64, u8>,
    buffers: Vec<Vec<u8>>,
}

const POINTER_BUFFERS_64: u64 = 0x7FFD_0000_0000;
const POINTER_BUFFERS_32: u64 = 0x5F00_0000;
pub(crate) const RAX: usize = 0; // gpr indices
pub(crate) const RCX: usize = 1;
pub(crate) const RDX: usize = 2;
pub(crate) const RBX: usize = 3;
pub(crate) const RSP: usize = 4;
pub(crate) const RBP: usize = 5;
pub(crate) const RSI: usize = 6;
pub(crate) const RDI: usize = 7;
pub(crate) const R8: usize = 8;
pub(crate) const R9: usize = 9;
pub(crate) const R10: usize = 10;
pub(crate) const R11: usize = 11;
const R12: usize = 12;
const R13: usize = 13;
const R14: usize = 14;
const R15: usize = 15;
pub(super) const X64_ARGUMENTS: [usize; 4] = [RCX, RDX, R8, R9];
const RETURN_SENTINEL_64: u64 = 0xCAFE_BABE_D00D_0000; // no code lives there
const RETURN_SENTINEL_32: u64 = 0xCAFE_B000;

fn return_sentinel(bits: u32) -> u64 {
    match bits {
        64 => RETURN_SENTINEL_64,
        _ => RETURN_SENTINEL_32,
    }
}
const POINTER_BUFFER: u64 = 0x1_0000;
const POINTER_BUFFERS: u64 = 32;
const ARENA_64: u64 = 0x7FFC_0000_0000;
const ARENA_32: u64 = 0x5E00_0000;
const ARENA_SIZE: u64 = 0x10_0000;
const ARENA_BUFFER: u64 = 0x4000;
const STACK_ARGS: u64 = 4;
const HOME_SLOTS: u64 = 4; // x64 callers leave room for the register arguments

#[derive(Clone, Copy)]
enum Arguments {
    Seeded,
    Pointers, // each points at its own buffer
    Small,    // small args end loops
}

#[derive(Clone, Copy)]
pub(crate) enum Agreement {
    Every, // vmp junk
    Finished,
}

impl Agreement {
    fn arguments(self) -> &'static [Arguments] {
        match self {
            Agreement::Every => &[Arguments::Seeded, Arguments::Pointers],
            Agreement::Finished => &[Arguments::Seeded, Arguments::Pointers, Arguments::Small],
        }
    }
}

const SMALL_ARGUMENT: u64 = 0x40;
const SMALL_SEED: u64 = 0x5EED;

fn observe(
    image: &[u8],
    image_base: u64,
    bits: u32,
    entry: u64,
    arguments: Arguments,
    private: &Range<u64>,
) -> Option<Behaviour> {
    let kept: &[usize] = if bits == 64 {
        &[RAX, RBX, RSP, RBP, RSI, RDI, R12, R13, R14, R15]
    } else {
        &[RAX, RBX, RSP, RBP, RSI, RDI]
    };

    let mut cpu = Cpu::new_exec(image, image_base, bits)?;
    let stack = cpu.gpr[RSP];
    cpu.poison_registers(u64::from(matches!(arguments, Arguments::Pointers)));

    let synthetic = cpu.extra.len();
    match arguments {
        Arguments::Seeded => {}
        Arguments::Small => cpu.pass_small_arguments(stack)?,
        Arguments::Pointers => cpu.pass_pointer_arguments(stack)?,
    }

    let stop = cpu.run_function(entry);
    let returned = stop == Stop::Returned;
    let left_to = match stop {
        Stop::Returned => Some(cpu.rip),
        Stop::Left(api) => Some(api),
        Stop::Fault => None,
    };
    let argument_regs: &[usize] = match (left_to, bits) {
        (None, _) => &[],
        (Some(_), 64) => &X64_ARGUMENTS,
        (Some(_), _) => &[RCX, RDX], // thiscall, fastcall
    };
    let outgoing = match stop {
        Stop::Left(_) => cpu.outgoing_arguments(),
        _ => Vec::new(),
    };

    let wide_result: &[usize] = match (returned, bits) {
        (true, 32) => &[RDX], // high half of a 64-bit return
        _ => &[],
    };

    Some(Behaviour {
        returned,
        left_to,
        regs: kept
            .iter()
            .chain(argument_regs)
            .chain(wide_result)
            .map(|&reg| cpu.gpr[reg])
            .collect(),
        float_result: cpu.xmm[0],
        x87: cpu.x87,
        backwards: cpu.flags.df,
        outgoing,
        buffers: cpu
            .extra
            .split_off(synthetic)
            .into_iter()
            .map(|region| region.bytes)
            .collect(),
        writes: cpu
            .overlay
            .unwrap_or_default()
            .into_writes()
            .filter(|(at, _)| !private.contains(at)) // packer state
            .collect(),
    })
}

pub(crate) fn same_behaviour(
    original: &[u8],
    patched: &[u8],
    image_base: u64,
    bits: u32,
    entry: u64,
    private: &Range<u64>,
    agreement: Agreement,
) -> bool {
    let observed: Option<Vec<(Behaviour, Behaviour)>> = agreement
        .arguments()
        .iter()
        .map(|arguments| {
            Some((
                observe(original, image_base, bits, entry, *arguments, private)?,
                observe(patched, image_base, bits, entry, *arguments, private)?,
            ))
        })
        .collect();
    let Some(runs) = observed else {
        return false;
    };

    let finished = |run: &Behaviour| run.left_to.is_some();
    let conclusive = runs.iter().any(|(packed, _)| finished(packed));
    let alike = runs
        .iter()
        .filter(|(packed, _)| matches!(agreement, Agreement::Every) || finished(packed))
        .all(|(packed, clean)| packed == clean);
    conclusive && alike
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stop {
    Returned,
    Left(u64),
    Fault,
}

impl<'a> Cpu<'a> {
    pub(super) fn new(image: &'a [u8], image_base: u64, bits: u32) -> Option<Self> {
        Self::with_stack(image, image_base, bits, STUB_STACK_SIZE)
    }

    pub(super) fn with_stack(
        image: &'a [u8],
        image_base: u64,
        bits: u32,
        size: u64,
    ) -> Option<Self> {
        let in_image = |range: &Range<u64>| overlaps(range, image_base, image.len() as u64);
        let stack = clear_base(stack_base(bits), size, 0, bits, in_image)?;

        Some(Self::on_stack(image, image_base, bits, stack, size))
    }

    fn on_stack(image: &'a [u8], image_base: u64, bits: u32, stack_base: u64, size: u64) -> Self {
        let mut cpu = Cpu {
            gpr: [0; 16],
            rip: 0,
            flags: Flags::default(),
            image,
            image_base,
            stack: vec![0; size as usize],
            stack_base,
            bits,
            overlay: None,
            thread_block: None,
            extra: Vec::new(),
            x87: X87::default(),
            xmm: [0; 16],
            string_fuel: STRING_BUDGET,
            outside: None,
            unmapped: None,
            arena: None,
        };
        cpu.gpr[RSP] = stack_base + size / 2; // mid stack
        cpu
    }

    fn new_exec(image: &'a [u8], image_base: u64, bits: u32) -> Option<Self> {
        let in_image = |range: &Range<u64>| overlaps(range, image_base, image.len() as u64);
        let (stack, teb) = exec_bases(bits, in_image)?;

        Some(Self::new_exec_at(image, image_base, bits, stack, teb))
    }

    pub(super) fn new_exec_at(
        image: &'a [u8],
        image_base: u64,
        bits: u32,
        stack_base: u64,
        teb_base: u64,
    ) -> Self {
        let teb = if bits == 64 { TEB_64 } else { TEB_32 };
        let peb_base = teb_base + PEB_AFTER_TEB;
        let mut cpu = Cpu {
            overlay: Some(Overlay::default()),
            thread_block: Some(teb_base),
            extra: vec![
                Region::thread_block(teb_base),
                Region::thread_block(peb_base),
            ],
            ..Self::on_stack(image, image_base, bits, stack_base, FUNCTION_STACK_SIZE)
        };

        let ptr = (bits / 8) as usize;
        let stack_top = stack_base + FUNCTION_STACK_SIZE;
        cpu.write_mem(teb_base + teb.own_address, ptr, teb_base);
        cpu.write_mem(teb_base + teb.peb, ptr, peb_base);
        cpu.write_mem(teb_base + teb.stack_top, ptr, stack_top);
        cpu.write_mem(teb_base + teb.stack_limit, ptr, stack_base);
        cpu.write_mem(peb_base + PEB_BEING_DEBUGGED, 1, 0);
        cpu.write_mem(peb_base + teb.peb_image_base, ptr, image_base);
        if let Some(version) = os_version() {
            let fields = (peb_base + teb.peb_os_version..).step_by(4);
            for (at, field) in fields.zip(version.as_chunks::<4>().0) {
                cpu.write_mem(at, 4, u64::from(u32::from_le_bytes(*field)));
            }
        }
        if bits == 32 {
            cpu.write_mem(teb_base, ptr, SEH_CHAIN_END); // fs:[0]
        }

        cpu
    }

    fn covers(&self, range: &Range<u64>) -> bool {
        overlaps(range, self.image_base, self.image.len() as u64)
            || overlaps(range, self.stack_base, self.stack.len() as u64)
            || self
                .extra
                .iter()
                .any(|region| overlaps(range, region.base, region.bytes.len() as u64))
    }

    fn pass_small_arguments(&mut self, stack: u64) -> Option<()> {
        self.unmapped = Some(SMALL_SEED);
        self.pass_arguments(stack, |k| (k * 7 + 3) % SMALL_ARGUMENT)
    }

    // zeroed writable memory, as an allocating api would return
    pub(super) fn fresh_buffer(&mut self) -> Option<u64> {
        if self.arena.is_none() {
            let preferred = match self.bits {
                64 => ARENA_64,
                _ => ARENA_32,
            };
            let base = clear_base(preferred, ARENA_SIZE, BUFFER_LANE, self.bits, |range| {
                self.covers(range)
            })?;
            self.extra.push(Region::buffer(base, ARENA_SIZE as usize));
            self.arena = Some(base..base + ARENA_SIZE);
        }

        let arena = self.arena.as_mut()?;
        let buffer = arena.start;
        (buffer + ARENA_BUFFER <= arena.end).then_some(())?;
        arena.start += ARENA_BUFFER;
        Some(buffer)
    }

    fn pass_pointer_arguments(&mut self, stack: u64) -> Option<()> {
        let preferred = if self.bits == 64 {
            POINTER_BUFFERS_64
        } else {
            POINTER_BUFFERS_32
        };
        let first = clear_base(
            preferred,
            POINTER_BUFFER * POINTER_BUFFERS,
            BUFFER_LANE,
            self.bits,
            |range| self.covers(range),
        )?;

        for k in 0..self.gpr_count() as u64 + STACK_ARGS {
            self.extra.push(Region::buffer(
                first + k * POINTER_BUFFER,
                POINTER_BUFFER as usize,
            ));
        }

        self.pass_arguments(stack, |k| first + k * POINTER_BUFFER + POINTER_BUFFER / 2)
    }

    // argument k: registers by number, then the stack slots above the return (x64 home area first)
    fn pass_arguments(&mut self, stack: u64, value: impl Fn(u64) -> u64) -> Option<()> {
        let ptr = u64::from(self.bits / 8);
        let regs = self.gpr_count() as u64;
        for reg in (0..regs).filter(|&reg| reg != RSP as u64) {
            self.gpr[reg as usize] = value(reg);
        }

        for k in 0..STACK_ARGS {
            self.write_mem(stack + k * ptr, ptr as usize, value(regs + k))?;
        }
        Some(())
    }

    fn outgoing_arguments(&self) -> Vec<Option<u64>> {
        let ptr = u64::from(self.bits / 8);
        let first = match self.bits {
            64 => 1 + HOME_SLOTS,
            _ => 1, // past the return address
        };

        (first..first + STACK_ARGS)
            .map(|slot| self.mem(self.gpr[RSP].wrapping_add(slot * ptr), ptr as usize))
            .collect()
    }

    pub(super) fn in_image(&self, addr: u64) -> bool {
        addr.checked_sub(self.image_base)
            .is_some_and(|offset| offset < self.image.len() as u64)
    }

    pub(super) fn fetch(&self) -> Option<Instruction> {
        let end = self.rip.saturating_add(MAX_INSTRUCTION as u64);
        let rewritten = self
            .overlay
            .as_ref()
            .is_some_and(|overlay| overlay.any_in(self.rip..end));
        if rewritten {
            return self.decode_at(self.rip);
        }

        decode_one(self.bits, self.static_window(self.rip)?, self.rip)
    }

    pub(super) fn decode_at(&self, at: u64) -> Option<Instruction> {
        let mut window = [0u8; MAX_INSTRUCTION];
        let mut length = 0;
        for (slot, addr) in window
            .iter_mut()
            .zip(at..at.saturating_add(MAX_INSTRUCTION as u64))
        {
            let Some(byte) = self.read_byte(addr) else {
                break;
            };
            *slot = byte;
            length += 1;
        }

        decode_one(self.bits, window.get(..length)?, at)
    }

    fn static_window(&self, addr: u64) -> Option<&[u8]> {
        let (bytes, start): (&[u8], usize) = if self.in_image(addr) {
            (self.image, (addr - self.image_base) as usize)
        } else {
            self.extra
                .iter()
                .filter(|region| region.modelled.is_none())
                .find_map(|region| Some((region.bytes.as_slice(), region.offset(addr)?)))?
        };
        bytes.get(start..start.saturating_add(MAX_INSTRUCTION).min(bytes.len()))
    }

    fn run_function(&mut self, entry: u64) -> Stop {
        let sentinel = return_sentinel(self.bits);
        if self.push(sentinel).is_none() {
            return Stop::Fault;
        }
        self.rip = entry;

        for _ in 0..OBSERVE_BUDGET {
            if self.rip == sentinel {
                return Stop::Returned;
            }
            let Some(insn) = self.fetch() else {
                return match self.in_image(self.rip) {
                    true => Stop::Fault,
                    false => Stop::Left(self.rip),
                };
            };
            if self.step(&insn).is_none() {
                return Stop::Fault;
            }
        }
        Stop::Fault
    }

    fn run(&mut self, start: u64, call_site: u64, seed: u64) -> Result<Resolved, Failure> {
        let width = (self.bits / 8) as usize;
        let ptr = width as u64;

        let seeds = self.poison_registers(seed);
        let frame = self.gpr[RSP];
        let marks: Vec<u64> = (0..FRAME_SLOTS)
            .map(|slot| frame_mark(seed, slot, self.bits))
            .collect();
        for (slot, mark) in (0u64..).zip(&marks) {
            self.write_mem(frame + slot * ptr, width, *mark)
                .ok_or(Failure::Unmodelled)?;
        }

        let after_call = call_site.saturating_add(REL32_LEN as u64);
        let returns = after_call..=after_call.saturating_add(MAX_CALL_PADDING);
        self.rip = start;

        for steps in 0..BUDGET {
            let left = returns.contains(&self.rip) || !self.in_image(self.rip);
            if left && steps < SHORTEST_STUB {
                return Err(Failure::Coincidence);
            }
            if returns.contains(&self.rip) {
                return self
                    .returned(frame, &marks, &seeds)
                    .ok_or(Failure::Mismatch);
            }
            if !self.in_image(self.rip) {
                let reached_api = plausible(self.rip, self.bits);
                return self.escaped(frame, &marks, &seeds).ok_or(if reached_api {
                    Failure::Mismatch
                } else {
                    Failure::Coincidence
                });
            }

            let insn = self.fetch().ok_or(Failure::Coincidence)?;
            self.step(&insn).ok_or(match step_budget::ran_dry() {
                true => Failure::Budget,
                false => Failure::Unmodelled,
            })?;
        }
        Err(Failure::Budget)
    }

    fn returned(&self, frame: u64, marks: &[u64], seeds: &[u64; 16]) -> Option<Resolved> {
        if self.gpr[RSP] != frame || !self.frame_intact(frame, marks) {
            return None;
        }

        let changed: Vec<usize> = self.changed(seeds).collect();
        let reg = match changed[..] {
            [only] => only,
            _ => match changed
                .iter()
                .filter(|&&reg| !self.is_scratch(reg))
                .collect::<Vec<_>>()[..]
            {
                [&only] => only,
                _ => return None,
            },
        };

        Some(Resolved {
            target: mask(self.gpr[reg], (self.bits / 8) as usize),
            flow: Flow::Load(Gpr(reg as u8)),
            end: Some(self.rip),
        })
    }

    fn escaped(&self, frame: u64, marks: &[u64], seeds: &[u64; 16]) -> Option<Resolved> {
        let width = (self.bits / 8) as usize;
        if !self.frame_intact(frame, marks) || !self.only_scratch_changed(seeds) {
            return None;
        }

        let sp = self.gpr[RSP];
        let (flow, end) = if sp == frame {
            (Flow::Jump, None)
        } else if sp.checked_add(width as u64) == Some(frame) {
            (Flow::Call, Some(self.mem(sp, width)?))
        } else {
            return None;
        };

        Some(Resolved {
            target: self.rip,
            flow,
            end,
        })
    }

    pub(super) fn poison_registers(&mut self, seed: u64) -> [u64; 16] {
        for index in 0..self.gpr_count() {
            if index != RSP {
                self.gpr[index] = poison(seed, index, self.bits);
            }
        }

        let flag_bits = match seed {
            0 => 0,
            1 => u64::MAX,
            _ => drawn(seed, 0),
        };
        if flag_bits != 0 {
            let flag = |bit: u32| flag_bits >> bit & 1 == 1;
            self.flags = Flags {
                cf: flag(0),
                of: flag(1),
                sf: flag(2),
                zf: flag(3),
                af: flag(4),
                pf: flag(5),
                df: false, // the abi keeps it clear
            };
        }

        self.gpr
    }

    pub(super) fn gpr_count(&self) -> usize {
        gpr_count(self.bits)
    }

    fn is_scratch(&self, reg: usize) -> bool {
        match self.bits {
            64 => matches!(reg, RAX | R10 | R11),
            _ => reg == RAX,
        }
    }

    pub(super) fn only_scratch_changed(&self, seeds: &[u64; 16]) -> bool {
        self.changed(seeds).all(|reg| self.is_scratch(reg))
    }

    pub(super) fn changed<'s>(&'s self, seeds: &'s [u64; 16]) -> impl Iterator<Item = usize> + 's {
        let width = (self.bits / 8) as usize;
        (0..self.gpr_count()).filter(move |&index| {
            index != RSP && mask(self.gpr[index], width) != mask(seeds[index], width)
        })
    }

    fn frame_intact(&self, frame: u64, marks: &[u64]) -> bool {
        let width = (self.bits / 8) as usize;
        (0u64..)
            .zip(marks)
            .all(|(slot, mark)| self.mem(frame + slot * width as u64, width) == Some(*mark))
    }

    pub(super) fn mem(&self, addr: u64, size: usize) -> Option<u64> {
        if size > LARGEST_INTEGER {
            return None;
        }

        let mut value = 0u64;
        for i in 0..size as u64 {
            value |= u64::from(self.read_byte(addr.checked_add(i)?)?) << (i * 8);
        }
        Some(value)
    }

    pub(super) fn write_mem(&mut self, addr: u64, size: usize, value: u64) -> Option<()> {
        if size > LARGEST_INTEGER {
            return None;
        }

        for i in 0..size as u64 {
            self.write_byte(addr.checked_add(i)?, (value >> (i * 8)) as u8)?;
        }
        Some(())
    }

    pub(super) fn read_byte(&self, addr: u64) -> Option<u8> {
        if let Some(overlay) = &self.overlay
            && let Some(byte) = overlay.get(addr)
        {
            return Some(byte);
        }
        if self.in_image(addr) {
            return self.image.get((addr - self.image_base) as usize).copied();
        }
        if let Some(offset) = addr.checked_sub(self.stack_base)
            && let Some(byte) = self.stack.get(offset as usize)
        {
            return Some(*byte);
        }
        for region in &self.extra {
            if let Some(offset) = region.offset(addr) {
                return region.read(offset);
            }
        }
        if let Some(seed) = self.unmapped {
            return Some(noise_byte(seed, addr));
        }
        self.outside?.byte(usize::try_from(addr).ok()?)
    }

    fn write_byte(&mut self, addr: u64, value: u8) -> Option<()> {
        if self.in_image(addr) {
            return self.overlay.as_mut()?.insert(addr, value);
        }
        if let Some(offset) = addr.checked_sub(self.stack_base)
            && let Some(byte) = self.stack.get_mut(offset as usize)
        {
            *byte = value;
            return Some(());
        }
        for region in &mut self.extra {
            if let Some(offset) = region.offset(addr) {
                return region.write(offset, value);
            }
        }

        if self.unmapped.is_none() {
            self.outside?.byte(usize::try_from(addr).ok()?)?;
        }
        self.overlay.as_mut()?.insert(addr, value)
    }
}

fn plausible(value: u64, bits: u32) -> bool {
    let ceiling = if bits == 64 {
        0x7FFF_FFFF_0000
    } else {
        0x8000_0000
    };
    (0x1_0000..ceiling).contains(&value)
}

pub(crate) const SEEDS: [u64; 3] = [0, 1, 2]; // flags clear, flags set, flags drawn

pub(crate) fn agreed<T: PartialEq>(mut runs: impl Iterator<Item = Option<T>>) -> Option<T> {
    let first = runs.next()??;
    runs.all(|run| run.as_ref() == Some(&first))
        .then_some(first)
}

const GOLDEN_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

fn finalised(mut mixed: u64) -> u64 {
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9); // splitmix64
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    mixed ^ (mixed >> 31)
}

fn drawn(seed: u64, index: u64) -> u64 {
    finalised((seed ^ index.rotate_left(32)).wrapping_add(GOLDEN_GAMMA))
}

fn poison(seed: u64, index: usize, bits: u32) -> u64 {
    let low = drawn(seed, index as u64 + 1);
    if bits == 64 {
        0xC000_0000_0000_0000 | (low & 0x0000_FFFF_FFFF_FFFF) // never a canonical address
    } else {
        0xC000_0000 | (low & 0x0FFF_FFFF) // above anything user mode maps
    }
}

pub(super) fn frame_mark(seed: u64, slot: u64, bits: u32) -> u64 {
    if bits == 64 {
        0xB000_0000_0000_0000 | (seed << 48) | (slot << 4) | 0x7
    } else {
        0xB000_0000 | ((seed << 24) & 0x0F00_0000) | (slot << 4) | 0x7
    }
}

fn noise_byte(seed: u64, addr: u64) -> u8 {
    finalised((addr ^ seed.rotate_left(32)).wrapping_mul(GOLDEN_GAMMA)) as u8
}

pub(crate) fn mask(value: u64, size: usize) -> u64 {
    value & Width(size).mask()
}

pub(crate) fn gpr_count(bits: u32) -> usize {
    if bits == 64 { 16 } else { 8 }
}
