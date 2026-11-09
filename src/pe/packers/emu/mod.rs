use std::collections::BTreeMap;

use iced_x86::{ConditionCode, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

mod fp;

const STACK_SIZE: u64 = 0x1_0000;
const STACK_BASE_64: u64 = 0x7FF0_0000_0000;
const STACK_BASE_32: u64 = 0x6000_0000;
const BUDGET: usize = 50_000;
const EXEC_STACK_SIZE: u64 = 0x20_0000; // a whole virtualized function needs far more stack than a stub
const FRAME_SLOTS: u64 = 8; // caller stack slots marked to prove the stub leaves the caller frame alone
const MIN_STUB_STEPS: usize = 8;
const WINDOW: usize = 16; // longest x86 instruction

#[derive(Default)]
struct Flags {
    cf: bool,
    of: bool,
    sf: bool,
    zf: bool,
    af: bool,
    pf: bool,
}

struct Cpu<'a> {
    gpr: [u64; 16],
    rip: u64,
    flags: Flags,
    image: &'a [u8],
    image_base: u64,
    stack: Vec<u8>,
    stack_base: u64,
    bits: u32,
    overlay: Option<BTreeMap<u64, u8>>,
    seg_base: u64,
    extra: Vec<(u64, Vec<u8>)>,
    x87: fp::X87,
    vex_scratch: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Failure {
    Stray,
    Mismatch,
}

pub(super) struct Resolved {
    pub(super) target: u64,
    pub(super) flow: Flow,
    pub(super) end: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Flow {
    Call,
    Jump,
    Load(u8),
}

pub(super) fn resolve(
    image: &[u8],
    image_base: u64,
    bits: u32,
    start: u64,
    call_site: u64,
    seed: u64,
) -> Result<Resolved, Failure> {
    Cpu::new(image, image_base, bits).run(start, call_site, seed)
}

pub(super) fn stub_return(image: &[u8], image_base: u64, bits: u32, site: u64) -> Option<u64> {
    let first = resolve(image, image_base, bits, site, site, 0).ok()?;
    let second = resolve(image, image_base, bits, site, site, 1).ok()?;
    (first.end == second.end).then_some(first.end)?
}

#[derive(Debug, PartialEq)]
struct Behaviour {
    returned: bool,
    left_to: Option<u64>,
    regs: Vec<u64>,
    writes: BTreeMap<u64, u8>,
    buffers: Vec<Vec<u8>>,
}

const POINTER_BUFFERS_64: u64 = 0x7FFD_0000_0000;
const POINTER_BUFFERS_32: u64 = 0x5F00_0000;
const POINTER_BUFFER: u64 = 0x1_0000;
const STACK_ARGS: u64 = 4;
const VEX_SCRATCH_SLOT: u64 = 32;
const VEX_SCRATCH_SIZE: usize = 64;

fn behaviour(image: &[u8], image_base: u64, bits: u32, entry: u64, pointers: bool) -> Behaviour {
    const BUDGET: usize = 200_000;
    let kept: &[usize] = if bits == 64 {
        &[0, 3, 4, 5, 6, 7, 12, 13, 14, 15] // rax rbx rsp rbp rsi rdi and r12 to r15
    } else {
        &[0, 3, 4, 5, 6, 7]
    };

    let mut cpu = Cpu::new_exec(image, image_base, bits);
    let stack = cpu.gpr[4];
    cpu.seed(u64::from(pointers));
    cpu.gpr[4] = stack;

    let first = if bits == 64 {
        POINTER_BUFFERS_64
    } else {
        POINTER_BUFFERS_32
    };
    cpu.vex_scratch = first + VEX_SCRATCH_SLOT * POINTER_BUFFER;
    cpu.extra.push((cpu.vex_scratch, vec![0; VEX_SCRATCH_SIZE]));

    let synthetic = cpu.extra.len(); // the teb and peb new_exec maps which are not the function doing
    if pointers {
        let ptr = u64::from(bits / 8);
        let regs = cpu.gpr_count() as u64;
        let pointer = |k: u64| first + k * POINTER_BUFFER + POINTER_BUFFER / 2;

        for k in 0..regs + STACK_ARGS {
            cpu.extra
                .push((first + k * POINTER_BUFFER, vec![0; POINTER_BUFFER as usize]));
        }
        for reg in (0..regs).filter(|&reg| reg != 4) {
            cpu.gpr[reg as usize] = pointer(reg);
        }
        for k in 0..STACK_ARGS {
            cpu.write_mem(stack + k * ptr, ptr as usize, pointer(regs + k));
        }
    }

    let (returned, stop) = cpu.run_function(entry, BUDGET);
    Behaviour {
        returned,
        left_to: (!cpu.in_image(stop)).then_some(stop),
        regs: kept.iter().map(|&reg| cpu.gpr[reg]).collect(),
        buffers: cpu
            .extra
            .split_off(synthetic)
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect(),
        writes: cpu.overlay.unwrap_or_default(),
    }
}

pub(super) fn same_behaviour(
    original: &[u8],
    patched: &[u8],
    image_base: u64,
    bits: u32,
    entry: u64,
) -> bool {
    let runs: Vec<(Behaviour, Behaviour)> = [false, true]
        .into_iter()
        .map(|pointers| {
            (
                behaviour(original, image_base, bits, entry, pointers),
                behaviour(patched, image_base, bits, entry, pointers),
            )
        })
        .collect();

    let alike = runs.iter().all(|(vmp, clean)| vmp == clean);
    let conclusive = runs
        .iter()
        .any(|(vmp, _)| vmp.returned || vmp.left_to.is_some());
    alike && conclusive
}

impl<'a> Cpu<'a> {
    fn new(image: &'a [u8], image_base: u64, bits: u32) -> Self {
        let stack_base = if bits == 64 {
            STACK_BASE_64
        } else {
            STACK_BASE_32
        };
        let mut cpu = Cpu {
            gpr: [0; 16],
            rip: 0,
            flags: Flags::default(),
            image,
            image_base,
            stack: vec![0; STACK_SIZE as usize],
            stack_base,
            bits,
            overlay: None,
            seg_base: 0,
            extra: Vec::new(),
            x87: fp::X87 {
                cw: 0x037F,
                ..Default::default()
            },
            vex_scratch: 0,
        };
        cpu.gpr[4] = stack_base + STACK_SIZE / 2; // rsp mid stack so push and pop both have room
        cpu
    }

    fn new_exec(image: &'a [u8], image_base: u64, bits: u32) -> Self {
        let stack_base = if bits == 64 {
            STACK_BASE_64
        } else {
            STACK_BASE_32
        };
        let teb_base = 0x7FFE_0000_0000u64;
        let peb_base = teb_base + 0x4000;
        let mut cpu = Cpu {
            gpr: [0; 16],
            rip: 0,
            flags: Flags::default(),
            image,
            image_base,
            stack: vec![0; EXEC_STACK_SIZE as usize],
            stack_base,
            bits,
            overlay: Some(BTreeMap::new()),
            seg_base: teb_base,
            extra: vec![(teb_base, vec![0; 0x2000]), (peb_base, vec![0; 0x2000])],
            x87: fp::X87 {
                cw: 0x037F,
                ..Default::default()
            },
            vex_scratch: 0,
        };
        cpu.gpr[4] = stack_base + EXEC_STACK_SIZE / 2;

        let ptr = u64::from(bits / 8);
        let stack_top = stack_base + EXEC_STACK_SIZE;
        let (self_off, peb_off, base_off, limit_off) = if bits == 64 {
            (0x30, 0x60, 0x08, 0x10)
        } else {
            (0x18, 0x30, 0x04, 0x08)
        };
        cpu.write_mem(teb_base + self_off, ptr as usize, teb_base);
        cpu.write_mem(teb_base + peb_off, ptr as usize, peb_base);
        cpu.write_mem(teb_base + base_off, ptr as usize, stack_top);
        cpu.write_mem(teb_base + limit_off, ptr as usize, stack_base);
        cpu.write_mem(peb_base + 0x02, 1, 0); // BeingDebugged

        cpu
    }

    fn in_image(&self, addr: u64) -> bool {
        addr >= self.image_base && addr < self.image_base + self.image.len() as u64
    }

    fn fetch(&self) -> Option<Instruction> {
        let code = self.code_at(self.rip)?;
        let mut decoder = Decoder::with_ip(self.bits, code, self.rip, DecoderOptions::NONE);
        let insn = decoder.decode();
        (!insn.is_invalid()).then_some(insn)
    }

    fn code_at(&self, addr: u64) -> Option<&[u8]> {
        let (bytes, start): (&[u8], usize) = if self.in_image(addr) {
            (self.image, (addr - self.image_base) as usize)
        } else {
            self.extra.iter().find_map(|(base, bytes)| {
                let start = addr.checked_sub(*base)? as usize;
                (start < bytes.len()).then_some((bytes.as_slice(), start))
            })?
        };
        bytes.get(start..start.saturating_add(WINDOW).min(bytes.len()))
    }

    fn run_function(&mut self, entry: u64, budget: usize) -> (bool, u64) {
        let ptr = u64::from(self.bits / 8);
        let sentinel = if self.bits == 64 {
            0xCAFE_BABE_D00D_0000
        } else {
            0xCAFE_B000
        };

        self.gpr[4] = self.gpr[4].wrapping_sub(ptr);
        let rsp = self.gpr[4];
        if self.write_mem(rsp, ptr as usize, sentinel).is_none() {
            return (false, rsp);
        }
        self.rip = entry;

        for _ in 0..budget {
            if self.rip == sentinel {
                return (true, self.rip);
            }
            let Some(insn) = self.fetch() else {
                return (false, self.rip);
            };
            if self.step(&insn).is_none() {
                return (false, self.rip);
            }
        }
        (false, self.rip)
    }

    fn run(&mut self, start: u64, call_site: u64, seed: u64) -> Result<Resolved, Failure> {
        let width = (self.bits / 8) as usize;
        let ptr = width as u64;

        let seeds = self.seed(seed);
        let frame = self.gpr[4];
        let marks: Vec<u64> = (0..FRAME_SLOTS)
            .map(|slot| frame_mark(seed, slot, self.bits))
            .collect();
        for (slot, mark) in (0u64..).zip(&marks) {
            self.write_mem(frame + slot * ptr, width, *mark)
                .ok_or(Failure::Stray)?;
        }

        let returns = call_site.saturating_add(5)..=call_site.saturating_add(7);
        self.rip = start;

        for steps in 0..BUDGET {
            let left = returns.contains(&self.rip) || !self.in_image(self.rip);
            if left && steps < MIN_STUB_STEPS {
                return Err(Failure::Stray);
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
                    Failure::Stray
                });
            }

            let offset = (self.rip - self.image_base) as usize;
            let end = offset.saturating_add(WINDOW).min(self.image.len());
            let code = self.image.get(offset..end).ok_or(Failure::Stray)?;
            let mut decoder = Decoder::with_ip(self.bits, code, self.rip, DecoderOptions::NONE);
            let insn = decoder.decode();
            if insn.is_invalid() {
                return Err(Failure::Stray);
            }
            self.step(&insn).ok_or(Failure::Stray)?;
        }
        Err(Failure::Stray)
    }

    fn returned(&self, frame: u64, marks: &[u64], seeds: &[u64; 16]) -> Option<Resolved> {
        if self.gpr[4] != frame || !self.frame_intact(frame, marks) {
            return None;
        }

        let changed: Vec<usize> = self.changed(seeds).collect();
        let reg = match changed[..] {
            [only] => only,
            _ => match changed
                .iter()
                .filter(|&&reg| !self.scratch(reg))
                .collect::<Vec<_>>()[..]
            {
                [&only] => only,
                _ => return None,
            },
        };

        Some(Resolved {
            target: mask(self.gpr[reg], (self.bits / 8) as usize),
            flow: Flow::Load(reg as u8),
            end: Some(self.rip),
        })
    }

    fn escaped(&self, frame: u64, marks: &[u64], seeds: &[u64; 16]) -> Option<Resolved> {
        let width = (self.bits / 8) as usize;
        if !self.frame_intact(frame, marks) || self.changed(seeds).any(|reg| !self.scratch(reg)) {
            return None;
        }

        let sp = self.gpr[4];
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

    fn seed(&mut self, seed: u64) -> [u64; 16] {
        for index in 0..self.gpr_count() {
            if index != 4 {
                self.gpr[index] = register_seed(seed, index, self.bits);
            }
        }

        if seed & 1 == 1 {
            self.flags = Flags {
                cf: true,
                of: true,
                sf: true,
                zf: true,
                af: true,
                pf: true,
            };
        }

        self.gpr
    }

    fn gpr_count(&self) -> usize {
        if self.bits == 64 { 16 } else { 8 }
    }

    fn scratch(&self, reg: usize) -> bool {
        match self.bits {
            64 => matches!(reg, 0 | 10 | 11), // rax r10 and r11
            _ => reg == 0,                    // eax
        }
    }

    fn changed<'s>(&'s self, seeds: &'s [u64; 16]) -> impl Iterator<Item = usize> + 's {
        let width = (self.bits / 8) as usize;
        (0..self.gpr_count()).filter(move |&index| {
            index != 4 && mask(self.gpr[index], width) != mask(seeds[index], width)
        })
    }

    fn frame_intact(&self, frame: u64, marks: &[u64]) -> bool {
        let width = (self.bits / 8) as usize;
        (0u64..)
            .zip(marks)
            .all(|(slot, mark)| self.mem(frame + slot * width as u64, width) == Some(*mark))
    }

    fn mem(&self, addr: u64, size: usize) -> Option<u64> {
        if self.overlay.is_some() {
            let mut value = 0u64;
            for i in 0..size as u64 {
                value |= u64::from(self.read_byte(addr.checked_add(i)?)?) << (i * 8);
            }
            return Some(value);
        }
        let bytes = self.region(addr, size)?;
        let mut value = 0u64;
        for (i, byte) in bytes.iter().enumerate() {
            value |= u64::from(*byte) << (i * 8);
        }
        Some(value)
    }

    fn write_mem(&mut self, addr: u64, size: usize, value: u64) -> Option<()> {
        if self.overlay.is_some() {
            for i in 0..size as u64 {
                self.write_byte(addr.checked_add(i)?, (value >> (i * 8)) as u8)?;
            }
            return Some(());
        }
        let dst = self.region_mut(addr, size)?;
        for (i, byte) in dst.iter_mut().enumerate() {
            *byte = (value >> (i * 8)) as u8;
        }
        Some(())
    }

    fn read_byte(&self, addr: u64) -> Option<u8> {
        if let Some(overlay) = &self.overlay
            && let Some(byte) = overlay.get(&addr)
        {
            return Some(*byte);
        }
        if self.in_image(addr) {
            return self.image.get((addr - self.image_base) as usize).copied();
        }
        if let Some(offset) = addr.checked_sub(self.stack_base)
            && let Some(byte) = self.stack.get(offset as usize)
        {
            return Some(*byte);
        }
        for (base, region) in &self.extra {
            if let Some(byte) = addr.checked_sub(*base).and_then(|o| region.get(o as usize)) {
                return Some(*byte);
            }
        }
        None
    }

    fn write_byte(&mut self, addr: u64, value: u8) -> Option<()> {
        if self.in_image(addr) {
            self.overlay.as_mut()?.insert(addr, value);
            return Some(());
        }
        if let Some(offset) = addr.checked_sub(self.stack_base)
            && let Some(byte) = self.stack.get_mut(offset as usize)
        {
            *byte = value;
            return Some(());
        }
        for (base, region) in &mut self.extra {
            if let Some(byte) = addr
                .checked_sub(*base)
                .and_then(|o| region.get_mut(o as usize))
            {
                *byte = value;
                return Some(());
            }
        }
        None
    }

    fn region(&self, addr: u64, size: usize) -> Option<&[u8]> {
        if self.in_image(addr) {
            let start = (addr - self.image_base) as usize;
            return self.image.get(start..start.checked_add(size)?);
        }
        let start = addr.checked_sub(self.stack_base)? as usize;
        self.stack.get(start..start.checked_add(size)?)
    }

    fn region_mut(&mut self, addr: u64, size: usize) -> Option<&mut [u8]> {
        let start = addr.checked_sub(self.stack_base)? as usize;
        self.stack.get_mut(start..start.checked_add(size)?)
    }

    fn reg(&self, r: Register) -> u64 {
        if r == Register::RIP {
            return self.rip;
        }
        let Some(idx) = slot(r) else { return 0 };
        let full = self.gpr.get(idx).copied().unwrap_or(0);
        if high8(r) {
            return (full >> 8) & 0xFF;
        }
        mask(full, r.size())
    }

    fn set_reg(&mut self, r: Register, value: u64) {
        let Some(idx) = slot(r) else { return };
        let Some(cell) = self.gpr.get_mut(idx) else {
            return;
        };
        match r.size() {
            8 => *cell = value,
            4 => *cell = value & 0xFFFF_FFFF, // 32 bit writes clear the upper half
            _ if high8(r) => *cell = (*cell & !0xFF00) | ((value & 0xFF) << 8),
            n => {
                let bits = n * 8;
                let m = (1u64 << bits) - 1;
                *cell = (*cell & !m) | (value & m);
            }
        }
    }

    fn ea(&self, insn: &Instruction) -> u64 {
        let seg = match insn.memory_segment() {
            Register::GS | Register::FS => self.seg_base,
            _ => 0,
        };
        if insn.memory_base() == Register::RIP {
            return seg.wrapping_add(insn.memory_displacement64());
        }
        let mut addr = 0u64;
        if insn.memory_base() != Register::None {
            addr = addr.wrapping_add(self.reg(insn.memory_base()));
        }
        if insn.memory_index() != Register::None {
            addr = addr.wrapping_add(
                self.reg(insn.memory_index())
                    .wrapping_mul(u64::from(insn.memory_index_scale())),
            );
        }
        seg.wrapping_add(addr.wrapping_add(insn.memory_displacement64()) & self.addr_mask())
    }

    fn addr_mask(&self) -> u64 {
        if self.bits == 64 {
            u64::MAX
        } else {
            0xFFFF_FFFF
        }
    }

    fn op_size(&self, insn: &Instruction, i: u32) -> usize {
        match insn.op_kind(i) {
            OpKind::Register => insn.op_register(i).size(),
            OpKind::Memory => insn.memory_size().size(),
            _ => (self.bits / 8) as usize,
        }
    }

    fn get(&self, insn: &Instruction, i: u32) -> Option<u64> {
        match insn.op_kind(i) {
            OpKind::Register => Some(self.reg(insn.op_register(i))),
            OpKind::Memory => self.mem(self.ea(insn), insn.memory_size().size()),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Some(insn.near_branch_target())
            }
            _ => Some(insn.immediate(i)),
        }
    }

    fn set(&mut self, insn: &Instruction, i: u32, value: u64) -> Option<()> {
        match insn.op_kind(i) {
            OpKind::Register => {
                self.set_reg(insn.op_register(i), value);
                Some(())
            }
            OpKind::Memory => self.write_mem(self.ea(insn), insn.memory_size().size(), value),
            _ => None,
        }
    }

    fn push(&mut self, value: u64) -> Option<()> {
        let width = u64::from(self.bits / 8);
        self.gpr[4] = self.gpr[4].wrapping_sub(width);
        self.write_mem(self.gpr[4], width as usize, value)
    }

    fn pop(&mut self) -> Option<u64> {
        let width = u64::from(self.bits / 8);
        let value = self.mem(self.gpr[4], width as usize)?;
        self.gpr[4] = self.gpr[4].wrapping_add(width);
        Some(value)
    }

    fn step(&mut self, insn: &Instruction) -> Option<()> {
        self.rip = insn.next_ip();
        match insn.mnemonic() {
            Mnemonic::Nop | Mnemonic::Prefetchw | Mnemonic::Cld | Mnemonic::Std => Some(()),
            Mnemonic::Cdq => {
                let fill = if self.reg(Register::EAX) & 0x8000_0000 != 0 {
                    0xFFFF_FFFF
                } else {
                    0
                };
                self.set_reg(Register::EDX, fill);
                Some(())
            }
            Mnemonic::Cqo => {
                let fill = if self.reg(Register::RAX) & 0x8000_0000_0000_0000 != 0 {
                    u64::MAX
                } else {
                    0
                };
                self.set_reg(Register::RDX, fill);
                Some(())
            }
            Mnemonic::Cwd => {
                let fill = if self.reg(Register::AX) & 0x8000 != 0 {
                    0xFFFF
                } else {
                    0
                };
                self.set_reg(Register::DX, fill);
                Some(())
            }
            Mnemonic::Mov | Mnemonic::Movzx => {
                let v = self.get(insn, 1)?;
                self.set(insn, 0, v)
            }
            Mnemonic::Movsx | Mnemonic::Movsxd => {
                let v = sign_extend(self.get(insn, 1)?, self.op_size(insn, 1));
                self.set(insn, 0, v)
            }
            Mnemonic::Lea => {
                let ea = self.ea(insn);
                self.set(insn, 0, ea)
            }
            Mnemonic::Push => {
                let size = insn.stack_pointer_increment().unsigned_abs() as u64;
                let v = self.get(insn, 0)?;
                self.gpr[4] = self.gpr[4].wrapping_sub(size);
                self.write_mem(self.gpr[4], size as usize, v)
            }
            Mnemonic::Pop => {
                let size = insn.stack_pointer_increment().unsigned_abs() as u64;
                let v = self.mem(self.gpr[4], size as usize)?;
                self.gpr[4] = self.gpr[4].wrapping_add(size);
                self.set(insn, 0, v)
            }
            Mnemonic::Add => self.arith(insn, false, false),
            Mnemonic::Adc => self.arith(insn, false, true),
            Mnemonic::Sub => self.arith(insn, true, false),
            Mnemonic::Sbb => self.arith(insn, true, true),
            Mnemonic::Cmp => {
                let (a, b) = (self.get(insn, 0)?, self.get(insn, 1)?);
                self.sub(a, b, false, self.op_size(insn, 0));
                Some(())
            }
            Mnemonic::Test => {
                let r = self.get(insn, 0)? & self.get(insn, 1)?;
                self.logic_flags(r, self.op_size(insn, 0));
                Some(())
            }
            Mnemonic::And | Mnemonic::Or | Mnemonic::Xor => {
                let (a, b) = (self.get(insn, 0)?, self.get(insn, 1)?);
                let r = match insn.mnemonic() {
                    Mnemonic::And => a & b,
                    Mnemonic::Or => a | b,
                    _ => a ^ b,
                };
                self.logic_flags(r, self.op_size(insn, 0));
                self.set(insn, 0, r)
            }
            Mnemonic::Not => {
                let v = !self.get(insn, 0)?;
                self.set(insn, 0, v)
            }
            Mnemonic::Neg => {
                let a = self.get(insn, 0)?;
                let r = self.sub(0, a, false, self.op_size(insn, 0));
                self.flags.cf = a != 0;
                self.set(insn, 0, r)
            }
            Mnemonic::Inc => {
                let cf = self.flags.cf;
                let r = self.add(self.get(insn, 0)?, 1, false, self.op_size(insn, 0));
                self.flags.cf = cf; // inc leaves cf
                self.set(insn, 0, r)
            }
            Mnemonic::Dec => {
                let cf = self.flags.cf;
                let r = self.sub(self.get(insn, 0)?, 1, false, self.op_size(insn, 0));
                self.flags.cf = cf;
                self.set(insn, 0, r)
            }
            Mnemonic::Xchg => {
                let (a, b) = (self.get(insn, 0)?, self.get(insn, 1)?);
                self.set(insn, 0, b)?;
                self.set(insn, 1, a)
            }
            Mnemonic::Xadd => {
                let size = self.op_size(insn, 0);
                let memory = insn.op0_kind() == OpKind::Memory;
                let address = memory.then(|| self.ea(insn));
                let (dst, src) = (self.get(insn, 0)?, self.get(insn, 1)?);
                let sum = self.add(dst, src, false, size);
                self.set(insn, 1, dst)?;
                match address {
                    Some(address) => self.write_mem(address, size, sum),
                    None => self.set(insn, 0, sum),
                }
            }
            Mnemonic::Bswap => {
                let size = self.op_size(insn, 0);
                let v = self.get(insn, 0)?;
                let swapped = v.to_le_bytes();
                let mut out = 0u64;
                for i in 0..size {
                    out |= u64::from(swapped.get(size - 1 - i).copied().unwrap_or(0)) << (i * 8);
                }
                self.set(insn, 0, out)
            }
            Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc => {
                let a = self.get(insn, 0)?;
                let bit = self.get(insn, 1)? % (self.op_size(insn, 0) as u64 * 8);
                self.flags.cf = (a >> bit) & 1 == 1;
                let r = match insn.mnemonic() {
                    Mnemonic::Bts => a | (1 << bit),
                    Mnemonic::Btr => a & !(1 << bit),
                    Mnemonic::Btc => a ^ (1 << bit),
                    _ => return Some(()),
                };
                self.set(insn, 0, r)
            }
            Mnemonic::Cdqe | Mnemonic::Cwde | Mnemonic::Cbw => {
                let (from, to) = match insn.mnemonic() {
                    Mnemonic::Cdqe => (Register::EAX, Register::RAX),
                    Mnemonic::Cwde => (Register::AX, Register::EAX),
                    _ => (Register::AL, Register::AX),
                };
                let v = sign_extend(self.reg(from), from.size());
                self.set_reg(to, v);
                Some(())
            }
            Mnemonic::Sahf => {
                self.set_flags(self.reg(Register::AH));
                Some(())
            }
            Mnemonic::Lahf => {
                self.set_reg(Register::AH, self.flags_bits() & 0xFF);
                Some(())
            }
            Mnemonic::Pushfd | Mnemonic::Pushfq => self.push(self.flags_bits()),
            Mnemonic::Popfd | Mnemonic::Popfq => {
                let v = self.pop()?;
                self.set_flags(v);
                Some(())
            }
            Mnemonic::Shl
            | Mnemonic::Sal
            | Mnemonic::Sar
            | Mnemonic::Shr
            | Mnemonic::Rol
            | Mnemonic::Ror => self.shift(insn),
            Mnemonic::Rcl | Mnemonic::Rcr => self.rotate_carry(insn),
            Mnemonic::Shld => self.double_shift(insn, true),
            Mnemonic::Shrd => self.double_shift(insn, false),
            Mnemonic::Imul => self.imul(insn),
            Mnemonic::Mul => self.mul(insn),
            Mnemonic::Div => self.div(insn),
            Mnemonic::Idiv => self.idiv(insn),
            Mnemonic::Clc => {
                self.flags.cf = false;
                Some(())
            }
            Mnemonic::Stc => {
                self.flags.cf = true;
                Some(())
            }
            Mnemonic::Cmc => {
                self.flags.cf = !self.flags.cf;
                Some(())
            }
            Mnemonic::Call => {
                self.push(insn.next_ip())?;
                self.rip = self.get(insn, 0)?;
                Some(())
            }
            Mnemonic::Syscall => {
                self.gpr[11] = self.flags_bits();
                self.gpr[1] = self.rip;
                self.gpr[0] = 0;
                Some(())
            }
            Mnemonic::Jmp
                if matches!(insn.op0_kind(), OpKind::FarBranch16 | OpKind::FarBranch32) =>
            {
                self.gpr[0] = 0;
                self.rip = self.pop()?;
                Some(())
            }
            Mnemonic::Jmp => {
                self.rip = self.get(insn, 0)?;
                Some(())
            }
            Mnemonic::Ret => {
                self.rip = self.pop()?;
                if insn.op_count() > 0 {
                    self.gpr[4] = self.gpr[4].wrapping_add(self.get(insn, 0)?);
                }
                Some(())
            }
            m if is_jcc(m) => {
                if self.cond(insn) {
                    self.rip = self.get(insn, 0)?;
                }
                Some(())
            }
            m if is_setcc(m) => {
                let value = u64::from(self.cond(insn));
                self.set(insn, 0, value)
            }
            m if is_cmovcc(m) => {
                let source = if self.cond(insn) { 1 } else { 0 };
                let v = self.get(insn, source)?;
                self.set(insn, 0, v)
            }
            Mnemonic::Cpuid => {
                let (a, b, c, d) = host_cpuid(
                    self.reg(Register::RAX) as u32,
                    self.reg(Register::RCX) as u32,
                );
                self.set_reg(Register::RAX, u64::from(a));
                self.set_reg(Register::RBX, u64::from(b));
                self.set_reg(Register::RCX, u64::from(c));
                self.set_reg(Register::RDX, u64::from(d));
                Some(())
            }
            Mnemonic::Rdtsc | Mnemonic::Rdtscp => {
                self.set_reg(Register::RAX, 0);
                self.set_reg(Register::RDX, 0);
                Some(())
            }
            Mnemonic::In => self.set(insn, 0, 0),
            Mnemonic::Out
            | Mnemonic::Pause
            | Mnemonic::Lfence
            | Mnemonic::Mfence
            | Mnemonic::Sfence => Some(()),
            _ if is_string_op(insn) => self.string_op(insn),
            Mnemonic::Leave => {
                self.gpr[4] = self.gpr[5];
                let v = self.pop()?;
                self.gpr[5] = v;
                Some(())
            }
            Mnemonic::Bsf
            | Mnemonic::Bsr
            | Mnemonic::Tzcnt
            | Mnemonic::Lzcnt
            | Mnemonic::Popcnt => self.bit_scan(insn),
            Mnemonic::Cmpxchg => {
                let size = self.op_size(insn, 0);
                let (dst, src) = (self.get(insn, 0)?, self.get(insn, 1)?);
                let acc = self.reg(acc_reg(size, false));
                self.sub(acc, dst, false, size);
                if acc == dst {
                    self.set(insn, 0, src)
                } else {
                    self.set_reg(acc_reg(size, false), dst);
                    Some(())
                }
            }
            Mnemonic::Movbe => {
                let size = self.op_size(insn, 0);
                let v = self.get(insn, 1)?.to_le_bytes();
                let mut out = 0u64;
                for i in 0..size {
                    out |= u64::from(v[size - 1 - i]) << (i * 8);
                }
                self.set(insn, 0, out)
            }
            Mnemonic::Endbr64 | Mnemonic::Endbr32 => Some(()),
            Mnemonic::Pushad => {
                let sp = self.gpr[4];
                for value in [
                    self.gpr[0],
                    self.gpr[1],
                    self.gpr[2],
                    self.gpr[3],
                    sp,
                    self.gpr[5],
                    self.gpr[6],
                    self.gpr[7],
                ] {
                    self.push(value)?;
                }
                Some(())
            }
            Mnemonic::Popad => {
                for slot in [7usize, 6, 5, 4, 3, 2, 1, 0] {
                    let v = self.pop()?;
                    if slot != 4 {
                        self.gpr[slot] = v;
                    }
                }
                Some(())
            }
            _ if fp::is_x87(insn.mnemonic()) => self.x87_step(insn),
            _ => None,
        }
    }

    fn string_op(&mut self, insn: &Instruction) -> Option<()> {
        let (size, kind) = string_shape(insn.mnemonic())?;
        let rep = insn.has_rep_prefix() || insn.has_repe_prefix() || insn.has_repne_prefix();
        let mask = self.addr_mask();
        let step = size as u64;
        let mut count = string_count(self, insn);
        if count > 1 << 24 {
            return None;
        }
        while count > 0 {
            let (si, di) = (self.gpr[6], self.gpr[7]);
            match kind {
                "Movs" => {
                    let v = self.mem(si, size)?;
                    self.write_mem(di, size, v)?;
                }
                "Stos" => self.write_mem(di, size, self.gpr[0])?,
                "Lods" => self.set_reg(acc_reg(size, false), self.mem(si, size)?),
                "Scas" => {
                    let v = self.mem(di, size)?;
                    self.sub(self.gpr[0], v, false, size);
                }
                _ => {
                    let (a, b) = (self.mem(si, size)?, self.mem(di, size)?);
                    self.sub(a, b, false, size);
                }
            }
            if matches!(kind, "Movs" | "Lods" | "Cmps") {
                self.gpr[6] = si.wrapping_add(step) & mask;
            }
            if matches!(kind, "Movs" | "Stos" | "Scas" | "Cmps") {
                self.gpr[7] = di.wrapping_add(step) & mask;
            }
            count -= 1;
            if rep {
                self.gpr[1] = count;
            }
            let compare = matches!(kind, "Scas" | "Cmps");
            if compare
                && ((insn.has_repe_prefix() && !self.flags.zf)
                    || (insn.has_repne_prefix() && self.flags.zf))
            {
                break;
            }
        }
        Some(())
    }

    fn bit_scan(&mut self, insn: &Instruction) -> Option<()> {
        let size = self.op_size(insn, 0);
        let bits = size as u32 * 8;
        let v = self.get(insn, 1)? & width_mask(size);
        let leading = v.leading_zeros() - (64 - bits);
        let r = match insn.mnemonic() {
            Mnemonic::Bsf | Mnemonic::Bsr => {
                self.flags.zf = v == 0;
                if v == 0 {
                    return Some(());
                }
                if insn.mnemonic() == Mnemonic::Bsf {
                    v.trailing_zeros()
                } else {
                    bits - 1 - leading
                }
            }
            Mnemonic::Tzcnt => {
                let r = if v == 0 { bits } else { v.trailing_zeros() };
                self.flags.cf = v == 0;
                self.flags.zf = r == 0;
                r
            }
            Mnemonic::Lzcnt => {
                let r = if v == 0 { bits } else { leading };
                self.flags.cf = v == 0;
                self.flags.zf = r == 0;
                r
            }
            _ => {
                self.flags.zf = v == 0;
                self.flags.cf = false;
                self.flags.of = false;
                self.flags.sf = false;
                self.flags.pf = false;
                self.flags.af = false;
                v.count_ones()
            }
        };
        self.set(insn, 0, u64::from(r))
    }

    fn arith(&mut self, insn: &Instruction, subtract: bool, carry: bool) -> Option<()> {
        let (a, b) = (self.get(insn, 0)?, self.get(insn, 1)?);
        let cin = carry && self.flags.cf;
        let size = self.op_size(insn, 0);
        let r = if subtract {
            self.sub(a, b, cin, size)
        } else {
            self.add(a, b, cin, size)
        };
        self.set(insn, 0, r)
    }

    fn add(&mut self, a: u64, b: u64, cin: bool, size: usize) -> u64 {
        let bits = size * 8;
        let m = width_mask(size);
        let full = u128::from(a) + u128::from(b) + u128::from(cin);
        let r = (full as u64) & m;
        self.flags.cf = full > u128::from(m);
        let sign = 1u64 << (bits - 1);
        self.flags.of = ((!(a ^ b)) & (a ^ r) & sign) != 0;
        self.flags.af = ((a ^ b ^ r) >> 4) & 1 == 1;
        self.zsp(r, size);
        r
    }

    fn sub(&mut self, a: u64, b: u64, cin: bool, size: usize) -> u64 {
        let bits = size * 8;
        let m = width_mask(size);
        let r = a.wrapping_sub(b).wrapping_sub(u64::from(cin)) & m;
        self.flags.cf = u128::from(a) < u128::from(b) + u128::from(cin);
        let sign = 1u64 << (bits - 1);
        self.flags.of = ((a ^ b) & (a ^ r) & sign) != 0;
        self.flags.af = ((a ^ b ^ r) >> 4) & 1 == 1;
        self.zsp(r, size);
        r
    }

    fn shift(&mut self, insn: &Instruction) -> Option<()> {
        let size = self.op_size(insn, 0);
        let bits = (size * 8) as u64;
        let m = width_mask(size);
        let a = self.get(insn, 0)? & m;
        let count = self.get(insn, 1)? & if size == 8 { 0x3F } else { 0x1F };

        let mnemonic = insn.mnemonic();
        let r = match mnemonic {
            Mnemonic::Shl | Mnemonic::Sal => {
                if count != 0 && count <= bits {
                    self.flags.cf = (a >> (bits - count)) & 1 == 1;
                }
                if count < bits { (a << count) & m } else { 0 }
            }
            Mnemonic::Shr => {
                if count != 0 {
                    self.flags.cf = (a >> (count - 1)) & 1 == 1;
                }
                if count < bits { a >> count } else { 0 }
            }
            Mnemonic::Sar => {
                if count != 0 {
                    self.flags.cf = (a >> (count - 1).min(bits - 1)) & 1 == 1;
                }
                let signed = sign_extend(a, size) as i64;
                (signed >> count.min(bits - 1)) as u64 & m
            }
            Mnemonic::Rol => {
                let c = count % bits;
                let r = if c == 0 {
                    a
                } else {
                    ((a << c) | (a >> (bits - c))) & m
                };
                if count != 0 {
                    self.flags.cf = r & 1 == 1;
                }
                r
            }
            _ => {
                let c = count % bits;
                let r = if c == 0 {
                    a
                } else {
                    ((a >> c) | (a << (bits - c))) & m
                };
                if count != 0 {
                    self.flags.cf = (r >> (bits - 1)) & 1 == 1;
                }
                r
            }
        };

        if count != 0 {
            self.flags.of = match mnemonic {
                Mnemonic::Shl | Mnemonic::Sal | Mnemonic::Rol => {
                    top_bit(a, size) ^ next_bit(a, size)
                }
                Mnemonic::Shr => top_bit(a, size),
                Mnemonic::Sar => false,
                _ => (a & 1 == 1) ^ top_bit(a, size),
            };
            if matches!(
                mnemonic,
                Mnemonic::Shl | Mnemonic::Sal | Mnemonic::Shr | Mnemonic::Sar
            ) {
                self.zsp(r, size);
            }
        }

        self.set(insn, 0, r)
    }

    fn double_shift(&mut self, insn: &Instruction, left: bool) -> Option<()> {
        let size = self.op_size(insn, 0);
        let bits = (size * 8) as u64;
        let m = width_mask(size);
        let dst = self.get(insn, 0)? & m;
        let src = self.get(insn, 1)? & m;
        let count = self.get(insn, 2)? & if size == 8 { 0x3F } else { 0x1F };

        if count == 0 || count > bits {
            return self.set(insn, 0, dst);
        }

        let r = if left {
            self.flags.cf = (dst >> (bits - count)) & 1 == 1;
            ((dst << count) | (src >> (bits - count))) & m
        } else {
            self.flags.cf = (dst >> (count - 1)) & 1 == 1;
            ((dst >> count) | (src << (bits - count))) & m
        };

        self.flags.of = if left {
            top_bit(dst, size) ^ next_bit(dst, size)
        } else {
            (src & 1 == 1) ^ top_bit(dst, size)
        };
        self.zsp(r, size);
        self.set(insn, 0, r)
    }

    fn rotate_carry(&mut self, insn: &Instruction) -> Option<()> {
        let size = self.op_size(insn, 0);
        let bits = (size * 8) as u32;
        let m = width_mask(size);
        let operand = u128::from(self.get(insn, 0)? & m);
        let raw = self.get(insn, 1)? & if size == 8 { 0x3F } else { 0x1F };
        let count = (raw as u32) % (bits + 1);

        if count == 0 {
            return self.set(insn, 0, operand as u64 & m);
        }

        let left = insn.mnemonic() == Mnemonic::Rcl;
        let carry_in = self.flags.cf;
        let span = (1u128 << (bits + 1)) - 1;
        let mut value = operand | (u128::from(carry_in) << bits);
        for _ in 0..count {
            value = if left {
                let top = (value >> bits) & 1;
                ((value << 1) & span) | top
            } else {
                let bottom = value & 1;
                (value >> 1) | (bottom << bits)
            };
        }

        self.flags.cf = ((value >> bits) & 1) == 1;
        let original = operand as u64;
        self.flags.of = if left {
            top_bit(original, size) ^ next_bit(original, size)
        } else {
            carry_in ^ top_bit(original, size)
        };
        self.set(insn, 0, value as u64 & m)
    }

    fn imul(&mut self, insn: &Instruction) -> Option<()> {
        let size = self.op_size(insn, 0);
        let widen = |value: u64, bytes: usize| sign_extend(value, bytes) as i64 as i128;

        let overflow = match insn.op_count() {
            1 => {
                let src = widen(self.get(insn, 0)?, size);
                let full = widen(self.reg(acc_reg(size, false)), size).wrapping_mul(src);
                let low = (full as u64) & width_mask(size);

                if size == 1 {
                    self.set_reg(Register::AX, (full as u64) & 0xFFFF);
                } else {
                    self.set_reg(acc_reg(size, false), low);
                    self.set_reg(
                        acc_reg(size, true),
                        ((full >> (size * 8)) as u64) & width_mask(size),
                    );
                }

                full != widen(low, size)
            }
            2 => {
                let full =
                    widen(self.get(insn, 0)?, size).wrapping_mul(widen(self.get(insn, 1)?, size));
                let low = (full as u64) & width_mask(size);
                self.set(insn, 0, low)?;
                full != widen(low, size)
            }
            _ => {
                let full =
                    widen(self.get(insn, 1)?, size).wrapping_mul(self.get(insn, 2)? as i64 as i128);
                let low = (full as u64) & width_mask(size);
                self.set(insn, 0, low)?;
                full != widen(low, size)
            }
        };

        self.flags.cf = overflow;
        self.flags.of = overflow;
        Some(())
    }

    fn mul(&mut self, insn: &Instruction) -> Option<()> {
        let size = self.op_size(insn, 0);
        let src = (self.get(insn, 0)? & width_mask(size)) as u128;
        let a = (self.reg(acc_reg(size, false)) & width_mask(size)) as u128;
        let full = a.wrapping_mul(src);

        let low = (full as u64) & width_mask(size);
        let high = (full >> (size * 8)) as u64 & width_mask(size);
        if size == 1 {
            self.set_reg(Register::AX, full as u64 & 0xFFFF);
        } else {
            self.set_reg(acc_reg(size, false), low);
            self.set_reg(acc_reg(size, true), high);
        }

        let overflow = high != 0;
        self.flags.cf = overflow;
        self.flags.of = overflow;
        Some(())
    }

    fn div(&mut self, insn: &Instruction) -> Option<()> {
        let size = self.op_size(insn, 0);
        let divisor = (self.get(insn, 0)? & width_mask(size)) as u128;
        if divisor == 0 {
            return None;
        }
        let dividend = self.dividend(size);
        let (q, r) = (dividend / divisor, dividend % divisor);
        self.store_quot_rem(size, q as u64, r as u64);
        Some(())
    }

    fn idiv(&mut self, insn: &Instruction) -> Option<()> {
        let size = self.op_size(insn, 0);
        let divisor = sign_extend(self.get(insn, 0)? & width_mask(size), size) as i64 as i128;
        if divisor == 0 {
            return None;
        }
        let dividend = self.dividend(size) as i128;
        let bits = (2 * size * 8).min(128) as u32;
        let dividend = (dividend << (128 - bits)) >> (128 - bits); // sign extend the 2*size byte value
        let (q, r) = (dividend / divisor, dividend % divisor);
        self.store_quot_rem(size, q as u64, r as u64);
        Some(())
    }

    fn dividend(&self, size: usize) -> u128 {
        if size == 1 {
            return u128::from(self.reg(Register::AX) & 0xFFFF);
        }
        let low = u128::from(self.reg(acc_reg(size, false)) & width_mask(size));
        let high = u128::from(self.reg(acc_reg(size, true)) & width_mask(size));
        (high << (size * 8)) | low
    }

    fn store_quot_rem(&mut self, size: usize, quotient: u64, remainder: u64) {
        if size == 1 {
            self.set_reg(Register::AL, quotient & 0xFF);
            self.set_reg(Register::AH, remainder & 0xFF);
        } else {
            self.set_reg(acc_reg(size, false), quotient & width_mask(size));
            self.set_reg(acc_reg(size, true), remainder & width_mask(size));
        }
    }

    fn logic_flags(&mut self, r: u64, size: usize) {
        self.flags.cf = false;
        self.flags.of = false;
        self.flags.af = false;
        self.zsp(r & width_mask(size), size);
    }

    fn zsp(&mut self, r: u64, size: usize) {
        let m = width_mask(size);
        let r = r & m;
        self.flags.zf = r == 0;
        self.flags.sf = (r >> (size * 8 - 1)) & 1 == 1;
        self.flags.pf = (r as u8).count_ones().is_multiple_of(2);
    }

    fn cond(&self, insn: &Instruction) -> bool {
        let f = &self.flags;
        match insn.condition_code() {
            ConditionCode::e => f.zf,
            ConditionCode::ne => !f.zf,
            ConditionCode::b => f.cf,
            ConditionCode::ae => !f.cf,
            ConditionCode::be => f.cf || f.zf,
            ConditionCode::a => !(f.cf || f.zf),
            ConditionCode::s => f.sf,
            ConditionCode::ns => !f.sf,
            ConditionCode::l => f.sf != f.of,
            ConditionCode::ge => f.sf == f.of,
            ConditionCode::le => f.zf || (f.sf != f.of),
            ConditionCode::g => !f.zf && (f.sf == f.of),
            ConditionCode::o => f.of,
            ConditionCode::no => !f.of,
            ConditionCode::p => f.pf,
            ConditionCode::np => !f.pf,
            ConditionCode::None => match insn.mnemonic() {
                Mnemonic::Jcxz => self.gpr[1] & 0xFFFF == 0,
                Mnemonic::Jecxz => self.gpr[1] & 0xFFFF_FFFF == 0,
                Mnemonic::Jrcxz => self.gpr[1] == 0,
                _ => false,
            },
        }
    }

    fn flags_bits(&self) -> u64 {
        let f = &self.flags;
        2 | (u64::from(f.cf))
            | (u64::from(f.pf) << 2)
            | (u64::from(f.af) << 4)
            | (u64::from(f.zf) << 6)
            | (u64::from(f.sf) << 7)
            | (u64::from(f.of) << 11)
    }

    fn set_flags(&mut self, v: u64) {
        self.flags.cf = v & 1 == 1;
        self.flags.pf = (v >> 2) & 1 == 1;
        self.flags.af = (v >> 4) & 1 == 1;
        self.flags.zf = (v >> 6) & 1 == 1;
        self.flags.sf = (v >> 7) & 1 == 1;
        self.flags.of = (v >> 11) & 1 == 1;
    }
}

fn slot(r: Register) -> Option<usize> {
    r.is_gpr().then(|| r.full_register().number())
}

fn acc_reg(size: usize, high: bool) -> Register {
    match (size, high) {
        (1, _) => Register::AL,
        (2, false) => Register::AX,
        (2, true) => Register::DX,
        (4, false) => Register::EAX,
        (4, true) => Register::EDX,
        (_, false) => Register::RAX,
        (_, true) => Register::RDX,
    }
}

fn high8(r: Register) -> bool {
    matches!(r, Register::AH | Register::BH | Register::CH | Register::DH)
}

fn plausible(value: u64, bits: u32) -> bool {
    let ceiling = if bits == 64 {
        0x7FFF_FFFF_0000
    } else {
        0x8000_0000
    };
    (0x1_0000..ceiling).contains(&value)
}

fn host_cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    #[cfg(target_arch = "x86_64")]
    {
        let r = std::arch::x86_64::__cpuid_count(leaf, subleaf);
        (r.eax, r.ebx, r.ecx, r.edx)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (leaf, subleaf);
        (0, 0, 0, 0)
    }
}

fn register_seed(seed: u64, index: usize, bits: u32) -> u64 {
    let index = index as u64;
    if bits == 64 {
        0xC000_0000_0000_0000 | (seed << 48) | (index << 8) | 0x11
    } else {
        0xC000_0000 | ((seed << 24) & 0x0F00_0000) | (index << 8) | 0x11
    }
}

fn frame_mark(seed: u64, slot: u64, bits: u32) -> u64 {
    if bits == 64 {
        0xB000_0000_0000_0000 | (seed << 48) | (slot << 4) | 0x7
    } else {
        0xB000_0000 | ((seed << 24) & 0x0F00_0000) | (slot << 4) | 0x7
    }
}

fn mask(value: u64, size: usize) -> u64 {
    value & width_mask(size)
}

fn top_bit(value: u64, size: usize) -> bool {
    (value >> (size * 8 - 1)) & 1 == 1
}

fn next_bit(value: u64, size: usize) -> bool {
    (value >> (size * 8 - 2)) & 1 == 1
}

fn width_mask(size: usize) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

fn sign_extend(value: u64, size: usize) -> u64 {
    if size >= 8 {
        return value;
    }
    let bits = size * 8;
    let sign = 1u64 << (bits - 1);
    if value & sign != 0 {
        value | !width_mask(size)
    } else {
        value & width_mask(size)
    }
}

fn is_string_op(insn: &Instruction) -> bool {
    (0..insn.op_count()).any(|i| {
        matches!(
            insn.op_kind(i),
            OpKind::MemorySegSI
                | OpKind::MemorySegESI
                | OpKind::MemorySegRSI
                | OpKind::MemoryESDI
                | OpKind::MemoryESEDI
                | OpKind::MemoryESRDI
        )
    })
}

fn string_shape(m: Mnemonic) -> Option<(usize, &'static str)> {
    let name = format!("{m:?}");
    let kind = ["Movs", "Stos", "Lods", "Scas", "Cmps"]
        .into_iter()
        .find(|k| name.starts_with(k))?;
    let size = match name.chars().last()? {
        'b' => 1,
        'w' => 2,
        'd' => 4,
        _ => 8,
    };
    Some((size, kind))
}

fn string_count(cpu: &Cpu, insn: &Instruction) -> u64 {
    let rep = insn.has_rep_prefix() || insn.has_repe_prefix() || insn.has_repne_prefix();
    if rep { cpu.gpr[1] & cpu.addr_mask() } else { 1 }
}

fn is_jcc(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Jb
            | Mnemonic::Jae
            | Mnemonic::Jbe
            | Mnemonic::Ja
            | Mnemonic::Js
            | Mnemonic::Jns
            | Mnemonic::Jl
            | Mnemonic::Jge
            | Mnemonic::Jle
            | Mnemonic::Jg
            | Mnemonic::Jo
            | Mnemonic::Jno
            | Mnemonic::Jp
            | Mnemonic::Jnp
            | Mnemonic::Jcxz
            | Mnemonic::Jecxz
            | Mnemonic::Jrcxz
    )
}

fn is_setcc(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Sete
            | Mnemonic::Setne
            | Mnemonic::Setb
            | Mnemonic::Setae
            | Mnemonic::Setbe
            | Mnemonic::Seta
            | Mnemonic::Sets
            | Mnemonic::Setns
            | Mnemonic::Setl
            | Mnemonic::Setge
            | Mnemonic::Setle
            | Mnemonic::Setg
            | Mnemonic::Seto
            | Mnemonic::Setno
            | Mnemonic::Setp
            | Mnemonic::Setnp
    )
}

fn is_cmovcc(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Cmove
            | Mnemonic::Cmovne
            | Mnemonic::Cmovb
            | Mnemonic::Cmovae
            | Mnemonic::Cmovbe
            | Mnemonic::Cmova
            | Mnemonic::Cmovs
            | Mnemonic::Cmovns
            | Mnemonic::Cmovl
            | Mnemonic::Cmovge
            | Mnemonic::Cmovle
            | Mnemonic::Cmovg
            | Mnemonic::Cmovo
            | Mnemonic::Cmovno
            | Mnemonic::Cmovp
            | Mnemonic::Cmovnp
    )
}
