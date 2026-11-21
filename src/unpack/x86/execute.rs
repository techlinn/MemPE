use iced_x86::{Code, ConditionCode, Instruction, Mnemonic, OpKind, Register};

use super::emulator::{
    ADJUST_FLAG, CARRY_FLAG, Cpu, DIRECTION_FLAG, INTERRUPT_FLAG, MODELLED_FLAGS, OVERFLOW_FLAG,
    PARITY_FLAG, R11, RAX, RBP, RBX, RCX, RDI, RDX, RESERVED_FLAG, RSI, RSP, SIGN_FLAG, ZERO_FLAG,
    mask,
};
use crate::unpack::x86::step_budget;

impl Cpu<'_> {
    fn reg(&self, r: Register) -> Option<u64> {
        let full = *self.gpr.get(slot(r)?)?;
        Some(match is_high_byte(r) {
            true => (full >> 8) & 0xFF,
            false => mask(full, r.size()),
        })
    }

    pub(super) fn set_reg(&mut self, r: Register, value: u64) -> Option<()> {
        let cell = self.gpr.get_mut(slot(r)?)?;
        match r.size() {
            8 => *cell = value,
            4 => *cell = value & 0xFFFF_FFFF, // zero extends
            _ if is_high_byte(r) => *cell = (*cell & !0xFF00) | ((value & 0xFF) << 8),
            n => {
                let m = Width(n).mask();
                *cell = (*cell & !m) | (value & m);
            }
        }
        Some(())
    }

    fn offset_in_segment(&self, insn: &Instruction) -> Option<u64> {
        let (base, index) = (insn.memory_base(), insn.memory_index());
        if matches!(base, Register::RIP | Register::EIP) {
            return Some(insn.memory_displacement64()); // iced gives the target
        }

        let mut offset = insn.memory_displacement64();
        let mut width = (self.bits / 8) as usize;
        if base != Register::None {
            offset = offset.wrapping_add(self.reg(base)?);
            width = base.size();
        }
        if index != Register::None {
            let scaled = self
                .reg(index)?
                .wrapping_mul(u64::from(insn.memory_index_scale()));
            offset = offset.wrapping_add(scaled);
            width = index.size();
        }
        Some(mask(offset, width)) // the address size is the registers' size
    }

    pub(super) fn effective_address(&self, insn: &Instruction) -> Option<u64> {
        let thread_segment = match self.bits {
            64 => Register::GS,
            _ => Register::FS,
        };
        let segment = insn.memory_segment();
        let base = match segment {
            Register::FS | Register::GS if segment == thread_segment => self.thread_block?,
            Register::FS | Register::GS => return None,
            _ => 0,
        };

        Some(base.wrapping_add(self.offset_in_segment(insn)?))
    }

    fn address_mask(&self) -> u64 {
        if self.bits == 64 {
            u64::MAX
        } else {
            0xFFFF_FFFF
        }
    }

    fn operand_size(&self, insn: &Instruction, i: u32) -> usize {
        match insn.op_kind(i) {
            OpKind::Register => insn.op_register(i).size(),
            OpKind::Memory => insn.memory_size().size(),
            _ => (self.bits / 8) as usize,
        }
    }

    fn width(&self, insn: &Instruction, i: u32) -> Width {
        Width(self.operand_size(insn, i))
    }

    pub(super) fn get(&self, insn: &Instruction, i: u32) -> Option<u64> {
        match insn.op_kind(i) {
            OpKind::Register => self.reg(insn.op_register(i)),
            OpKind::Memory => self.mem(self.effective_address(insn)?, insn.memory_size().size()),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Some(insn.near_branch_target())
            }
            _ => insn.try_immediate(i).ok(),
        }
    }

    pub(super) fn set(&mut self, insn: &Instruction, i: u32, value: u64) -> Option<()> {
        match insn.op_kind(i) {
            OpKind::Register => self.set_reg(insn.op_register(i), value),
            OpKind::Memory => self.write_mem(
                self.effective_address(insn)?,
                insn.memory_size().size(),
                value,
            ),
            _ => None,
        }
    }

    pub(super) fn push(&mut self, value: u64) -> Option<()> {
        let width = u64::from(self.bits / 8);
        self.gpr[RSP] = self.gpr[RSP].wrapping_sub(width);
        self.write_mem(self.gpr[RSP], width as usize, value)
    }

    fn pop(&mut self) -> Option<u64> {
        let width = u64::from(self.bits / 8);
        let value = self.mem(self.gpr[RSP], width as usize)?;
        self.gpr[RSP] = self.gpr[RSP].wrapping_add(width);
        Some(value)
    }

    pub(super) fn step(&mut self, insn: &Instruction) -> Option<()> {
        step_budget::burn()?;
        if unmodelled(insn) {
            return None;
        }
        self.rip = insn.next_ip();
        if super::sse::is_sse(insn) {
            return self.sse_step(insn); // string movsd shares mnemonic
        }

        match insn.mnemonic() {
            Mnemonic::Nop
            | Mnemonic::Prefetch
            | Mnemonic::Prefetchnta
            | Mnemonic::Prefetcht0
            | Mnemonic::Prefetcht1
            | Mnemonic::Prefetcht2
            | Mnemonic::Prefetchw => Some(()),
            Mnemonic::Cld | Mnemonic::Std => {
                self.flags.df = insn.mnemonic() == Mnemonic::Std;
                Some(())
            }
            Mnemonic::Cwd | Mnemonic::Cdq | Mnemonic::Cqo => {
                let (from, to) = match insn.mnemonic() {
                    Mnemonic::Cwd => (Register::AX, Register::DX),
                    Mnemonic::Cdq => (Register::EAX, Register::EDX),
                    _ => (Register::RAX, Register::RDX),
                };
                let width = Width(from.size());
                let fill = match width.top_bit(self.reg(from)?) {
                    true => width.mask(),
                    false => 0,
                };
                self.set_reg(to, fill)
            }
            Mnemonic::Mov | Mnemonic::Movzx => {
                let v = self.get(insn, 1)?;
                self.set(insn, 0, v)
            }
            Mnemonic::Movsx | Mnemonic::Movsxd => {
                let v = self.width(insn, 1).sign_extend(self.get(insn, 1)?);
                self.set(insn, 0, v)
            }
            Mnemonic::Lea => {
                let ea = self.offset_in_segment(insn)?; // no segment base
                self.set(insn, 0, ea)
            }
            Mnemonic::Push => {
                let size = insn.stack_pointer_increment().unsigned_abs() as u64;
                let v = self.get(insn, 0)?;
                self.gpr[RSP] = self.gpr[RSP].wrapping_sub(size);
                self.write_mem(self.gpr[RSP], size as usize, v)
            }
            Mnemonic::Pop => {
                let size = insn.stack_pointer_increment().unsigned_abs() as u64;
                let v = self.mem(self.gpr[RSP], size as usize)?;
                self.gpr[RSP] = self.gpr[RSP].wrapping_add(size);
                self.set(insn, 0, v)
            }
            Mnemonic::Add => self.add_or_subtract(insn, Sum::Add, Carry::Ignored),
            Mnemonic::Adc => self.add_or_subtract(insn, Sum::Add, Carry::Taken),
            Mnemonic::Sub => self.add_or_subtract(insn, Sum::Subtract, Carry::Ignored),
            Mnemonic::Sbb => self.add_or_subtract(insn, Sum::Subtract, Carry::Taken),
            Mnemonic::Cmp => {
                let (a, b) = (self.get(insn, 0)?, self.get(insn, 1)?);
                self.sub(a, b, false, self.width(insn, 0));
                Some(())
            }
            Mnemonic::Test => {
                let r = self.get(insn, 0)? & self.get(insn, 1)?;
                self.set_logic_flags(r, self.width(insn, 0));
                Some(())
            }
            Mnemonic::And | Mnemonic::Or | Mnemonic::Xor => {
                let (a, b) = (self.get(insn, 0)?, self.get(insn, 1)?);
                let r = match insn.mnemonic() {
                    Mnemonic::And => a & b,
                    Mnemonic::Or => a | b,
                    _ => a ^ b,
                };
                self.set_logic_flags(r, self.width(insn, 0));
                self.set(insn, 0, r)
            }
            Mnemonic::Not => {
                let v = !self.get(insn, 0)?;
                self.set(insn, 0, v)
            }
            Mnemonic::Neg => {
                let a = self.get(insn, 0)?;
                let r = self.sub(0, a, false, self.width(insn, 0));
                self.flags.cf = a != 0;
                self.set(insn, 0, r)
            }
            Mnemonic::Inc => {
                let cf = self.flags.cf;
                let r = self.add(self.get(insn, 0)?, 1, false, self.width(insn, 0));
                self.flags.cf = cf; // inc leaves cf
                self.set(insn, 0, r)
            }
            Mnemonic::Dec => {
                let cf = self.flags.cf;
                let r = self.sub(self.get(insn, 0)?, 1, false, self.width(insn, 0));
                self.flags.cf = cf;
                self.set(insn, 0, r)
            }
            Mnemonic::Xchg => {
                let (a, b) = (self.get(insn, 0)?, self.get(insn, 1)?);
                self.set(insn, 0, b)?;
                self.set(insn, 1, a)
            }
            Mnemonic::Xadd => {
                let width = self.width(insn, 0);
                let memory = insn.op0_kind() == OpKind::Memory;
                let address = match memory {
                    true => Some(self.effective_address(insn)?),
                    false => None,
                };
                let (dst, src) = (self.get(insn, 0)?, self.get(insn, 1)?);
                let sum = self.add(dst, src, false, width);
                self.set(insn, 1, dst)?;
                match address {
                    Some(address) => self.write_mem(address, width.bytes(), sum),
                    None => self.set(insn, 0, sum),
                }
            }
            Mnemonic::Bswap | Mnemonic::Movbe => {
                let source = u32::from(insn.mnemonic() == Mnemonic::Movbe);
                let size = self.operand_size(insn, 0);
                let v = self.get(insn, source)?.swap_bytes() >> (64 - 8 * size);
                self.set(insn, 0, v)
            }
            Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc => self.bit_test(insn),
            Mnemonic::Cdqe | Mnemonic::Cwde | Mnemonic::Cbw => {
                let (from, to) = match insn.mnemonic() {
                    Mnemonic::Cdqe => (Register::EAX, Register::RAX),
                    Mnemonic::Cwde => (Register::AX, Register::EAX),
                    _ => (Register::AL, Register::AX),
                };
                let v = Width(from.size()).sign_extend(self.reg(from)?);
                self.set_reg(to, v)
            }
            Mnemonic::Sahf => {
                self.set_status_flags(self.reg(Register::AH)?);
                Some(())
            }
            Mnemonic::Lahf => self.set_reg(Register::AH, self.eflags() & 0xFF),
            Mnemonic::Pushfd | Mnemonic::Pushfq => self.push(self.eflags()),
            Mnemonic::Popfd | Mnemonic::Popfq => {
                let v = self.pop()?;
                self.set_eflags(v)
            }
            Mnemonic::Shl
            | Mnemonic::Sal
            | Mnemonic::Sar
            | Mnemonic::Shr
            | Mnemonic::Rol
            | Mnemonic::Ror => self.shift(insn),
            Mnemonic::Rcl | Mnemonic::Rcr => self.rotate_through_carry(insn),
            Mnemonic::Shld | Mnemonic::Shrd => self.double_shift(insn),
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
                let target = self.get(insn, 0)?; // before the push moves rsp
                self.push(insn.next_ip())?;
                self.rip = target;
                Some(())
            }
            Mnemonic::Syscall => {
                step_budget::note_system_call();
                self.gpr[R11] = self.eflags();
                self.gpr[RCX] = self.rip;
                self.gpr[RAX] = 0;
                Some(())
            }
            Mnemonic::Jmp
                if matches!(insn.op0_kind(), OpKind::FarBranch16 | OpKind::FarBranch32) =>
            {
                step_budget::note_system_call();
                self.gpr[RAX] = 0; // wow64 gate: syscall taken as success
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
                    self.gpr[RSP] = self.gpr[RSP].wrapping_add(self.get(insn, 0)?);
                }
                Some(())
            }
            _ if is_jcc(insn) => {
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
            Mnemonic::Rdtsc | Mnemonic::Rdtscp => {
                self.gpr[RAX] = 0;
                self.gpr[RDX] = 0;
                if insn.mnemonic() == Mnemonic::Rdtscp {
                    self.gpr[RCX] = 0; // the processor id
                }
                Some(())
            }
            Mnemonic::Pause | Mnemonic::Lfence | Mnemonic::Mfence | Mnemonic::Sfence => Some(()),
            _ if insn.is_string_instruction() => self.string_op(insn),
            Mnemonic::Leave => {
                self.gpr[RSP] = self.gpr[RBP];
                let v = self.pop()?;
                self.gpr[RBP] = v;
                Some(())
            }
            Mnemonic::Bsf
            | Mnemonic::Bsr
            | Mnemonic::Tzcnt
            | Mnemonic::Lzcnt
            | Mnemonic::Popcnt => self.bit_scan(insn),
            Mnemonic::Cmpxchg => {
                let width = self.width(insn, 0);
                let (dst, src) = (self.get(insn, 0)?, self.get(insn, 1)?);
                let acc = self.reg(accumulator(width, Half::Low))?;
                self.sub(acc, dst, false, width);
                if acc == dst {
                    self.set(insn, 0, src)
                } else {
                    self.set_reg(accumulator(width, Half::Low), dst)
                }
            }
            Mnemonic::Endbr64 | Mnemonic::Endbr32 => Some(()),
            Mnemonic::Pushad => {
                let sp = self.gpr[RSP];
                for value in [
                    self.gpr[RAX],
                    self.gpr[RCX],
                    self.gpr[RDX],
                    self.gpr[RBX],
                    sp,
                    self.gpr[RBP],
                    self.gpr[RSI],
                    self.gpr[RDI],
                ] {
                    self.push(value)?;
                }
                Some(())
            }
            Mnemonic::Popad => {
                for slot in [RDI, RSI, RBP, RSP, RBX, RDX, RCX, RAX] {
                    let v = self.pop()?;
                    if slot != RSP {
                        self.gpr[slot] = v;
                    }
                }
                Some(())
            }
            _ => self.x87_step(insn),
        }
    }

    fn string_op(&mut self, insn: &Instruction) -> Option<()> {
        let (size, kind) = string_shape(insn.mnemonic())?;
        if !self.plain_string_addressing(insn) {
            return None;
        }
        let rep = insn.has_rep_prefix() || insn.has_repe_prefix() || insn.has_repne_prefix();
        let mask = self.address_mask();
        let step = size as u64;
        let mut count = if rep { self.gpr[RCX] & mask } else { 1 };

        while count > 0 {
            self.string_fuel = self.string_fuel.checked_sub(1)?;
            let (si, di) = (self.gpr[RSI], self.gpr[RDI]);
            match kind {
                StringOp::Movs => {
                    let v = self.mem(si, size)?;
                    self.write_mem(di, size, v)?;
                }
                StringOp::Stos => self.write_mem(di, size, self.gpr[RAX])?,
                StringOp::Lods => {
                    self.set_reg(accumulator(Width(size), Half::Low), self.mem(si, size)?)?
                }
                StringOp::Scas => {
                    let v = self.mem(di, size)?;
                    self.sub(self.gpr[RAX], v, false, Width(size));
                }
                StringOp::Cmps => {
                    let (a, b) = (self.mem(si, size)?, self.mem(di, size)?);
                    self.sub(a, b, false, Width(size));
                }
            }

            let advance = |at: u64| match self.flags.df {
                true => at.wrapping_sub(step) & mask, // std: backwards
                false => at.wrapping_add(step) & mask,
            };
            if matches!(kind, StringOp::Movs | StringOp::Lods | StringOp::Cmps) {
                self.gpr[RSI] = advance(si);
            }
            if kind != StringOp::Lods {
                self.gpr[RDI] = advance(di);
            }
            count -= 1;
            if rep {
                self.gpr[RCX] = count;
            }

            let compare = matches!(kind, StringOp::Scas | StringOp::Cmps);
            if compare
                && ((insn.has_repe_prefix() && !self.flags.zf)
                    || (insn.has_repne_prefix() && self.flags.zf))
            {
                break;
            }
        }
        Some(())
    }

    fn plain_string_addressing(&self, insn: &Instruction) -> bool {
        let native = |kind: OpKind| match self.bits {
            64 => matches!(kind, OpKind::MemorySegRSI | OpKind::MemoryESRDI),
            _ => matches!(kind, OpKind::MemorySegESI | OpKind::MemoryESEDI),
        };
        let thread_segment = matches!(insn.segment_prefix(), Register::FS | Register::GS);

        !thread_segment
            && (0..insn.op_count())
                .map(|i| insn.op_kind(i))
                .filter(|kind| is_string_memory(*kind))
                .all(native)
    }

    fn bit_test(&mut self, insn: &Instruction) -> Option<()> {
        let width = self.width(insn, 0);
        let bits = u64::from(width.bits());
        let index = self.get(insn, 1)?;
        let in_memory = insn.op0_kind() == OpKind::Memory && insn.op1_kind() == OpKind::Register;

        let (address, bit) = match in_memory {
            true => {
                let signed = width.sign_extend(index) as i64; // index reaches past the first element
                let element = signed.div_euclid(bits as i64) * width.bytes() as i64;
                (
                    Some(self.effective_address(insn)?.wrapping_add(element as u64)),
                    signed.rem_euclid(bits as i64) as u64,
                )
            }
            false => (None, index % bits),
        };
        let value = match address {
            Some(at) => self.mem(at, width.bytes())?,
            None => self.get(insn, 0)?,
        };

        self.flags.cf = (value >> bit) & 1 == 1;
        let result = match insn.mnemonic() {
            Mnemonic::Bts => value | (1 << bit),
            Mnemonic::Btr => value & !(1 << bit),
            Mnemonic::Btc => value ^ (1 << bit),
            _ => return Some(()),
        };
        match address {
            Some(at) => self.write_mem(at, width.bytes(), result),
            None => self.set(insn, 0, result),
        }
    }

    fn bit_scan(&mut self, insn: &Instruction) -> Option<()> {
        let width = self.width(insn, 0);
        let bits = width.bits();
        let v = self.get(insn, 1)? & width.mask();
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

    fn add_or_subtract(&mut self, insn: &Instruction, sum: Sum, carry: Carry) -> Option<()> {
        let (a, b) = (self.get(insn, 0)?, self.get(insn, 1)?);
        let cin = carry == Carry::Taken && self.flags.cf;
        let width = self.width(insn, 0);
        let r = match sum {
            Sum::Subtract => self.sub(a, b, cin, width),
            Sum::Add => self.add(a, b, cin, width),
        };
        self.set(insn, 0, r)
    }

    fn add(&mut self, a: u64, b: u64, cin: bool, width: Width) -> u64 {
        let m = width.mask();
        let (a, b) = (a & m, b & m);
        let full = u128::from(a) + u128::from(b) + u128::from(cin);
        let r = (full as u64) & m;
        self.flags.cf = full > u128::from(m);
        self.flags.of = ((!(a ^ b)) & (a ^ r) & width.sign_bit()) != 0;
        self.flags.af = ((a ^ b ^ r) >> 4) & 1 == 1;
        self.set_zero_sign_parity(r, width);
        r
    }

    fn sub(&mut self, a: u64, b: u64, cin: bool, width: Width) -> u64 {
        let m = width.mask();
        let (a, b) = (a & m, b & m);
        let r = a.wrapping_sub(b).wrapping_sub(u64::from(cin)) & m;
        self.flags.cf = u128::from(a) < u128::from(b) + u128::from(cin);
        self.flags.of = ((a ^ b) & (a ^ r) & width.sign_bit()) != 0;
        self.flags.af = ((a ^ b ^ r) >> 4) & 1 == 1;
        self.set_zero_sign_parity(r, width);
        r
    }

    fn shift(&mut self, insn: &Instruction) -> Option<()> {
        let width = self.width(insn, 0);
        let bits = u64::from(width.bits());
        let m = width.mask();
        let a = self.get(insn, 0)? & m;
        let count = self.get(insn, 1)? & width.count_mask();

        let mnemonic = insn.mnemonic();
        let r = match mnemonic {
            Mnemonic::Shl | Mnemonic::Sal => {
                if count != 0 {
                    self.flags.cf = count <= bits && (a >> (bits - count)) & 1 == 1; // shifted out entirely: clear
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
                let signed = width.sign_extend(a) as i64;
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
                    width.top_bit(a) ^ width.second_top_bit(a)
                }
                Mnemonic::Shr => width.top_bit(a),
                Mnemonic::Sar => false,
                _ => (a & 1 == 1) ^ width.top_bit(a),
            };
            if matches!(
                mnemonic,
                Mnemonic::Shl | Mnemonic::Sal | Mnemonic::Shr | Mnemonic::Sar
            ) {
                self.set_zero_sign_parity(r, width);
            }
        }

        self.set(insn, 0, r)
    }

    fn double_shift(&mut self, insn: &Instruction) -> Option<()> {
        let left = insn.mnemonic() == Mnemonic::Shld;
        let width = self.width(insn, 0);
        let bits = u64::from(width.bits());
        let m = width.mask();
        let dst = self.get(insn, 0)? & m;
        let src = self.get(insn, 1)? & m;
        let count = self.get(insn, 2)? & width.count_mask();

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
            width.top_bit(dst) ^ width.second_top_bit(dst)
        } else {
            (src & 1 == 1) ^ width.top_bit(dst)
        };
        self.set_zero_sign_parity(r, width);
        self.set(insn, 0, r)
    }

    fn rotate_through_carry(&mut self, insn: &Instruction) -> Option<()> {
        let width = self.width(insn, 0);
        let bits = width.bits();
        let m = width.mask();
        let operand = u128::from(self.get(insn, 0)? & m);
        let raw = self.get(insn, 1)? & width.count_mask();
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
            width.top_bit(original) ^ width.second_top_bit(original)
        } else {
            carry_in ^ width.top_bit(original)
        };
        self.set(insn, 0, value as u64 & m)
    }

    fn imul(&mut self, insn: &Instruction) -> Option<()> {
        let width = self.width(insn, 0);
        let widen = |value: u64| width.sign_extend(value) as i64 as i128;

        let overflow = match insn.op_count() {
            1 => {
                let src = widen(self.get(insn, 0)?);
                let full = widen(self.reg(accumulator(width, Half::Low))?).wrapping_mul(src);
                let low = (full as u64) & width.mask();
                let high = ((full >> width.bits()) as u64) & width.mask();

                self.set_reg(accumulator(width, Half::Low), low)?;
                self.set_reg(accumulator(width, Half::High), high)?;
                full != widen(low)
            }
            2 => {
                let full = widen(self.get(insn, 0)?).wrapping_mul(widen(self.get(insn, 1)?));
                let low = (full as u64) & width.mask();
                self.set(insn, 0, low)?;
                full != widen(low)
            }
            _ => {
                let full = widen(self.get(insn, 1)?).wrapping_mul(widen(self.get(insn, 2)?)); // iced zero-extends imm16 and imm32
                let low = (full as u64) & width.mask();
                self.set(insn, 0, low)?;
                full != widen(low)
            }
        };

        self.flags.cf = overflow;
        self.flags.of = overflow;
        Some(())
    }

    fn mul(&mut self, insn: &Instruction) -> Option<()> {
        let width = self.width(insn, 0);
        let src = (self.get(insn, 0)? & width.mask()) as u128;
        let a = (self.reg(accumulator(width, Half::Low))? & width.mask()) as u128;
        let full = a.wrapping_mul(src);

        let low = (full as u64) & width.mask();
        let high = (full >> width.bits()) as u64 & width.mask();
        self.set_reg(accumulator(width, Half::Low), low)?;
        self.set_reg(accumulator(width, Half::High), high)?;

        let overflow = high != 0;
        self.flags.cf = overflow;
        self.flags.of = overflow;
        Some(())
    }

    fn div(&mut self, insn: &Instruction) -> Option<()> {
        let width = self.width(insn, 0);
        let divisor = (self.get(insn, 0)? & width.mask()) as u128;
        if divisor == 0 {
            return None;
        }
        let dividend = self.dividend(width)?;
        let (q, r) = (dividend / divisor, dividend % divisor);
        if q > u128::from(width.mask()) {
            return None; // #DE
        }
        self.store_quotient_remainder(width, q as u64, r as u64)
    }

    fn idiv(&mut self, insn: &Instruction) -> Option<()> {
        let width = self.width(insn, 0);
        let divisor = width.sign_extend(self.get(insn, 0)?) as i64 as i128;
        if divisor == 0 {
            return None;
        }
        let dividend = self.dividend(width)? as i128;
        let bits = (2 * width.bits()).min(128);
        let dividend = (dividend << (128 - bits)) >> (128 - bits); // sign extend
        let (q, r) = (
            dividend.checked_div(divisor)?,
            dividend.checked_rem(divisor)?,
        );
        let limit = i128::from(width.sign_bit());
        if !(-limit..limit).contains(&q) {
            return None; // #DE
        }
        self.store_quotient_remainder(width, q as u64, r as u64)
    }

    fn dividend(&self, width: Width) -> Option<u128> {
        let low = u128::from(self.reg(accumulator(width, Half::Low))?);
        let high = u128::from(self.reg(accumulator(width, Half::High))?);
        Some((high << width.bits()) | low)
    }

    fn store_quotient_remainder(&mut self, width: Width, q: u64, r: u64) -> Option<()> {
        self.set_reg(accumulator(width, Half::Low), q & width.mask())?;
        self.set_reg(accumulator(width, Half::High), r & width.mask())
    }

    fn set_logic_flags(&mut self, r: u64, width: Width) {
        self.flags.cf = false;
        self.flags.of = false;
        self.flags.af = false;
        self.set_zero_sign_parity(r & width.mask(), width);
    }

    fn set_zero_sign_parity(&mut self, r: u64, width: Width) {
        let m = width.mask();
        let r = r & m;
        self.flags.zf = r == 0;
        self.flags.sf = width.top_bit(r);
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
                Mnemonic::Jcxz => self.gpr[RCX] & 0xFFFF == 0,
                Mnemonic::Jecxz => self.gpr[RCX] & 0xFFFF_FFFF == 0,
                Mnemonic::Jrcxz => self.gpr[RCX] == 0,
                _ => false,
            },
        }
    }

    pub(super) fn eflags(&self) -> u64 {
        let f = &self.flags;
        let bit = |set: bool, flag: u64| if set { flag } else { 0 };

        RESERVED_FLAG
            | INTERRUPT_FLAG
            | bit(f.cf, CARRY_FLAG)
            | bit(f.pf, PARITY_FLAG)
            | bit(f.af, ADJUST_FLAG)
            | bit(f.zf, ZERO_FLAG)
            | bit(f.sf, SIGN_FLAG)
            | bit(f.df, DIRECTION_FLAG)
            | bit(f.of, OVERFLOW_FLAG)
    }

    fn set_status_flags(&mut self, v: u64) {
        self.flags.cf = v & CARRY_FLAG != 0;
        self.flags.pf = v & PARITY_FLAG != 0;
        self.flags.af = v & ADJUST_FLAG != 0;
        self.flags.zf = v & ZERO_FLAG != 0;
        self.flags.sf = v & SIGN_FLAG != 0;
    }

    pub(super) fn set_eflags(&mut self, v: u64) -> Option<()> {
        if v & !MODELLED_FLAGS != 0 {
            return None; // trap, id and the rest
        }

        self.set_status_flags(v);
        self.flags.df = v & DIRECTION_FLAG != 0;
        self.flags.of = v & OVERFLOW_FLAG != 0;
        Some(())
    }
}

fn unmodelled(insn: &Instruction) -> bool {
    let registers = (0..insn.op_count())
        .filter(|index| insn.op_kind(*index) == OpKind::Register)
        .map(|index| insn.op_register(index));
    let system_register = registers.into_iter().any(|register| {
        register.is_segment_register() || register.is_cr() || register.is_dr() || register.is_tr()
    });

    system_register
        || insn.is_call_far()
        || insn.is_call_far_indirect()
        || insn.is_jmp_far_indirect()
        || sixteen_bit_flow(insn)
}

fn sixteen_bit_flow(insn: &Instruction) -> bool {
    let narrow_target = match insn.op0_kind() {
        OpKind::NearBranch16 => true,
        OpKind::Register => insn.op0_register().size() == 2,
        OpKind::Memory => insn.memory_size().size() == 2,
        _ => false,
    };

    match insn.mnemonic() {
        Mnemonic::Call | Mnemonic::Jmp => narrow_target,
        Mnemonic::Ret => matches!(insn.code(), Code::Retnw | Code::Retnw_imm16),
        Mnemonic::Leave => insn.code() == Code::Leavew,
        _ => is_jcc(insn) && insn.op0_kind() == OpKind::NearBranch16,
    }
}

fn slot(r: Register) -> Option<usize> {
    r.is_gpr().then(|| r.full_register().number())
}

#[derive(Clone, Copy)]
enum Half {
    Low,  // al, ax, eax, rax
    High, // ah, dx, edx, rdx
}

#[derive(Clone, Copy)]
enum Sum {
    Add,
    Subtract,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Carry {
    Ignored,
    Taken, // adc and sbb
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Width(pub(super) usize); // bytes

impl Width {
    const QWORD: Self = Self(8);

    fn bytes(self) -> usize {
        self.0
    }

    fn bits(self) -> u32 {
        self.0 as u32 * 8
    }

    pub(super) fn mask(self) -> u64 {
        match self.0 {
            8.. => u64::MAX,
            bytes => (1u64 << (bytes * 8)) - 1,
        }
    }

    fn sign_bit(self) -> u64 {
        1u64 << (self.bits() - 1)
    }

    fn top_bit(self, value: u64) -> bool {
        value & self.sign_bit() != 0
    }

    fn second_top_bit(self, value: u64) -> bool {
        value & (self.sign_bit() >> 1) != 0
    }

    fn count_mask(self) -> u64 {
        match self {
            Self::QWORD => 0x3F,
            _ => 0x1F, // count is modulo 32 below 64-bit
        }
    }

    fn sign_extend(self, value: u64) -> u64 {
        match self.0 < 8 && self.top_bit(value) {
            true => value | !self.mask(),
            false => value & self.mask(),
        }
    }
}

fn accumulator(width: Width, half: Half) -> Register {
    match (width.bytes(), half) {
        (1, Half::Low) => Register::AL,
        (1, Half::High) => Register::AH,
        (2, Half::Low) => Register::AX,
        (2, Half::High) => Register::DX,
        (4, Half::Low) => Register::EAX,
        (4, Half::High) => Register::EDX,
        (_, Half::Low) => Register::RAX,
        (_, Half::High) => Register::RDX,
    }
}

fn is_high_byte(r: Register) -> bool {
    matches!(r, Register::AH | Register::BH | Register::CH | Register::DH)
}

fn is_string_memory(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::MemorySegSI
            | OpKind::MemorySegESI
            | OpKind::MemorySegRSI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI
    )
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StringOp {
    Movs,
    Stos,
    Lods,
    Scas,
    Cmps,
}

fn string_shape(m: Mnemonic) -> Option<(usize, StringOp)> {
    use Mnemonic as M;
    use StringOp as Op;

    Some(match m {
        M::Movsb => (1, Op::Movs),
        M::Movsw => (2, Op::Movs),
        M::Movsd => (4, Op::Movs),
        M::Movsq => (8, Op::Movs),
        M::Stosb => (1, Op::Stos),
        M::Stosw => (2, Op::Stos),
        M::Stosd => (4, Op::Stos),
        M::Stosq => (8, Op::Stos),
        M::Lodsb => (1, Op::Lods),
        M::Lodsw => (2, Op::Lods),
        M::Lodsd => (4, Op::Lods),
        M::Lodsq => (8, Op::Lods),
        M::Scasb => (1, Op::Scas),
        M::Scasw => (2, Op::Scas),
        M::Scasd => (4, Op::Scas),
        M::Scasq => (8, Op::Scas),
        M::Cmpsb => (1, Op::Cmps),
        M::Cmpsw => (2, Op::Cmps),
        M::Cmpsd => (4, Op::Cmps),
        M::Cmpsq => (8, Op::Cmps),
        _ => return None,
    })
}

fn is_jcc(insn: &Instruction) -> bool {
    insn.is_jcc_short_or_near() || insn.is_jcx_short()
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
