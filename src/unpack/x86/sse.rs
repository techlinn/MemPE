use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use super::emulator::Cpu;

// no general-purpose instruction takes an xmm operand; string movsd has none
pub(crate) fn is_sse(insn: &Instruction) -> bool {
    (0..insn.op_count()).any(|operand| {
        insn.op_kind(operand) == OpKind::Register && insn.op_register(operand).is_xmm()
    })
}

impl Cpu<'_> {
    pub(crate) fn sse_step(&mut self, insn: &Instruction) -> Option<()> {
        use Mnemonic::*;
        match insn.mnemonic() {
            Movups | Movaps | Movupd | Movapd | Movdqu | Movdqa | Lddqu => {
                let value = self.vector(insn, 1)?;
                self.set_vector(insn, 0, value)
            }
            Movd | Movq => self.move_integer(insn),
            Movss | Movsd => self.move_scalar_float(insn),
            Movlps | Movlpd => self.move_low_half(insn),
            Pxor | Xorps | Xorpd => self.bitwise(insn, |a, b| a ^ b),
            Por | Orps | Orpd => self.bitwise(insn, |a, b| a | b),
            Pand | Andps | Andpd => self.bitwise(insn, |a, b| a & b),
            Pandn | Andnps | Andnpd => self.bitwise(insn, |a, b| !a & b),
            Paddb => self.lanewise(insn, 8, u64::wrapping_add),
            Paddw => self.lanewise(insn, 16, u64::wrapping_add),
            Paddd => self.lanewise(insn, 32, u64::wrapping_add),
            Paddq => self.lanewise(insn, 64, u64::wrapping_add),
            Psubb => self.lanewise(insn, 8, u64::wrapping_sub),
            Psubw => self.lanewise(insn, 16, u64::wrapping_sub),
            Psubd => self.lanewise(insn, 32, u64::wrapping_sub),
            Psubq => self.lanewise(insn, 64, u64::wrapping_sub),
            Pshufd => self.shuffle_dwords(insn),
            _ => None,
        }
    }

    fn vector(&self, insn: &Instruction, operand: u32) -> Option<u128> {
        match insn.op_kind(operand) {
            OpKind::Register => self.xmm_of(insn.op_register(operand)),
            OpKind::Memory => {
                let at = self.effective_address(insn)?;
                let size = insn.memory_size().size().min(16);
                let low = self.mem(at, size.min(8))?;
                let high = match size {
                    16 => self.mem(at.checked_add(8)?, 8)?,
                    _ => 0,
                };
                Some(u128::from(low) | (u128::from(high) << 64))
            }
            _ => None,
        }
    }

    fn set_vector(&mut self, insn: &Instruction, operand: u32, value: u128) -> Option<()> {
        match insn.op_kind(operand) {
            OpKind::Register => {
                let index = xmm_index(insn.op_register(operand))?;
                self.xmm[index] = value;
                Some(())
            }
            OpKind::Memory => {
                let at = self.effective_address(insn)?;
                let size = insn.memory_size().size().min(16);
                self.write_mem(at, size.min(8), value as u64)?;
                if size == 16 {
                    self.write_mem(at.checked_add(8)?, 8, (value >> 64) as u64)?;
                }
                Some(())
            }
            _ => None,
        }
    }

    fn xmm_of(&self, register: Register) -> Option<u128> {
        self.xmm.get(xmm_index(register)?).copied()
    }

    fn move_integer(&mut self, insn: &Instruction) -> Option<()> {
        let to_xmm = insn.op_kind(0) == OpKind::Register && insn.op_register(0).is_xmm();
        let width = match insn.mnemonic() {
            Mnemonic::Movd => 32,
            _ => 64,
        };
        let low_bits = |value: u128| value & ((1u128 << width) - 1);

        match to_xmm {
            true => {
                let value = match insn.op_kind(1) {
                    OpKind::Register if insn.op_register(1).is_xmm() => {
                        self.xmm_of(insn.op_register(1))?
                    }
                    _ => u128::from(self.get(insn, 1)?),
                };
                self.set_vector(insn, 0, low_bits(value)) // zero extends
            }
            false => {
                let value = low_bits(self.xmm_of(insn.op_register(1))?) as u64;
                self.set(insn, 0, value)
            }
        }
    }

    fn move_low_half(&mut self, insn: &Instruction) -> Option<()> {
        const LOW: u128 = u64::MAX as u128;

        if insn.op_kind(0) == OpKind::Register {
            let index = xmm_index(insn.op_register(0))?;
            let loaded = u128::from(self.get(insn, 1)?);
            self.xmm[index] = (self.xmm[index] & !LOW) | loaded; // keeps upper half
            return Some(());
        }

        let low = (self.xmm_of(insn.op_register(1))? & LOW) as u64;
        self.set(insn, 0, low)
    }

    fn move_scalar_float(&mut self, insn: &Instruction) -> Option<()> {
        let width = match insn.mnemonic() {
            Mnemonic::Movss => 32,
            _ => 64,
        };
        let lane = (1u128 << width) - 1;
        let source = self.vector(insn, 1)? & lane;

        match (insn.op_kind(0), insn.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let index = xmm_index(insn.op_register(0))?;
                self.xmm[index] = (self.xmm[index] & !lane) | source; // keeps upper lanes
                Some(())
            }
            _ => self.set_vector(insn, 0, source), // a load zero extends
        }
    }

    fn bitwise(&mut self, insn: &Instruction, op: fn(u128, u128) -> u128) -> Option<()> {
        let value = op(self.vector(insn, 0)?, self.vector(insn, 1)?);
        self.set_vector(insn, 0, value)
    }

    fn lanewise(&mut self, insn: &Instruction, bits: u32, op: fn(u64, u64) -> u64) -> Option<()> {
        let (left, right) = (self.vector(insn, 0)?, self.vector(insn, 1)?);
        let mask = match bits {
            64 => u64::MAX,
            bits => (1u64 << bits) - 1,
        };

        let mut result = 0u128;
        for lane in 0..128 / bits {
            let shift = lane * bits;
            let a = (left >> shift) as u64 & mask;
            let b = (right >> shift) as u64 & mask;
            result |= u128::from(op(a, b) & mask) << shift;
        }
        self.set_vector(insn, 0, result)
    }

    fn shuffle_dwords(&mut self, insn: &Instruction) -> Option<()> {
        let source = self.vector(insn, 1)?;
        let order = insn.immediate8();

        let mut result = 0u128;
        for lane in 0..4 {
            let pick = (order >> (lane * 2)) & 3;
            let dword = (source >> (u32::from(pick) * 32)) as u32;
            result |= u128::from(dword) << (lane * 32);
        }
        self.set_vector(insn, 0, result)
    }
}

fn xmm_index(register: Register) -> Option<usize> {
    register
        .is_xmm()
        .then(|| register as usize - Register::XMM0 as usize)
        .filter(|index| *index < 16)
}
