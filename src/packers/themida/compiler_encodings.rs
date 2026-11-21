use iced_x86::{Code, Instruction, MemoryOperand, Mnemonic, Register};

use crate::unpack::x86::gpr_count;

const ACCUMULATOR: usize = 0;

pub(super) const DIRECTIONS: [(Code, Code); 36] = {
    use Code::*;
    [
        (Add_rm8_r8, Add_r8_rm8),
        (Add_rm16_r16, Add_r16_rm16),
        (Add_rm32_r32, Add_r32_rm32),
        (Add_rm64_r64, Add_r64_rm64),
        (Or_rm8_r8, Or_r8_rm8),
        (Or_rm16_r16, Or_r16_rm16),
        (Or_rm32_r32, Or_r32_rm32),
        (Or_rm64_r64, Or_r64_rm64),
        (Adc_rm8_r8, Adc_r8_rm8),
        (Adc_rm16_r16, Adc_r16_rm16),
        (Adc_rm32_r32, Adc_r32_rm32),
        (Adc_rm64_r64, Adc_r64_rm64),
        (Sbb_rm8_r8, Sbb_r8_rm8),
        (Sbb_rm16_r16, Sbb_r16_rm16),
        (Sbb_rm32_r32, Sbb_r32_rm32),
        (Sbb_rm64_r64, Sbb_r64_rm64),
        (And_rm8_r8, And_r8_rm8),
        (And_rm16_r16, And_r16_rm16),
        (And_rm32_r32, And_r32_rm32),
        (And_rm64_r64, And_r64_rm64),
        (Sub_rm8_r8, Sub_r8_rm8),
        (Sub_rm16_r16, Sub_r16_rm16),
        (Sub_rm32_r32, Sub_r32_rm32),
        (Sub_rm64_r64, Sub_r64_rm64),
        (Xor_rm8_r8, Xor_r8_rm8),
        (Xor_rm16_r16, Xor_r16_rm16),
        (Xor_rm32_r32, Xor_r32_rm32),
        (Xor_rm64_r64, Xor_r64_rm64),
        (Cmp_rm8_r8, Cmp_r8_rm8),
        (Cmp_rm16_r16, Cmp_r16_rm16),
        (Cmp_rm32_r32, Cmp_r32_rm32),
        (Cmp_rm64_r64, Cmp_r64_rm64),
        (Mov_rm8_r8, Mov_r8_rm8),
        (Mov_rm16_r16, Mov_r16_rm16),
        (Mov_rm32_r32, Mov_r32_rm32),
        (Mov_rm64_r64, Mov_r64_rm64),
    ]
}; // reg-reg: both directions, compiler picks one

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Op {
    Add = 0, // row index in DIRECTIONS
    Or = 1,
    Adc = 2,
    Sbb = 3,
    And = 4,
    Sub = 5,
    Xor = 6,
    Mov = 8,
}

#[derive(Clone, Copy)]
pub(super) struct Memory {
    pub(super) operand: MemoryOperand,
    pub(super) size: usize,
}

pub(super) fn displacement_size(displacement: i64, base: Register, bits: u32) -> u32 {
    match (displacement, base) {
        (_, Register::None | Register::RIP | Register::EIP) => 4,
        (0, _) => 0,
        (value, _) if i8::try_from(value).is_ok() => 1,
        _ => bits / 8, // iced names a disp32 by the address width
    }
}

pub(super) fn stack_pointer(bits: u32) -> Register {
    match bits {
        64 => Register::RSP,
        _ => Register::ESP,
    }
}

pub(super) fn sign_extend(value: u64, size: usize) -> i64 {
    match size {
        1 => value as u8 as i8 as i64,
        2 => value as u16 as i16 as i64,
        4 => value as u32 as i32 as i64,
        _ => value as i64,
    }
}

pub(super) fn register(index: usize, size: usize, bits: u32) -> Option<Register> {
    if index >= gpr_count(bits) {
        return None;
    }

    let index = index as u32;
    Some(match size {
        8 if bits == 64 => Register::RAX + index,
        4 => Register::EAX + index,
        2 => Register::AX + index,
        1 if index < 4 => Register::AL + index,
        1 if bits == 64 => Register::SPL + (index - 4), // rex: ah..bh become spl..dil
        _ => return None,
    })
}

fn binary_code(op: Op, size: usize, form: Form) -> Option<Code> {
    let (rm_r, r_rm) = DIRECTIONS[op as usize * 4 + column(size)?];
    Some(match form {
        Form::ToMemoryOrRegister => rm_r,
        Form::FromMemoryOrRegister => r_rm,
    })
}

fn immediate_code(op: Op, size: usize, short: bool, register: bool) -> Option<Code> {
    use Code::*;
    let codes: [Code; 4] = match (op, short) {
        (Op::Mov, _) if register => [Mov_r8_imm8, Mov_r16_imm16, Mov_r32_imm32, Mov_rm64_imm32], // b8+r
        (Op::Mov, _) => [Mov_rm8_imm8, Mov_rm16_imm16, Mov_rm32_imm32, Mov_rm64_imm32],
        (Op::Add, true) => [Add_rm8_imm8, Add_rm16_imm8, Add_rm32_imm8, Add_rm64_imm8],
        (Op::Add, false) => [Add_rm8_imm8, Add_rm16_imm16, Add_rm32_imm32, Add_rm64_imm32],
        (Op::Sub, true) => [Sub_rm8_imm8, Sub_rm16_imm8, Sub_rm32_imm8, Sub_rm64_imm8],
        (Op::Sub, false) => [Sub_rm8_imm8, Sub_rm16_imm16, Sub_rm32_imm32, Sub_rm64_imm32],
        (Op::And, true) => [And_rm8_imm8, And_rm16_imm8, And_rm32_imm8, And_rm64_imm8],
        (Op::And, false) => [And_rm8_imm8, And_rm16_imm16, And_rm32_imm32, And_rm64_imm32],
        (Op::Or, true) => [Or_rm8_imm8, Or_rm16_imm8, Or_rm32_imm8, Or_rm64_imm8],
        (Op::Or, false) => [Or_rm8_imm8, Or_rm16_imm16, Or_rm32_imm32, Or_rm64_imm32],
        (Op::Xor, true) => [Xor_rm8_imm8, Xor_rm16_imm8, Xor_rm32_imm8, Xor_rm64_imm8],
        (Op::Xor, false) => [Xor_rm8_imm8, Xor_rm16_imm16, Xor_rm32_imm32, Xor_rm64_imm32],
        (Op::Adc, true) => [Adc_rm8_imm8, Adc_rm16_imm8, Adc_rm32_imm8, Adc_rm64_imm8],
        (Op::Adc, false) => [Adc_rm8_imm8, Adc_rm16_imm16, Adc_rm32_imm32, Adc_rm64_imm32],
        (Op::Sbb, true) => [Sbb_rm8_imm8, Sbb_rm16_imm8, Sbb_rm32_imm8, Sbb_rm64_imm8],
        (Op::Sbb, false) => [Sbb_rm8_imm8, Sbb_rm16_imm16, Sbb_rm32_imm32, Sbb_rm64_imm32],
    };

    Some(codes[column(size)?])
}

fn column(size: usize) -> Option<usize> {
    Some(match size {
        1 => 0,
        2 => 1,
        4 => 2,
        8 => 3,
        _ => return None,
    })
}

#[derive(Clone, Copy)]
enum Form {
    ToMemoryOrRegister,
    FromMemoryOrRegister,
}

pub(super) fn register_register(
    bits: u32,
    op: Op,
    dest: usize,
    src: usize,
    size: usize,
) -> Option<Instruction> {
    let code = binary_code(op, size, Form::FromMemoryOrRegister)?; // Style settles the direction
    Instruction::with2(
        code,
        register(dest, size, bits)?,
        register(src, size, bits)?,
    )
    .ok()
}

pub(super) fn register_memory(
    bits: u32,
    op: Op,
    dest: usize,
    memory: &Memory,
) -> Option<Instruction> {
    let code = binary_code(op, memory.size, Form::FromMemoryOrRegister)?;
    Instruction::with2(code, register(dest, memory.size, bits)?, memory.operand).ok()
}

pub(super) fn memory_register(
    bits: u32,
    op: Op,
    memory: &Memory,
    src: usize,
) -> Option<Instruction> {
    let code = binary_code(op, memory.size, Form::ToMemoryOrRegister)?;
    Instruction::with2(code, memory.operand, register(src, memory.size, bits)?).ok()
}

pub(super) fn register_immediate(
    bits: u32,
    op: Op,
    dest: usize,
    size: usize,
    value: i64,
) -> Option<Instruction> {
    let reg = register(dest, size, bits)?;
    if op == Op::Mov && size == 8 && i32::try_from(value).is_err() {
        return Instruction::with2(Code::Mov_r64_imm64, reg, value as u64).ok();
    }

    let value = immediate_operand(size, value)?;
    let short = i8::try_from(value).is_ok();
    let code = match accumulator_code(op, size) {
        Some(code) if dest == ACCUMULATOR && (size == 1 || !short) => code, // accumulator form
        _ => immediate_code(op, size, short, true)?,
    };
    Instruction::with2(code, reg, value).ok()
}

fn accumulator_code(op: Op, size: usize) -> Option<Code> {
    use Code::*;
    let codes: [Code; 4] = match op {
        Op::Mov => return None,
        Op::Add => [Add_AL_imm8, Add_AX_imm16, Add_EAX_imm32, Add_RAX_imm32],
        Op::Sub => [Sub_AL_imm8, Sub_AX_imm16, Sub_EAX_imm32, Sub_RAX_imm32],
        Op::And => [And_AL_imm8, And_AX_imm16, And_EAX_imm32, And_RAX_imm32],
        Op::Or => [Or_AL_imm8, Or_AX_imm16, Or_EAX_imm32, Or_RAX_imm32],
        Op::Xor => [Xor_AL_imm8, Xor_AX_imm16, Xor_EAX_imm32, Xor_RAX_imm32],
        Op::Adc => [Adc_AL_imm8, Adc_AX_imm16, Adc_EAX_imm32, Adc_RAX_imm32],
        Op::Sbb => [Sbb_AL_imm8, Sbb_AX_imm16, Sbb_EAX_imm32, Sbb_RAX_imm32],
    };
    Some(codes[column(size)?])
}

pub(super) fn memory_immediate(op: Op, memory: &Memory, value: i64) -> Option<Instruction> {
    let value = immediate_operand(memory.size, value)?;
    let code = immediate_code(op, memory.size, i8::try_from(value).is_ok(), false)?;
    Instruction::with2(code, memory.operand, value).ok()
}

fn immediate_operand(size: usize, value: i64) -> Option<i32> {
    let fits = match size {
        1 => i8::try_from(value).is_ok() || u8::try_from(value).is_ok(),
        2 => i16::try_from(value).is_ok() || u16::try_from(value).is_ok(),
        4 => i32::try_from(value).is_ok() || u32::try_from(value).is_ok(),
        _ => i32::try_from(value).is_ok(), // imm32 sign-extended on x64
    };
    fits.then(|| sign_extend(value as u64, size.min(4)) as i32)
}

pub(super) fn unary_register(
    bits: u32,
    mnemonic: Mnemonic,
    dest: usize,
    size: usize,
) -> Option<Instruction> {
    let code = match (bits, size, mnemonic) {
        (32, 4, Mnemonic::Inc) => Code::Inc_r32, // one-byte 40+r, gone on x64
        (32, 4, Mnemonic::Dec) => Code::Dec_r32,
        _ => unary_code(mnemonic, size)?,
    };
    Instruction::with1(code, register(dest, size, bits)?).ok()
}

pub(super) fn unary_memory(mnemonic: Mnemonic, memory: &Memory) -> Option<Instruction> {
    Instruction::with1(unary_code(mnemonic, memory.size)?, memory.operand).ok()
}

fn unary_code(mnemonic: Mnemonic, size: usize) -> Option<Code> {
    use Code::*;
    let codes = match mnemonic {
        Mnemonic::Inc => [Inc_rm8, Inc_rm16, Inc_rm32, Inc_rm64],
        Mnemonic::Dec => [Dec_rm8, Dec_rm16, Dec_rm32, Dec_rm64],
        Mnemonic::Neg => [Neg_rm8, Neg_rm16, Neg_rm32, Neg_rm64],
        Mnemonic::Not => [Not_rm8, Not_rm16, Not_rm32, Not_rm64],
        _ => return None,
    };
    Some(codes[column(size)?])
}

pub(super) fn adjust_stack(bits: u32, delta: i64) -> Option<Instruction> {
    let op = match delta < 0 {
        true => Op::Sub,
        false => Op::Add,
    };
    let amount = i32::try_from(delta.unsigned_abs()).ok()?;
    let size = (bits / 8) as usize;
    let code = immediate_code(op, size, i8::try_from(amount).is_ok(), true)?;
    Instruction::with2(code, stack_pointer(bits), amount).ok()
}

fn by_width(bits: u32, wide: Code, narrow: Code) -> Code {
    if bits == 64 { wide } else { narrow }
}

pub(super) fn push_register(bits: u32, reg: usize) -> Option<Instruction> {
    let code = by_width(bits, Code::Push_r64, Code::Push_r32);
    Instruction::with1(code, register(reg, (bits / 8) as usize, bits)?).ok()
}

pub(super) fn push_immediate(bits: u32, value: i64) -> Option<Instruction> {
    let value = sign_extend(value as u64, (bits / 8) as usize);
    let value = i32::try_from(value).ok()?;
    let code = match (bits, i8::try_from(value).is_ok()) {
        (64, true) => Code::Pushq_imm8,
        (64, false) => Code::Pushq_imm32,
        (_, true) => Code::Pushd_imm8,
        (_, false) => Code::Pushd_imm32,
    };
    Instruction::with1(code, value).ok()
}

pub(super) fn push_memory(bits: u32, memory: &Memory) -> Option<Instruction> {
    let code = by_width(bits, Code::Push_rm64, Code::Push_rm32);
    Instruction::with1(code, memory.operand).ok()
}

pub(super) fn pop(bits: u32, reg: usize) -> Option<Instruction> {
    let code = by_width(bits, Code::Pop_r64, Code::Pop_r32);
    Instruction::with1(code, register(reg, (bits / 8) as usize, bits)?).ok()
}

pub(super) fn pop_memory(bits: u32, memory: &Memory) -> Option<Instruction> {
    let code = by_width(bits, Code::Pop_rm64, Code::Pop_rm32);
    Instruction::with1(code, memory.operand).ok()
}

pub(super) fn exchange(bits: u32, first: usize, second: usize, size: usize) -> Option<Instruction> {
    let code = exchange_code(size)?;
    Instruction::with2(
        code,
        register(first, size, bits)?,
        register(second, size, bits)?,
    )
    .ok()
}

pub(super) fn exchange_memory(bits: u32, reg: usize, memory: &Memory) -> Option<Instruction> {
    let code = exchange_code(memory.size)?;
    Instruction::with2(code, memory.operand, register(reg, memory.size, bits)?).ok()
}

fn exchange_code(size: usize) -> Option<Code> {
    use Code::*;
    Some([Xchg_rm8_r8, Xchg_rm16_r16, Xchg_rm32_r32, Xchg_rm64_r64][column(size)?])
}

pub(super) fn zero_extend_memory(
    bits: u32,
    dest: usize,
    size: usize,
    memory: &Memory,
) -> Option<Instruction> {
    let code = zero_extend_code(size, memory.size)?;
    Instruction::with2(code, register(dest, size, bits)?, memory.operand).ok()
}

pub(super) fn zero_extend_register(
    bits: u32,
    dest: usize,
    size: usize,
    src: usize,
    from: usize,
) -> Option<Instruction> {
    let code = zero_extend_code(size, from)?;
    Instruction::with2(
        code,
        register(dest, size, bits)?,
        register(src, from, bits)?,
    )
    .ok()
}

fn zero_extend_code(size: usize, from: usize) -> Option<Code> {
    Some(match (size, from) {
        (2, 1) => Code::Movzx_r16_rm8,
        (4, 1) => Code::Movzx_r32_rm8,
        (4, 2) => Code::Movzx_r32_rm16,
        (8, 1) => Code::Movzx_r64_rm8,
        (8, 2) => Code::Movzx_r64_rm16,
        _ => return None,
    })
}
