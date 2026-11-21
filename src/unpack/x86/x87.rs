use std::cmp::Ordering;

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use super::emulator::Cpu;

const SIGN: u16 = 0x8000;
const EXPONENT: u16 = 0x7FFF;
const BIAS: i32 = 16383;
const INTEGER_BIT: u64 = 1 << 63;
const POWER_ON_CONTROL_WORD: u16 = 0x037F; // exceptions masked, nearest, 64-bit precision
const ROUNDING_SHIFT: u16 = 10; // control word bits 10 and 11
const PRECISION_MASKED: u16 = 1 << 5;
const REGISTERS: usize = 8;

const DOUBLE_BIAS: i32 = 1023;
const DOUBLE_EXPONENTS: std::ops::RangeInclusive<i32> = -1022..=1023; // normal doubles
const DOUBLE_EXPONENT_FIELD: u64 = 0x7FF;
const DOUBLE_FRACTION_BITS: u32 = 52;
const BITS_A_DOUBLE_DROPS: u64 = (1 << 11) - 1;
const CHECKED_EXPONENT: i32 = 400; // the fma residue cannot underflow inside it

#[derive(Clone, Copy, PartialEq)]
pub(super) struct X87 {
    st: [Ext80; REGISTERS],
    used: [bool; REGISTERS],
    top: usize,
    c: [bool; 4], // c0..c3
    cw: u16,
    status_known: bool, // an inexact store sets bits this does not model
}

impl Default for X87 {
    fn default() -> Self {
        Self {
            st: [Ext80::default(); REGISTERS],
            used: [false; REGISTERS],
            top: 0,
            c: [false; 4],
            cw: POWER_ON_CONTROL_WORD,
            status_known: true,
        }
    }
}

impl X87 {
    fn physical(&self, i: usize) -> usize {
        (self.top + i) % REGISTERS
    }

    fn rounding(&self) -> Rounding {
        match (self.cw >> ROUNDING_SHIFT) & 3 {
            0 => Rounding::Nearest,
            1 => Rounding::Down,
            2 => Rounding::Up,
            _ => Rounding::Zero,
        }
    }

    fn get(&self, i: usize) -> Option<Ext80> {
        let slot = self.physical(i);
        self.used[slot].then_some(self.st[slot])
    }

    fn set(&mut self, i: usize, value: Ext80) {
        let slot = self.physical(i);
        self.st[slot] = value;
        self.used[slot] = true;
    }

    fn free(&mut self, i: usize) {
        let slot = self.physical(i);
        self.used[slot] = false;
    }

    fn push(&mut self, value: Ext80) -> Option<()> {
        let slot = self.physical(REGISTERS - 1);
        if self.used[slot] {
            return None; // stack fault
        }

        self.top = slot;
        self.set(0, value);
        Some(())
    }

    fn pop(&mut self) -> Option<()> {
        self.get(0)?;
        self.free(0);
        self.top = self.physical(1);
        Some(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Rounding {
    Nearest,
    Down,
    Up,
    Zero,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Ext80 {
    mantissa: u64,
    sign_exponent: u16,
}

impl Ext80 {
    const ONE: Self = Self {
        mantissa: INTEGER_BIT,
        sign_exponent: BIAS as u16,
    };
    const PI: Self = Self {
        mantissa: 0xC90F_DAA2_2168_C235,
        sign_exponent: 0x4000,
    };

    fn negative(self) -> bool {
        self.sign_exponent & SIGN != 0
    }

    fn exponent(self) -> i32 {
        i32::from(self.sign_exponent & EXPONENT)
    }

    fn is_zero(self) -> bool {
        self.exponent() == 0 && self.mantissa == 0
    }

    fn is_infinite(self) -> bool {
        self.exponent() == i32::from(EXPONENT) && self.mantissa == INTEGER_BIT
    }

    fn is_normal(self) -> bool {
        (1..i32::from(EXPONENT)).contains(&self.exponent()) && self.mantissa & INTEGER_BIT != 0
    }

    fn negated(self) -> Self {
        Self {
            sign_exponent: self.sign_exponent ^ SIGN,
            ..self
        }
    }

    fn abs(self) -> Self {
        Self {
            sign_exponent: self.sign_exponent & EXPONENT,
            ..self
        }
    }

    fn from_memory(mantissa: u64, sign_exponent: u16) -> Option<Self> {
        let value = Self {
            mantissa,
            sign_exponent,
        };
        (value.is_zero() || value.is_normal() || value.is_infinite()).then_some(value) // nans and denormals raise flags
    }

    fn from_integer(value: i64) -> Self {
        if value == 0 {
            return Self::default();
        }

        let sign = if value < 0 { SIGN } else { 0 };
        let magnitude = value.unsigned_abs();
        let shift = magnitude.leading_zeros();
        Self {
            mantissa: magnitude << shift,
            sign_exponent: sign | (BIAS + 63 - shift as i32) as u16,
        }
    }

    fn to_integer(self, rounding: Rounding) -> Option<i128> {
        if self.exponent() == i32::from(EXPONENT) {
            return None;
        }

        let shift = BIAS + 63 - self.exponent(); // value is mantissa / 2^shift
        let mantissa = u128::from(self.mantissa);
        let magnitude = match shift {
            ..=0 if -shift >= 64 => return None,
            ..=0 => mantissa << -shift,
            128.. => self.rounded(0, Ordering::Less, mantissa != 0, rounding),
            _ => {
                let whole = mantissa >> shift;
                let rest = mantissa & ((1 << shift) - 1);
                let half = 1 << (shift - 1);
                self.rounded(whole, rest.cmp(&half), rest != 0, rounding)
            }
        };

        let magnitude = i128::try_from(magnitude).ok()?;
        Some(if self.negative() {
            -magnitude
        } else {
            magnitude
        })
    }

    fn is_whole(self) -> bool {
        self.to_integer(Rounding::Down) == self.to_integer(Rounding::Up)
    }

    fn rounded(self, whole: u128, half: Ordering, inexact: bool, rounding: Rounding) -> u128 {
        let away = match rounding {
            Rounding::Zero => false,
            Rounding::Down => self.negative() && inexact,
            Rounding::Up => !self.negative() && inexact,
            Rounding::Nearest => match half {
                Ordering::Greater => true,
                Ordering::Equal => whole & 1 == 1,
                Ordering::Less => false,
            },
        };
        whole + u128::from(away)
    }

    fn from_f64(value: f64) -> Option<Self> {
        let bits = value.to_bits();
        let sign = ((bits >> 63) as u16) << 15;
        let exponent = ((bits >> DOUBLE_FRACTION_BITS) & DOUBLE_EXPONENT_FIELD) as i32;
        let fraction = bits & ((1 << DOUBLE_FRACTION_BITS) - 1);
        let all_ones = DOUBLE_EXPONENT_FIELD as i32;

        match (exponent, fraction) {
            (0, 0) => Some(Self {
                mantissa: 0,
                sign_exponent: sign,
            }),
            (0, _) => None, // denormal operand flag
            (field, 0) if field == all_ones => Some(Self {
                mantissa: INTEGER_BIT,
                sign_exponent: sign | EXPONENT,
            }),
            (field, _) if field == all_ones => None,
            _ => Some(Self {
                mantissa: INTEGER_BIT | (fraction << 11),
                sign_exponent: sign | (exponent - DOUBLE_BIAS + BIAS) as u16,
            }),
        }
    }

    fn to_f64(self) -> Option<f64> {
        let sign = u64::from(self.negative()) << 63;
        if self.is_zero() {
            return Some(f64::from_bits(sign));
        }

        let exponent = self.exponent() - BIAS;
        let fits = self.is_normal()
            && self.mantissa & BITS_A_DOUBLE_DROPS == 0
            && DOUBLE_EXPONENTS.contains(&exponent);
        let field = ((exponent + DOUBLE_BIAS) as u64) << DOUBLE_FRACTION_BITS;
        let fraction = (self.mantissa << 1) >> 12; // without the integer bit
        fits.then(|| f64::from_bits(sign | field | fraction))
    }

    fn compare(self, other: Self) -> Ordering {
        if self.is_zero() && other.is_zero() {
            return Ordering::Equal; // +0 and -0
        }

        let magnitude = |value: Self| (value.exponent(), value.mantissa);
        match (self.negative(), other.negative()) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => magnitude(self).cmp(&magnitude(other)),
            (true, true) => magnitude(other).cmp(&magnitude(self)),
        }
    }
}

fn checked(value: f64) -> bool {
    let floor = 2f64.powi(-CHECKED_EXPONENT);
    let ceiling = 2f64.powi(CHECKED_EXPONENT);
    (floor..=ceiling).contains(&value.abs())
}

fn exact_sum(a: f64, b: f64, rounding: Rounding) -> Option<f64> {
    let sum = a + b;
    let b_part = sum - a;
    let error = (a - (sum - b_part)) + (b - b_part); // two-sum

    let signed_zero = sum == 0.0 && rounding != Rounding::Nearest; // rounding picks its sign
    (sum.is_finite() && error == 0.0 && !signed_zero).then_some(sum)
}

fn exact_product(a: f64, b: f64) -> Option<f64> {
    let product = a * b;
    if a == 0.0 || b == 0.0 {
        return (a.is_finite() && b.is_finite()).then_some(product);
    }

    let exact = checked(a) && checked(b) && checked(product) && a.mul_add(b, -product) == 0.0;
    exact.then_some(product)
}

fn exact_quotient(a: f64, b: f64) -> Option<f64> {
    if b == 0.0 || !b.is_finite() {
        return None;
    }
    let quotient = a / b;
    if a == 0.0 {
        return Some(quotient);
    }

    let exact = checked(a) && checked(b) && checked(quotient) && quotient.mul_add(b, -a) == 0.0;
    exact.then_some(quotient)
}

fn exact_root(a: f64) -> Option<f64> {
    if a == 0.0 {
        return Some(a);
    }

    let root = a.sqrt();
    (a > 0.0 && checked(a) && root.mul_add(root, -a) == 0.0).then_some(root)
}

enum X87Operand {
    Mem(Ext80), // against st0
    St(usize),
}

impl Cpu<'_> {
    fn st_index(r: Register) -> Option<usize> {
        (Register::ST0..=Register::ST7)
            .contains(&r)
            .then(|| r as usize - Register::ST0 as usize)
    }

    fn x87_load(&self, insn: &Instruction, integer: bool) -> Option<Ext80> {
        let ea = self.effective_address(insn)?;
        let size = insn.memory_size().size();
        match (integer, size) {
            (true, 2) => Some(Ext80::from_integer(i64::from(
                self.mem(ea, 2)? as u16 as i16
            ))),
            (true, 4) => Some(Ext80::from_integer(i64::from(
                self.mem(ea, 4)? as u32 as i32
            ))),
            (true, 8) => Some(Ext80::from_integer(self.mem(ea, 8)? as i64)),
            (false, 4) => Ext80::from_f64(f64::from(f32::from_bits(self.mem(ea, 4)? as u32))),
            (false, 8) => Ext80::from_f64(f64::from_bits(self.mem(ea, 8)?)),
            (false, 10) => {
                Ext80::from_memory(self.mem(ea, 8)?, self.mem(ea.wrapping_add(8), 2)? as u16)
            }
            _ => None,
        }
    }

    fn x87_store_integer(&mut self, insn: &Instruction, v: Ext80, truncate: bool) -> Option<()> {
        let ea = self.effective_address(insn)?;
        let size = insn.memory_size().size();
        if !matches!(size, 2 | 4 | 8) {
            return None;
        }
        let rounding = match truncate {
            true => Rounding::Zero,
            false => self.x87.rounding(),
        };

        let limit = 1i128 << (size * 8 - 1);
        let value = v
            .to_integer(rounding)
            .filter(|value| (-limit..limit).contains(value))?; // else the invalid flag
        if !v.is_whole() {
            if self.x87.cw & PRECISION_MASKED == 0 {
                return None; // traps
            }
            self.x87.status_known = false;
        }

        self.write_mem(ea, size, value as i64 as u64)
    }

    fn x87_store_float(&mut self, insn: &Instruction, v: Ext80) -> Option<()> {
        let ea = self.effective_address(insn)?;
        match insn.memory_size().size() {
            4 => {
                let wide = v.to_f64()?;
                let narrow = wide as f32;
                let exact = f64::from(narrow) == wide && (narrow == 0.0 || narrow.is_normal());
                exact.then_some(())?;
                self.write_mem(ea, 4, u64::from(narrow.to_bits()))
            }
            8 => self.write_mem(ea, 8, v.to_f64()?.to_bits()),
            10 => {
                self.write_mem(ea, 8, v.mantissa)?;
                self.write_mem(ea.wrapping_add(8), 2, u64::from(v.sign_exponent))
            }
            _ => None,
        }
    }

    fn x87_operand(&self, insn: &Instruction, integer: bool) -> Option<X87Operand> {
        match insn.op_count() {
            0 => Some(X87Operand::St(1)),
            1 if insn.op_kind(0) == OpKind::Memory => {
                Some(X87Operand::Mem(self.x87_load(insn, integer)?))
            }
            1 => Some(X87Operand::St(Self::st_index(insn.op_register(0))?)),
            _ => Some(X87Operand::St(Self::st_index(insn.op_register(1))?)),
        }
    }

    fn x87_value(&self, operand: X87Operand) -> Option<Ext80> {
        match operand {
            X87Operand::Mem(value) => Some(value),
            X87Operand::St(i) => self.x87.get(i),
        }
    }

    fn set_eflags_from_compare(&mut self, a: Ext80, b: Ext80) {
        let order = a.compare(b);
        self.flags.zf = order.is_eq();
        self.flags.pf = false;
        self.flags.cf = order.is_lt();
        self.flags.of = false;
        self.flags.sf = false;
        self.flags.af = false;
    }

    fn x87_arithmetic(&mut self, insn: &Instruction) -> Option<()> {
        use Mnemonic as M;
        let m = insn.mnemonic();
        let integer = matches!(
            m,
            M::Fiadd | M::Fisub | M::Fisubr | M::Fimul | M::Fidiv | M::Fidivr
        );
        let popping = matches!(
            m,
            M::Faddp | M::Fsubp | M::Fsubrp | M::Fmulp | M::Fdivp | M::Fdivrp
        );

        let (dst, src) = match self.x87_operand(insn, integer)? {
            X87Operand::Mem(v) => (0, v),
            X87Operand::St(i) if insn.op_count() == 2 => {
                (Self::st_index(insn.op_register(0))?, self.x87.get(i)?)
            }
            X87Operand::St(i) if popping => (i, self.x87.get(0)?),
            X87Operand::St(i) => (0, self.x87.get(i)?),
        };

        let (d, src) = (self.x87.get(dst)?.to_f64()?, src.to_f64()?);
        let rounding = self.x87.rounding();
        let r = match m {
            M::Fadd | M::Faddp | M::Fiadd => exact_sum(d, src, rounding),
            M::Fsub | M::Fsubp | M::Fisub => exact_sum(d, -src, rounding),
            M::Fsubr | M::Fsubrp | M::Fisubr => exact_sum(src, -d, rounding),
            M::Fmul | M::Fmulp | M::Fimul => exact_product(d, src),
            M::Fdiv | M::Fdivp | M::Fidiv => exact_quotient(d, src),
            _ => exact_quotient(src, d),
        }?;

        self.x87.set(dst, Ext80::from_f64(r)?);
        if popping {
            self.x87.pop()?;
        }
        Some(())
    }

    pub(super) fn x87_step(&mut self, insn: &Instruction) -> Option<()> {
        use Mnemonic as M;
        let m = insn.mnemonic();
        match m {
            M::Fld | M::Fild => {
                let v = self.x87_value(self.x87_operand(insn, m == M::Fild)?)?;
                self.x87.push(v)?;
            }
            M::Fld1 => self.x87.push(Ext80::ONE)?,
            M::Fldz => self.x87.push(Ext80::default())?,
            M::Fldpi => self.x87.push(Ext80::PI)?,
            M::Fst | M::Fstp | M::Fist | M::Fistp | M::Fisttp => {
                let v = self.x87.get(0)?;
                match (insn.op_kind(0), m) {
                    (OpKind::Memory, M::Fst | M::Fstp) => self.x87_store_float(insn, v)?,
                    (OpKind::Memory, _) => self.x87_store_integer(insn, v, m == M::Fisttp)?,
                    _ => self.x87.set(Self::st_index(insn.op_register(0))?, v),
                }
                if matches!(m, M::Fstp | M::Fistp | M::Fisttp) {
                    self.x87.pop()?;
                }
            }
            M::Fchs => self.x87.set(0, self.x87.get(0)?.negated()),
            M::Fabs => self.x87.set(0, self.x87.get(0)?.abs()),
            M::Fsqrt => {
                let root = exact_root(self.x87.get(0)?.to_f64()?)?;
                self.x87.set(0, Ext80::from_f64(root)?);
            }
            M::Fxch => {
                let i = if insn.op_count() == 0 {
                    1
                } else {
                    Self::st_index(insn.op_register(insn.op_count() - 1))?
                };
                let (a, b) = (self.x87.get(0)?, self.x87.get(i)?);
                self.x87.set(0, b);
                self.x87.set(i, a);
            }
            M::Fadd
            | M::Faddp
            | M::Fiadd
            | M::Fsub
            | M::Fsubp
            | M::Fisub
            | M::Fsubr
            | M::Fsubrp
            | M::Fisubr
            | M::Fmul
            | M::Fmulp
            | M::Fimul
            | M::Fdiv
            | M::Fdivp
            | M::Fidiv
            | M::Fdivr
            | M::Fdivrp
            | M::Fidivr => self.x87_arithmetic(insn)?,
            M::Fcomi | M::Fcomip | M::Fucomi | M::Fucomip => {
                let i = Self::st_index(insn.op_register(1))?;
                let (a, b) = (self.x87.get(0)?, self.x87.get(i)?);
                self.set_eflags_from_compare(a, b);
                if matches!(m, M::Fcomip | M::Fucomip) {
                    self.x87.pop()?;
                }
            }
            M::Fcom | M::Fcomp | M::Fcompp | M::Fucom | M::Fucomp | M::Fucompp | M::Ftst => {
                let b = match m {
                    M::Ftst => Ext80::default(),
                    _ => self.x87_value(self.x87_operand(insn, false)?)?,
                };
                let order = self.x87.get(0)?.compare(b);
                self.x87.c = [order.is_lt(), false, false, order.is_eq()];

                let pops = match m {
                    M::Fcomp | M::Fucomp => 1,
                    M::Fcompp | M::Fucompp => 2,
                    _ => 0,
                };
                for _ in 0..pops {
                    self.x87.pop()?;
                }
            }
            M::Fnstsw | M::Fstsw => {
                self.x87.status_known.then_some(())?;
                let c = self.x87.c;
                let sw = (u64::from(c[0]) << 8)
                    | (u64::from(c[1]) << 9)
                    | (u64::from(c[2]) << 10)
                    | ((self.x87.top as u64) << 11)
                    | (u64::from(c[3]) << 14);
                if insn.op_kind(0) == OpKind::Memory {
                    self.write_mem(self.effective_address(insn)?, 2, sw)?;
                } else {
                    self.set_reg(Register::AX, sw)?;
                }
            }
            M::Fnstcw | M::Fstcw => {
                self.write_mem(self.effective_address(insn)?, 2, u64::from(self.x87.cw))?
            }
            M::Fldcw => self.x87.cw = self.mem(self.effective_address(insn)?, 2)? as u16,
            M::Fninit | M::Finit => self.x87 = X87::default(),
            M::Ffree => self.x87.free(Self::st_index(insn.op_register(0))?),
            M::Fnclex | M::Fclex | M::Fnop => {}
            M::Fincstp => self.x87.top = self.x87.physical(1),
            M::Fdecstp => self.x87.top = self.x87.physical(REGISTERS - 1),
            _ => return None,
        }
        Some(())
    }
}
