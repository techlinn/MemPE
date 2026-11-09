use std::sync::OnceLock;

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use super::Cpu;

#[derive(Clone, Copy, Default)]
pub(super) struct X87 {
    pub(super) st: [f64; 8], // physical registers f64 since msvc only moves doubles through st0
    pub(super) top: usize,   // TOP where st(i) is st[(top + i) % 8]
    pub(super) depth: usize, // how many values are pushed (the tag word simplified)
    pub(super) c: [bool; 4], // condition codes C0 to C3
    pub(super) cw: u16,
}

impl X87 {
    pub(super) fn phys(&self, i: usize) -> usize {
        (self.top + i) % 8
    }
}

fn ext80_to_f64(lo: u64, hi: u16) -> f64 {
    let sign = if hi & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exp = i32::from(hi & 0x7FFF);
    if exp == 0 && lo == 0 {
        return 0.0 * sign;
    }
    if exp == 0x7FFF {
        return if lo << 1 == 0 {
            sign * f64::INFINITY
        } else {
            f64::NAN
        };
    }
    sign * (lo as f64) * 2f64.powi(exp - 16383 - 63)
}

fn f64_to_ext80(v: f64) -> (u64, u16) {
    let bits = v.to_bits();
    let sign = ((bits >> 63) as u16) << 15;
    let exp = ((bits >> 52) & 0x7FF) as i32;
    let frac = bits & ((1 << 52) - 1);
    if exp == 0 && frac == 0 {
        return (0, sign);
    }
    if exp == 0x7FF {
        return (
            if frac == 0 {
                1 << 63
            } else {
                (1 << 63) | (1 << 62)
            },
            sign | 0x7FFF,
        );
    }
    let (mut mant, mut e) = if exp == 0 {
        (frac, -1022) // a subnormal double normalises into the wider exponent range
    } else {
        (frac | (1 << 52), exp - 1023)
    };
    while mant & (1 << 52) == 0 {
        mant <<= 1;
        e -= 1;
    }
    (mant << 11, sign | ((e + 16383) as u16))
}

pub(super) fn is_x87(m: Mnemonic) -> bool {
    static X87: OnceLock<Vec<bool>> = OnceLock::new();
    X87.get_or_init(|| {
        let mut table = vec![false; Mnemonic::values().len()];
        for m in Mnemonic::values() {
            table[m as usize] = format!("{m:?}").starts_with('F')
                && !matches!(m, Mnemonic::Fxsave | Mnemonic::Fxrstor);
        }
        table
    })
    .get(m as usize)
    .copied()
    .unwrap_or(false)
}

enum X87Src {
    Mem(f64), // st0 is the implied other operand
    St(usize),
}

impl Cpu<'_> {
    fn st(&self, i: usize) -> f64 {
        self.x87.st[self.x87.phys(i)]
    }

    fn set_st(&mut self, i: usize, v: f64) {
        let p = self.x87.phys(i);
        self.x87.st[p] = v;
    }

    fn x87_push(&mut self, v: f64) {
        self.x87.top = (self.x87.top + 7) % 8;
        self.x87.depth = (self.x87.depth + 1).min(8);
        self.set_st(0, v);
    }

    fn x87_pop(&mut self) {
        self.x87.top = (self.x87.top + 1) % 8;
        self.x87.depth = self.x87.depth.saturating_sub(1);
    }

    fn st_index(r: Register) -> Option<usize> {
        (Register::ST0..=Register::ST7)
            .contains(&r)
            .then(|| r as usize - Register::ST0 as usize)
    }

    fn x87_mem(&self, insn: &Instruction, integer: bool) -> Option<f64> {
        let ea = self.ea(insn);
        let size = insn.memory_size().size();
        Some(match (integer, size) {
            (true, 2) => f64::from(self.mem(ea, 2)? as u16 as i16),
            (true, 4) => f64::from(self.mem(ea, 4)? as u32 as i32),
            (true, _) => self.mem(ea, 8)? as i64 as f64,
            (false, 4) => f64::from(f32::from_bits(self.mem(ea, 4)? as u32)),
            (false, 10) => ext80_to_f64(self.mem(ea, 8)?, self.mem(ea.wrapping_add(8), 2)? as u16),
            (false, _) => f64::from_bits(self.mem(ea, 8)?),
        })
    }

    fn x87_store(
        &mut self,
        insn: &Instruction,
        v: f64,
        integer: bool,
        truncate: bool,
    ) -> Option<()> {
        let ea = self.ea(insn);
        let size = insn.memory_size().size();
        if integer {
            let r = if truncate {
                v.trunc()
            } else {
                v.round_ties_even()
            };
            let bits = size as u32 * 8;
            let fits = r >= -(2f64.powi(bits as i32 - 1)) && r < 2f64.powi(bits as i32 - 1);
            let value = if fits && !r.is_nan() {
                r as i64 as u64
            } else {
                1u64 << (bits - 1)
            };
            return self.write_mem(ea, size, value);
        }
        match size {
            4 => self.write_mem(ea, 4, u64::from((v as f32).to_bits())),
            10 => {
                let (lo, hi) = f64_to_ext80(v);
                self.write_mem(ea, 8, lo)?;
                self.write_mem(ea.wrapping_add(8), 2, u64::from(hi))
            }
            _ => self.write_mem(ea, 8, v.to_bits()),
        }
    }

    fn x87_src(&self, insn: &Instruction, integer: bool) -> Option<X87Src> {
        match insn.op_count() {
            0 => Some(X87Src::St(1)),
            1 if insn.op_kind(0) == OpKind::Memory => {
                Some(X87Src::Mem(self.x87_mem(insn, integer)?))
            }
            1 => Some(X87Src::St(Self::st_index(insn.op_register(0))?)),
            _ => Some(X87Src::St(Self::st_index(insn.op_register(1))?)),
        }
    }

    fn x87_compare_flags(&mut self, a: f64, b: f64) {
        let unordered = a.is_nan() || b.is_nan();
        self.flags.zf = unordered || a == b;
        self.flags.pf = unordered;
        self.flags.cf = unordered || a < b;
        self.flags.of = false;
        self.flags.sf = false;
        self.flags.af = false;
    }

    pub(super) fn x87_step(&mut self, insn: &Instruction) -> Option<()> {
        use Mnemonic as M;
        let m = insn.mnemonic();
        match m {
            M::Fld | M::Fild => {
                let v = match self.x87_src(insn, m == M::Fild)? {
                    X87Src::Mem(v) => v,
                    X87Src::St(i) => self.st(i),
                };
                self.x87_push(v);
            }
            M::Fld1 => self.x87_push(1.0),
            M::Fldz => self.x87_push(0.0),
            M::Fldpi => self.x87_push(std::f64::consts::PI),
            M::Fst | M::Fstp | M::Fist | M::Fistp | M::Fisttp => {
                let v = self.st(0);
                if insn.op_kind(0) == OpKind::Memory {
                    let integer = matches!(m, M::Fist | M::Fistp | M::Fisttp);
                    self.x87_store(insn, v, integer, m == M::Fisttp)?;
                } else {
                    let i = Self::st_index(insn.op_register(0))?;
                    self.set_st(i, v);
                }
                if matches!(m, M::Fstp | M::Fistp | M::Fisttp) {
                    self.x87_pop();
                }
            }
            M::Fchs => self.set_st(0, -self.st(0)),
            M::Fabs => self.set_st(0, self.st(0).abs()),
            M::Fsqrt => self.set_st(0, self.st(0).sqrt()),
            M::Fxch => {
                let i = if insn.op_count() == 0 {
                    1
                } else {
                    Self::st_index(insn.op_register(insn.op_count() - 1))?
                };
                let (a, b) = (self.st(0), self.st(i));
                self.set_st(0, b);
                self.set_st(i, a);
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
            | M::Fidivr => {
                let integer = matches!(
                    m,
                    M::Fiadd | M::Fisub | M::Fisubr | M::Fimul | M::Fidiv | M::Fidivr
                );
                let popping = matches!(
                    m,
                    M::Faddp | M::Fsubp | M::Fsubrp | M::Fmulp | M::Fdivp | M::Fdivrp
                );
                let (dst, src) = match self.x87_src(insn, integer)? {
                    X87Src::Mem(v) => (0usize, v),
                    X87Src::St(i) => {
                        let first = (insn.op_count() == 2)
                            .then(|| Self::st_index(insn.op_register(0)))
                            .flatten()
                            .unwrap_or(0);
                        if popping || first != 0 {
                            (if first != 0 { first } else { i }, self.st(0))
                        } else {
                            (0, self.st(i))
                        }
                    }
                };
                let d = self.st(dst);
                let r = match m {
                    M::Fadd | M::Faddp | M::Fiadd => d + src,
                    M::Fsub | M::Fsubp | M::Fisub => d - src,
                    M::Fsubr | M::Fsubrp | M::Fisubr => src - d,
                    M::Fmul | M::Fmulp | M::Fimul => d * src,
                    M::Fdiv | M::Fdivp | M::Fidiv => d / src,
                    _ => src / d,
                };
                self.set_st(dst, r);
                if popping {
                    self.x87_pop();
                }
            }
            M::Fcomi | M::Fcomip | M::Fucomi | M::Fucomip => {
                let i = Self::st_index(insn.op_register(1))?;
                let (a, b) = (self.st(0), self.st(i));
                self.x87_compare_flags(a, b);
                if matches!(m, M::Fcomip | M::Fucomip) {
                    self.x87_pop();
                }
            }
            M::Fcom | M::Fcomp | M::Fcompp | M::Fucom | M::Fucomp | M::Fucompp | M::Ftst => {
                let b = if m == M::Ftst {
                    0.0
                } else {
                    match self.x87_src(insn, false)? {
                        X87Src::Mem(v) => v,
                        X87Src::St(i) => self.st(i),
                    }
                };
                let a = self.st(0);
                let unordered = a.is_nan() || b.is_nan();
                self.x87.c = [unordered || a < b, false, unordered, unordered || a == b];
                let pops = match m {
                    M::Fcomp | M::Fucomp => 1,
                    M::Fcompp | M::Fucompp => 2,
                    _ => 0,
                };
                for _ in 0..pops {
                    self.x87_pop();
                }
            }
            M::Fnstsw | M::Fstsw => {
                let c = self.x87.c;
                let sw = (u64::from(c[0]) << 8)
                    | (u64::from(c[1]) << 9)
                    | (u64::from(c[2]) << 10)
                    | ((self.x87.top as u64) << 11)
                    | (u64::from(c[3]) << 14);
                if insn.op_kind(0) == OpKind::Memory {
                    self.write_mem(self.ea(insn), 2, sw)?;
                } else {
                    self.set_reg(Register::AX, sw);
                }
            }
            M::Fnstcw | M::Fstcw => self.write_mem(self.ea(insn), 2, u64::from(self.x87.cw))?,
            M::Fldcw => self.x87.cw = self.mem(self.ea(insn), 2)? as u16,
            M::Fninit | M::Finit => {
                self.x87 = super::fp::X87 {
                    cw: 0x037F,
                    ..Default::default()
                }
            }
            M::Ffree | M::Fnclex | M::Fclex | M::Fnop => {}
            M::Fincstp => self.x87.top = (self.x87.top + 1) % 8,
            M::Fdecstp => self.x87.top = (self.x87.top + 7) % 8,
            _ => return None,
        }
        Some(())
    }
}
