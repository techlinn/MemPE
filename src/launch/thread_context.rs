use std::mem::offset_of;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_FLAGS, CONTEXT_FLOATING_POINT_AMD64,
    CONTEXT_INTEGER_AMD64, GetThreadContext, SetThreadContext, WOW64_CONTEXT,
    WOW64_CONTEXT_CONTROL, WOW64_CONTEXT_EXTENDED_REGISTERS, WOW64_CONTEXT_FLAGS,
    WOW64_CONTEXT_FLOATING_POINT, WOW64_CONTEXT_INTEGER, Wow64GetThreadContext,
    Wow64SetThreadContext,
};

use super::remote_memory::{read, read_pointer, write};
use crate::AppResult;
use crate::pe::PeKind;
use crate::unpack::x86::opcodes::INT3;
use crate::windows_error;

const NATIVE_RCX: usize = offset_of!(CONTEXT, Rcx);
const NATIVE_RDX: usize = offset_of!(CONTEXT, Rdx);
pub(super) const NATIVE_RSP: usize = offset_of!(CONTEXT, Rsp);
pub(super) const NATIVE_RIP: usize = offset_of!(CONTEXT, Rip);
pub(super) const WOW64_ESP: usize = offset_of!(WOW64_CONTEXT, Esp);
pub(super) const WOW64_EIP: usize = offset_of!(WOW64_CONTEXT, Eip);
const TRAP_FLAG: u32 = 0x100;

#[repr(align(16))]
pub(super) struct Context64(CONTEXT); // must be 16-byte aligned

impl Context64 {
    pub(super) fn of(thread: HANDLE) -> AppResult<Self> {
        Self::with(thread, CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64)
    }

    fn with(thread: HANDLE, parts: CONTEXT_FLAGS) -> AppResult<Self> {
        let mut context = Self(CONTEXT {
            ContextFlags: parts,
            ..Default::default()
        });

        unsafe { GetThreadContext(thread, &mut context.0) }
            .map_err(|error| windows_error("GetThreadContext", error))?;
        Ok(context)
    }

    pub(super) fn apply(&self, thread: HANDLE) -> AppResult<()> {
        unsafe { SetThreadContext(thread, &self.0) }
            .map_err(|error| windows_error("SetThreadContext", error))
    }

    pub(super) fn arguments(&self) -> [u64; 4] {
        [self.0.Rcx, self.0.Rdx, self.0.R8, self.0.R9]
    }

    pub(super) fn result(&self) -> u64 {
        self.0.Rax
    }

    pub(super) fn set_result(&mut self, status: u64) {
        self.0.Rax = status;
    }

    pub(super) fn stack(&self) -> usize {
        self.0.Rsp as usize
    }

    pub(super) fn jump(&mut self, pc: usize) {
        self.0.Rip = pc as u64;
    }

    pub(super) fn simulate_ret(&mut self, caller: usize) {
        self.0.Rip = caller as u64;
        self.0.Rsp += size_of::<u64>() as u64;
    }
}

pub(super) struct StopFrame {
    pub(super) pc: usize,
    pub(super) sp: usize,
    pub(super) registers: Option<[usize; 2]>, // rcx, rdx
}

pub(super) enum ThreadContext {
    Native(Box<Context64>),
    Wow64(Box<WOW64_CONTEXT>),
}

impl ThreadContext {
    pub(super) fn of(thread: HANDLE, kind: PeKind) -> AppResult<Self> {
        Self::capture(
            thread,
            kind,
            CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64,
            WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER,
        )
    }

    pub(super) fn with_float_state(thread: HANDLE, kind: PeKind) -> AppResult<Self> {
        Self::capture(
            thread,
            kind,
            CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64 | CONTEXT_FLOATING_POINT_AMD64,
            WOW64_CONTEXT_CONTROL
                | WOW64_CONTEXT_INTEGER
                | WOW64_CONTEXT_FLOATING_POINT
                | WOW64_CONTEXT_EXTENDED_REGISTERS,
        )
    }

    fn capture(
        thread: HANDLE,
        kind: PeKind,
        native: CONTEXT_FLAGS,
        wow64: WOW64_CONTEXT_FLAGS,
    ) -> AppResult<Self> {
        match kind {
            PeKind::Pe32Plus => Ok(Self::Native(Box::new(Context64::with(thread, native)?))),
            PeKind::Pe32 => {
                let mut context = Box::new(WOW64_CONTEXT {
                    ContextFlags: wow64,
                    ..Default::default()
                });

                unsafe { Wow64GetThreadContext(thread, &mut *context) }
                    .map_err(|error| windows_error("Wow64GetThreadContext", error))?;
                Ok(Self::Wow64(context))
            }
        }
    }

    pub(super) fn apply(&self, thread: HANDLE) -> AppResult<()> {
        match self {
            Self::Native(context) => context.apply(thread),
            Self::Wow64(context) => unsafe { Wow64SetThreadContext(thread, &**context) }
                .map_err(|error| windows_error("Wow64SetThreadContext", error)),
        }
    }

    pub(super) fn frame(&self) -> StopFrame {
        match self {
            Self::Native(context) => StopFrame {
                pc: context.0.Rip as usize,
                sp: context.0.Rsp as usize,
                registers: Some([context.0.Rcx as usize, context.0.Rdx as usize]),
            },
            Self::Wow64(context) => StopFrame {
                pc: context.Eip as usize,
                sp: context.Esp as usize,
                registers: None,
            },
        }
    }

    pub(super) fn result(&self) -> usize {
        match self {
            Self::Native(context) => context.0.Rax as usize,
            Self::Wow64(context) => context.Eax as usize,
        }
    }

    fn redirect(&mut self, pc: usize, sp: usize) {
        match self {
            Self::Native(context) => {
                context.0.Rip = pc as u64;
                context.0.Rsp = sp as u64;
            }
            Self::Wow64(context) => {
                context.Eip = pc as u32;
                context.Esp = sp as u32;
            }
        }
    }

    fn flags(&mut self) -> &mut u32 {
        match self {
            Self::Native(context) => &mut context.0.EFlags,
            Self::Wow64(context) => &mut context.EFlags,
        }
    }

    pub(super) fn restore(&mut self, process: HANDLE, thread: HANDLE) -> AppResult<()> {
        let StopFrame { pc, sp, .. } = self.frame();
        let mut first = [0u8; 1];
        let at_breakpoint = read(process, pc, &mut first) && first[0] == INT3; // else the breakpoint runs again

        self.redirect(pc + usize::from(at_breakpoint), sp);
        self.apply(thread)
    }
}

pub(super) fn read_frame(thread: HANDLE, kind: PeKind) -> AppResult<StopFrame> {
    Ok(ThreadContext::of(thread, kind)?.frame())
}

pub(super) fn redirect(thread: HANDLE, kind: PeKind, pc: usize, sp: usize) -> AppResult<()> {
    let mut context = ThreadContext::of(thread, kind)?;
    context.redirect(pc, sp);
    context.apply(thread)
}

pub(super) fn single_step(thread: HANDLE, kind: PeKind) -> AppResult<()> {
    let mut context = ThreadContext::of(thread, kind)?;
    *context.flags() |= TRAP_FLAG;
    context.apply(thread)
}

pub(super) fn saved_frame(process: HANDLE, context: usize, kind: PeKind) -> Option<StopFrame> {
    let field = |offset: usize| read_pointer(process, context + offset, kind);

    match kind {
        PeKind::Pe32Plus => Some(StopFrame {
            pc: field(NATIVE_RIP)?,
            sp: field(NATIVE_RSP)?,
            registers: Some([field(NATIVE_RCX)?, field(NATIVE_RDX)?]),
        }),
        PeKind::Pe32 => Some(StopFrame {
            pc: field(WOW64_EIP)?,
            sp: field(WOW64_ESP)?,
            registers: None,
        }),
    }
}

pub(super) fn save_frame(
    process: HANDLE,
    context: usize,
    kind: PeKind,
    pc: usize,
    sp: usize,
) -> bool {
    let width = kind.pointer_width();
    let (pc_at, sp_at) = match kind {
        PeKind::Pe32Plus => (NATIVE_RIP, NATIVE_RSP),
        PeKind::Pe32 => (WOW64_EIP, WOW64_ESP),
    };

    write(process, context + pc_at, &pc.to_le_bytes()[..width])
        && write(process, context + sp_at, &sp.to_le_bytes()[..width])
}
