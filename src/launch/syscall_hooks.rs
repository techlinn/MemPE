use windows::Win32::Foundation::HANDLE;

use super::remote_memory::patch_code;
use crate::pe;
use crate::unpack::x86::opcodes::INT3;
use crate::{AppError, AppResult};

const STUB_PREFIX: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8]; // mov r10, rcx; mov eax, n
const ENTER_OFFSET: usize = 8; // past the service number packers check
const SYSCALL_RETURN: [u8; 3] = [0x0F, 0x05, 0xC3];
const SYSCALL_LENGTH: usize = 2;
const STUB_LENGTH: usize = 0x20;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum HookedSyscall {
    ProtectVirtualMemory,
    QueryInformationProcess,
    QueryInformationThread,
    SetInformationThread,
    CreateThreadEx,
}

impl HookedSyscall {
    const ALL: [Self; 5] = [
        Self::ProtectVirtualMemory,
        Self::QueryInformationProcess,
        Self::QueryInformationThread,
        Self::SetInformationThread,
        Self::CreateThreadEx,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::ProtectVirtualMemory => "NtProtectVirtualMemory",
            Self::QueryInformationProcess => "NtQueryInformationProcess",
            Self::QueryInformationThread => "NtQueryInformationThread",
            Self::SetInformationThread => "NtSetInformationThread",
            Self::CreateThreadEx => "NtCreateThreadEx",
        }
    }
}

pub(super) struct Hook {
    pub(super) api: HookedSyscall,
    pub(super) enter: usize,
    pub(super) syscall: usize,
    pub(super) exit: usize,
    entered: u8,
    exited: u8,
}

impl Hook {
    fn find(api: HookedSyscall, base: usize, module: &[u8]) -> Option<Self> {
        let start = pe::export_rva(module, api.name())?;
        let code = module.get(start..start + STUB_LENGTH)?;
        let syscall = code
            .windows(SYSCALL_RETURN.len())
            .position(|window| window == SYSCALL_RETURN)?;
        if !code.starts_with(&STUB_PREFIX) || syscall <= ENTER_OFFSET {
            return None;
        }

        Some(Self {
            api,
            enter: base + start + ENTER_OFFSET,
            syscall: base + start + syscall,
            exit: base + start + syscall + SYSCALL_LENGTH,
            entered: code[ENTER_OFFSET],
            exited: code[syscall + SYSCALL_LENGTH],
        })
    }
}

pub(super) fn install(process: HANDLE, base: usize, module: &[u8]) -> AppResult<Vec<Hook>> {
    let mut hooks = Vec::new();
    for api in HookedSyscall::ALL {
        let Some(hook) = Hook::find(api, base, module) else {
            return Err(unsupported(api));
        };
        hooks.push(hook);
    }

    let mut placed: Vec<Hook> = Vec::new();
    for hook in hooks {
        if patch_code(process, hook.enter, &[INT3]).is_err() {
            remove(process, &placed);
            return Err(unsupported(hook.api));
        }
        if patch_code(process, hook.exit, &[INT3]).is_err() {
            let _ = patch_code(process, hook.enter, &[hook.entered]);
            remove(process, &placed);
            return Err(unsupported(hook.api));
        }
        placed.push(hook);
    }

    Ok(placed)
}

fn unsupported(api: HookedSyscall) -> AppError {
    AppError::new(format!(
        "ntdll's {} is not in the form launch mode expects, so it cannot guarantee the program is stopped; dump it with -p instead",
        api.name()
    ))
}

pub(super) fn remove(process: HANDLE, hooks: &[Hook]) {
    for hook in hooks {
        let _ = patch_code(process, hook.enter, &[hook.entered]);
        let _ = patch_code(process, hook.exit, &[hook.exited]);
    }
}
