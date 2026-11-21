use windows::Win32::Foundation::{DUPLICATE_CLOSE_SOURCE, DuplicateHandle, HANDLE};

use super::remote_memory::{read, read_pointer, write};
use super::syscall_hooks::HookedSyscall;
use super::thread_context::Context64;
use crate::pe::PeKind;
use crate::{AppError, AppResult};

const TEB_PEB: usize = 0x60;
const WOW64_TEB: usize = 0x2000; // 32-bit teb follows the 64-bit one
const WOW64_TEB_PEB: usize = 0x30;
const BEING_DEBUGGED: usize = 2;
const PEB_GLOBAL_FLAGS: usize = 0xBC;
const PEB32_GLOBAL_FLAGS: usize = 0x68;
const DEBUG_HEAP_FLAGS: u32 = 0x70; // set when started under a debugger
const DEBUG_PORT: u64 = 0x07;
const DEBUG_OBJECT_HANDLE: u64 = 0x1E;
const DEBUG_FLAGS: u64 = 0x1F;
const EXECUTE_FLAGS: u64 = 0x22;
const NO_DEBUG_INHERIT: u32 = 1;
const DEP_OFF: u32 = 0x32; // execute enabled, handlers on any page
const PORT_NOT_SET: u64 = 0xC000_0353;
const POINTER_ANSWER_BYTES: usize = 8;
const THREAD_HIDE_FROM_DEBUGGER: u64 = 0x11; // thread info class
const CREATE_FLAGS: usize = 0x38; // seventh argument of NtCreateThreadEx
const CREATE_HIDDEN: usize = 0x04;

pub(super) fn must_fake(api: HookedSyscall, arguments: [u64; 4]) -> bool {
    api == HookedSyscall::SetInformationThread && arguments[1] == THREAD_HIDE_FROM_DEBUGGER
}

pub(super) fn before(process: HANDLE, api: HookedSyscall, registers: &Context64) -> AppResult<()> {
    if api != HookedSyscall::CreateThreadEx {
        return Ok(());
    }

    let flags = registers.stack() + CREATE_FLAGS;
    let shown = read_pointer(process, flags, PeKind::Pe32Plus).is_some_and(|requested| {
        requested & CREATE_HIDDEN == 0
            || write(process, flags, &(requested & !CREATE_HIDDEN).to_le_bytes())
    });

    shown.then_some(()).ok_or_else(|| {
        AppError::new("could not keep a new thread of the program visible to the debugger")
    })
}

pub(super) fn after(
    process: HANDLE,
    api: HookedSyscall,
    arguments: [u64; 4],
    registers: &mut Context64,
    narrow: bool,
) -> AppResult<()> {
    let [_, class, buffer, length] = arguments;
    let buffer = buffer as usize;
    if registers.result() != 0 {
        return Ok(());
    }

    if api == HookedSyscall::QueryInformationThread && class == THREAD_HIDE_FROM_DEBUGGER {
        return answer(process, buffer, &[1]);
    }
    if api != HookedSyscall::QueryInformationProcess {
        return Ok(());
    }

    match class {
        DEBUG_PORT => {
            let zero = [0u8; POINTER_ANSWER_BYTES];
            answer(
                process,
                buffer,
                &zero[..(length as usize).min(POINTER_ANSWER_BYTES)],
            )
        }
        DEBUG_OBJECT_HANDLE => {
            if let Some(handle) = read_pointer(process, buffer, PeKind::Pe32Plus) {
                let leaked = HANDLE(handle as *mut _);
                let _ = unsafe {
                    DuplicateHandle(
                        process,
                        leaked,
                        HANDLE::default(),
                        std::ptr::null_mut(),
                        0,
                        false,
                        DUPLICATE_CLOSE_SOURCE,
                    )
                }; // the query opened a handle
            }

            registers.set_result(PORT_NOT_SET);
            answer(process, buffer, &[0u8; POINTER_ANSWER_BYTES])
        }
        DEBUG_FLAGS => answer(process, buffer, &NO_DEBUG_INHERIT.to_le_bytes()),
        EXECUTE_FLAGS if narrow => answer(process, buffer, &DEP_OFF.to_le_bytes()), // old stubs need dep reported off
        _ => Ok(()),
    }
}

fn answer(process: HANDLE, buffer: usize, bytes: &[u8]) -> AppResult<()> {
    write(process, buffer, bytes).then_some(()).ok_or_else(|| {
        AppError::new("could not rewrite what windows told the program about its debugger")
    })
}

pub(super) fn clear_debugged_flag(process: HANDLE, teb: usize, kind: PeKind) -> AppResult<()> {
    for (peb, _) in pebs(process, teb, kind)? {
        if !write(process, peb + BEING_DEBUGGED, &[0]) {
            return Err(not_hidden());
        }
    }

    Ok(())
}

pub(super) fn clear_debug_heap_flags(process: HANDLE, teb: usize, kind: PeKind) -> AppResult<()> {
    for (peb, global_flags) in pebs(process, teb, kind)? {
        let mut flags = [0u8; 4];
        if !read(process, peb + global_flags, &mut flags) {
            return Err(not_hidden());
        }

        let cleared = u32::from_le_bytes(flags) & !DEBUG_HEAP_FLAGS;
        if !write(process, peb + global_flags, &cleared.to_le_bytes()) {
            return Err(not_hidden());
        }
    }

    Ok(())
}

fn pebs(process: HANDLE, teb: usize, kind: PeKind) -> AppResult<Vec<(usize, usize)>> {
    let native = read_pointer(process, teb + TEB_PEB, PeKind::Pe32Plus).ok_or_else(not_hidden)?;
    let mut pebs = vec![(native, PEB_GLOBAL_FLAGS)];

    if kind == PeKind::Pe32 {
        let wow64 = read_pointer(process, teb + WOW64_TEB + WOW64_TEB_PEB, PeKind::Pe32)
            .ok_or_else(not_hidden)?;
        pebs.push((wow64, PEB32_GLOBAL_FLAGS));
    }

    Ok(pebs)
}

fn not_hidden() -> AppError {
    AppError::new("could not clear the marks windows leaves in a program started under a debugger")
}
