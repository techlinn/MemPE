use std::ops::Range;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::{FlushInstructionCache, WriteProcessMemory};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, VirtualAllocEx,
    VirtualFreeEx, VirtualProtectEx,
};

use crate::pe::{PAGE_SIZE, PeKind};
pub(super) use crate::process::read_memory as read;
use crate::process::{ACCESS_MASK, query_region};
use crate::{AppError, AppResult};

const EXECUTE_SHIFT: u32 = 4; // executable protection is plain << 4

const ALLOCATION_STEP: usize = 0x10000;
const NEAR_TRIES: usize = 0x4000; // within rel32 reach

pub(super) fn read_image(process: HANDLE, base: usize, size: usize) -> Vec<u8> {
    let mut image = vec![0u8; size];

    for (index, page) in image.chunks_mut(PAGE_SIZE).enumerate() {
        let _ = read(process, base + index * PAGE_SIZE, page);
    }

    image
}

pub(super) fn read_pointer(process: HANDLE, address: usize, kind: PeKind) -> Option<usize> {
    let mut bytes = [0u8; 8];
    let width = kind.pointer_width();

    read(process, address, &mut bytes[..width]).then(|| u64::from_le_bytes(bytes) as usize)
}

pub(super) fn write(process: HANDLE, address: usize, bytes: &[u8]) -> bool {
    unsafe {
        WriteProcessMemory(
            process,
            address as *const _,
            bytes.as_ptr().cast(),
            bytes.len(),
            None,
        )
    }
    .is_ok()
}

pub(super) fn patch_code(process: HANDLE, address: usize, bytes: &[u8]) -> AppResult<()> {
    let before = protect(process, address, bytes.len(), PAGE_EXECUTE_READWRITE)
        .ok_or_else(|| AppError::new("could not make code writable in the target"))?;

    let written = write(process, address, bytes);
    let _ = protect(process, address, bytes.len(), before);
    let _ = unsafe { FlushInstructionCache(process, Some(address as *const _), bytes.len()) };

    written
        .then_some(())
        .ok_or_else(|| AppError::new("could not write code in the target"))
}

pub(super) fn allocate(process: HANDLE, at: Option<usize>, size: usize) -> Option<usize> {
    let address = unsafe {
        VirtualAllocEx(
            process,
            at.map(|at| at as *const _),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    (!address.is_null()).then_some(address as usize)
}

pub(super) fn allocate_near(process: HANDLE, anchor: usize, size: usize) -> Option<usize> {
    let first = anchor.next_multiple_of(ALLOCATION_STEP);

    (0..NEAR_TRIES).find_map(|step| allocate(process, Some(first + step * ALLOCATION_STEP), size))
}

pub(super) fn free(process: HANDLE, address: usize) {
    let _ = unsafe { VirtualFreeEx(process, address as *mut _, 0, MEM_RELEASE) };
}

pub(super) fn protect(
    process: HANDLE,
    address: usize,
    size: usize,
    protection: PAGE_PROTECTION_FLAGS,
) -> Option<PAGE_PROTECTION_FLAGS> {
    let mut before = PAGE_PROTECTION_FLAGS::default();

    unsafe { VirtualProtectEx(process, address as *const _, size, protection, &mut before) }
        .ok()
        .map(|()| before)
}

// a guard is one-shot, so guarded code still runs and is trapped too
pub(super) fn grants_execute(protection: PAGE_PROTECTION_FLAGS) -> bool {
    let executable =
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    protection.0 & executable.0 != 0
}

pub(super) fn without_execute(protection: PAGE_PROTECTION_FLAGS) -> PAGE_PROTECTION_FLAGS {
    let access = match protection.0 & ACCESS_MASK {
        access if access == PAGE_EXECUTE.0 => PAGE_READONLY.0, // execute-only has no readable plain twin
        access => access >> EXECUTE_SHIFT,
    };

    PAGE_PROTECTION_FLAGS(protection.0 & !ACCESS_MASK | access)
}

pub(super) fn read_execute(protection: PAGE_PROTECTION_FLAGS) -> PAGE_PROTECTION_FLAGS {
    PAGE_PROTECTION_FLAGS(protection.0 & !ACCESS_MASK | PAGE_EXECUTE_READ.0)
}

pub(super) fn is_read_execute(protection: PAGE_PROTECTION_FLAGS) -> bool {
    protection.0 & ACCESS_MASK == PAGE_EXECUTE_READ.0
}

pub(super) fn allow_execute_from(process: HANDLE, address: usize) -> Option<Range<usize>> {
    let region = query_region(process, address)?;
    let access = region.protect & ACCESS_MASK;
    let plain = PAGE_READONLY.0..PAGE_EXECUTE.0;
    if region.state != MEM_COMMIT.0 || !plain.contains(&access) {
        return None;
    }

    let page = address & !(PAGE_SIZE - 1);
    let end = region.end();
    let executable = PAGE_PROTECTION_FLAGS(region.protect & !ACCESS_MASK | access << EXECUTE_SHIFT);

    protect(process, page, end.saturating_sub(page), executable).map(|_| page..end)
}
