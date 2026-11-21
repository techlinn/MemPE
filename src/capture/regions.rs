use windows::Win32::Foundation::{ERROR_INVALID_PARAMETER, GetLastError, HANDLE};
use windows::Win32::System::Memory::{
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};

use super::{AddressSpace, PAGE_SIZE, READ_CHUNK};
use crate::process::{ACCESS_MASK, MAX_REGIONS, MemoryRegion, query_region};
use crate::{AppError, AppResult, win32_status};

pub(super) fn list_regions(handle: HANDLE) -> AppResult<Vec<MemoryRegion>> {
    let mut regions = Vec::with_capacity(4_096);
    let mut address = 0usize;
    for _index in 0..MAX_REGIONS {
        let Some(region) = query_region(handle, address) else {
            if regions.is_empty() {
                return Err(AppError::new(
                    "VirtualQueryEx listed no memory at all: the process is gone or the handle may not query it",
                ));
            }

            let error = unsafe { GetLastError() }; // query_region calls nothing after VirtualQueryEx

            if error != ERROR_INVALID_PARAMETER {
                return Err(win32_status("VirtualQueryEx", error.0)); // only past the last user address is the end
            }

            return Ok(regions);
        };

        let next = region
            .base
            .checked_add(region.size)
            .ok_or_else(|| AppError::new("virtual memory region address overflowed"))?;
        if region.size == 0 || next <= address {
            return Err(AppError::new(
                "VirtualQueryEx returned the same address twice",
            ));
        }

        regions.push(region);
        address = next;
    }

    Err(AppError::new("too many memory regions were returned"))
}

pub(super) fn regions_in_range(
    regions: &[MemoryRegion],
    base: usize,
    size: usize,
) -> AppResult<Vec<MemoryRegion>> {
    let end = base
        .checked_add(size)
        .ok_or_else(|| AppError::new("hidden image range overflowed"))?;
    Ok(regions
        .iter()
        .filter(|region| region.base < end && region.end() > base)
        .copied()
        .collect())
}

pub(super) fn read_region(space: &AddressSpace, base: usize, destination: &mut [u8]) -> usize {
    let mut unreadable_pages = 0usize;
    for (index, chunk) in destination.chunks_mut(READ_CHUNK).enumerate() {
        let offset = index.saturating_mul(READ_CHUNK);

        if !space.read_exact(base.saturating_add(offset), chunk) {
            unreadable_pages = unreadable_pages.saturating_add(read_pages(
                space,
                base.saturating_add(offset),
                chunk,
            ));
        }
    }

    unreadable_pages
}

fn read_pages(space: &AddressSpace, base: usize, destination: &mut [u8]) -> usize {
    let mut unreadable = 0usize;
    for (index, page) in destination.chunks_mut(PAGE_SIZE).enumerate() {
        let offset = index.saturating_mul(PAGE_SIZE);

        if !space.read_exact(base.saturating_add(offset), page) {
            page.fill(0);
            unreadable = unreadable.saturating_add(1);
        }
    }

    unreadable
}

pub(super) fn is_readable(protect: u32) -> bool {
    usable_access(protect).is_some_and(|access| {
        [
            PAGE_READONLY.0,
            PAGE_READWRITE.0,
            PAGE_WRITECOPY.0,
            PAGE_EXECUTE.0,
            PAGE_EXECUTE_READ.0,
            PAGE_EXECUTE_READWRITE.0,
            PAGE_EXECUTE_WRITECOPY.0,
        ]
        .contains(&access)
    })
}

pub(super) fn lasting_protection(protect: u32) -> Option<u32> {
    if protect & ACCESS_MASK == PAGE_NOACCESS.0 || protect & ACCESS_MASK == 0 {
        return None; // no-access replaces the protection, a guard only masks it
    }

    Some(protect & !PAGE_GUARD.0)
}

pub(super) fn is_executable(protect: u32) -> bool {
    usable_access(protect).is_some_and(|access| {
        [
            PAGE_EXECUTE.0,
            PAGE_EXECUTE_READ.0,
            PAGE_EXECUTE_READWRITE.0,
            PAGE_EXECUTE_WRITECOPY.0,
        ]
        .contains(&access)
    })
}

pub(super) fn is_writable(protect: u32) -> bool {
    usable_access(protect).is_some_and(|access| {
        [
            PAGE_READWRITE.0,
            PAGE_WRITECOPY.0,
            PAGE_EXECUTE_READWRITE.0,
            PAGE_EXECUTE_WRITECOPY.0,
        ]
        .contains(&access)
    })
}

fn usable_access(protect: u32) -> Option<u32> {
    (protect & (PAGE_GUARD.0 | PAGE_NOACCESS.0) == 0).then_some(protect & ACCESS_MASK)
}
