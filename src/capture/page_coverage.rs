use std::collections::BTreeMap;
use std::ffi::c_void;
use std::mem::size_of;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_IMAGE};
use windows::Win32::System::ProcessStatus::{
    K32QueryWorkingSetEx, PSAPI_WORKING_SET_EX_INFORMATION,
};
use windows::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use super::{MAX_IMAGES, PAGE_SIZE, list_regions};
use crate::pe::{PAGE_PRIVATE, PAGE_RESIDENT};
use crate::process::TargetProcess;

const WORKING_SET_CHUNK: usize = 512;

const WORKING_SET_VALID: usize = 1;

const WORKING_SET_SHARED: usize = 1 << 15;

#[derive(Default)]
pub(super) struct PageCoverage {
    pub(super) resident: usize,
    pub(super) private: usize,
    pub(super) flags: Vec<u8>,
}

pub(super) fn measure_image_pages(target: &TargetProcess) -> BTreeMap<usize, PageCoverage> {
    let Ok(process) = target.open(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) else {
        return BTreeMap::new();
    };

    let Ok(regions) = list_regions(process.raw()) else {
        return BTreeMap::new();
    };

    let mut extents = BTreeMap::<usize, usize>::new();
    for region in regions.iter().filter(|region| {
        region.kind == MEM_IMAGE.0 && region.state == MEM_COMMIT.0 && region.allocation_base != 0
    }) {
        let end = region.end();
        extents
            .entry(region.allocation_base)
            .and_modify(|current| *current = (*current).max(end))
            .or_insert(end);
    }

    extents
        .into_iter()
        .take(MAX_IMAGES)
        .map(|(base, end)| {
            (
                base,
                measure_pages(process.raw(), base, end.saturating_sub(base)),
            )
        })
        .collect()
}

fn measure_pages(process: HANDLE, base: usize, size: usize) -> PageCoverage {
    let mut coverage = PageCoverage::default();
    let pages = size.div_ceil(PAGE_SIZE);
    coverage.flags.resize(pages, 0);

    let mut first = 0usize;
    while first < pages {
        let count = pages.saturating_sub(first).min(WORKING_SET_CHUNK);
        let mut entries = [PSAPI_WORKING_SET_EX_INFORMATION::default(); WORKING_SET_CHUNK];
        for (slot, entry) in entries.iter_mut().take(count).enumerate() {
            let offset = first.saturating_add(slot).saturating_mul(PAGE_SIZE);
            entry.VirtualAddress = base.saturating_add(offset) as *mut c_void;
        }

        let Ok(bytes) =
            u32::try_from(count.saturating_mul(size_of::<PSAPI_WORKING_SET_EX_INFORMATION>()))
        else {
            break;
        };

        if !unsafe { K32QueryWorkingSetEx(process, entries.as_mut_ptr().cast(), bytes) }.as_bool() {
            break;
        }

        for (slot, entry) in entries.iter().take(count).enumerate() {
            // union integer view, any bits valid
            let flags = unsafe { entry.VirtualAttributes.Flags };

            if flags & WORKING_SET_VALID == 0 {
                continue;
            }

            coverage.resident = coverage.resident.saturating_add(1);

            let mut bits = PAGE_RESIDENT;

            if flags & WORKING_SET_SHARED == 0 {
                coverage.private = coverage.private.saturating_add(1);
                bits |= PAGE_PRIVATE;
            }

            if let Some(page) = coverage.flags.get_mut(first.saturating_add(slot)) {
                *page = bits;
            }
        }

        first = first.saturating_add(count);
    }

    coverage.flags.truncate(first); // a failed query is not a page that was never touched

    coverage
}
