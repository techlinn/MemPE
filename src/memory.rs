use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_void;
use std::fmt::{Display, Formatter};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::mem::size_of;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ProcessSnapshotting::{
    HPSS, PSS_CAPTURE_VA_CLONE, PSS_CREATE_BREAKAWAY, PSS_CREATE_BREAKAWAY_OPTIONAL,
    PSS_CREATE_USE_VM_ALLOCATIONS, PSS_QUERY_VA_CLONE_INFORMATION, PSS_VA_CLONE_INFORMATION,
    PssCaptureSnapshot, PssFreeSnapshot, PssQuerySnapshot,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY, VirtualQueryEx,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, PROCESS_CREATE_PROCESS, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

use crate::pe::RegionEvidence;
use crate::process::{OwnedHandle, TargetProcess};
use crate::{AppError, AppResult};

const MAX_MEMORY_REGIONS: usize = 1_048_576;
const MAX_IMAGES: usize = 4_096;
const MAX_IMAGE_SIZE: usize = 1024 * 1024 * 1024;
const MAX_TOTAL_IMAGE_BYTES: usize = 4 * 1024 * 1024 * 1024;
const READ_CHUNK: usize = 64 * 1024;
const PAGE_SIZE: usize = 4 * 1024;
const MAX_HEADER_READ: usize = 64 * 1024;
const MAX_NON_IMAGE_SCAN_PAGES: usize = 262_144;
const STABLE_POLL_COUNT: usize = 30;
const STABLE_MATCH_COUNT: usize = 3;
const STABLE_POLL_DELAY: Duration = Duration::from_millis(100);
const MAX_STABILITY_READS: usize = 256;

pub(crate) enum AcquisitionMode {
    PssClone,
    LiveRead,
}

impl Display for AcquisitionMode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PssClone => formatter.write_str("PSS snapshot"),
            Self::LiveRead => formatter.write_str("live process read"),
        }
    }
}

pub(crate) struct CapturedImage {
    pub(crate) base: usize,
    pub(crate) bytes: Vec<u8>,
    pub(crate) regions: Vec<RegionEvidence>,
    pub(crate) unreadable_pages: usize,
    pub(crate) name: Option<String>,
    pub(crate) path: Option<PathBuf>,
    pub(crate) is_main: bool,
    pub(crate) hidden: bool,
}

pub(crate) struct Capture {
    pub(crate) mode: AcquisitionMode,
    pub(crate) setup_elapsed: Duration,
    pub(crate) fallback_reason: Option<String>,
    pub(crate) images: Vec<CapturedImage>,
    pub(crate) executable_non_image_allocations: usize,
}

pub(crate) struct StabilityInfo {
    pub(crate) elapsed: Duration,
    pub(crate) settled: bool,
}

#[derive(Clone, Copy, Hash)]
struct MemoryRegion {
    base: usize,
    allocation_base: usize,
    size: usize,
    state: u32,
    protect: u32,
    kind: u32,
}

#[derive(Default)]
struct ImageGroup {
    regions: Vec<MemoryRegion>,
    end: usize,
}

struct Snapshot {
    handle: HPSS,
    clone: HANDLE,
}

enum AddressSpace {
    Snapshot(Snapshot),
    Live(OwnedHandle),
}

struct AcquiredAddressSpace {
    space: AddressSpace,
    mode: AcquisitionMode,
    setup_elapsed: Duration,
    fallback_reason: Option<String>,
}

impl Snapshot {
    fn capture(target: &TargetProcess) -> AppResult<(Self, Duration)> {
        let process = OwnedHandle::open(
            target.pid,
            PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        )?;
        let flags = PSS_CAPTURE_VA_CLONE
            | PSS_CREATE_BREAKAWAY
            | PSS_CREATE_BREAKAWAY_OPTIONAL
            | PSS_CREATE_USE_VM_ALLOCATIONS;
        let started = Instant::now();
        let mut snapshot = HPSS::default();
        let status = unsafe { PssCaptureSnapshot(process.raw(), flags, None, &mut snapshot) };
        if status != ERROR_SUCCESS.0 {
            return Err(win32_status("PssCaptureSnapshot", status));
        }
        let elapsed = started.elapsed();

        let mut clone = PSS_VA_CLONE_INFORMATION::default();
        let buffer_length = u32::try_from(size_of::<PSS_VA_CLONE_INFORMATION>())
            .map_err(|_| AppError::new("PSS clone information size does not fit u32"))?;
        let query_status = unsafe {
            PssQuerySnapshot(
                snapshot,
                PSS_QUERY_VA_CLONE_INFORMATION,
                (&raw mut clone).cast(),
                buffer_length,
            )
        };
        if query_status != ERROR_SUCCESS.0 || clone.VaCloneHandle.is_invalid() {
            let _free_status = unsafe { PssFreeSnapshot(GetCurrentProcess(), snapshot) };
            if query_status != ERROR_SUCCESS.0 {
                return Err(win32_status("PssQuerySnapshot", query_status));
            }
            return Err(AppError::new("PSS returned an invalid VA clone handle"));
        }

        drop(process);
        Ok((
            Self {
                handle: snapshot,
                clone: clone.VaCloneHandle,
            },
            elapsed,
        ))
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        let status = unsafe { PssFreeSnapshot(GetCurrentProcess(), self.handle) };
        debug_assert_eq!(status, ERROR_SUCCESS.0);
    }
}

impl AddressSpace {
    fn acquire(target: &TargetProcess) -> AppResult<AcquiredAddressSpace> {
        match Snapshot::capture(target) {
            Ok((snapshot, setup_elapsed)) => Ok(AcquiredAddressSpace {
                space: Self::Snapshot(snapshot),
                mode: AcquisitionMode::PssClone,
                setup_elapsed,
                fallback_reason: None,
            }),
            Err(snapshot_error) => {
                let started = Instant::now();
                let process =
                    OwnedHandle::open(target.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)?;
                Ok(AcquiredAddressSpace {
                    space: Self::Live(process),
                    mode: AcquisitionMode::LiveRead,
                    setup_elapsed: started.elapsed(),
                    fallback_reason: Some(snapshot_error.to_string()),
                })
            }
        }
    }

    fn open_live(target: &TargetProcess) -> AppResult<Self> {
        OwnedHandle::open(target.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).map(Self::Live)
    }

    fn handle(&self) -> HANDLE {
        match self {
            Self::Snapshot(snapshot) => snapshot.clone,
            Self::Live(process) => process.raw(),
        }
    }

    fn regions(&self) -> AppResult<Vec<MemoryRegion>> {
        list_regions(self.handle())
    }

    fn read_exact(&self, address: usize, destination: &mut [u8]) -> bool {
        read_exact(self.handle(), address, destination)
    }
}

pub(crate) fn capture(target: &TargetProcess) -> AppResult<Capture> {
    let acquired = AddressSpace::acquire(target)?;
    let (images, non_image_count) = capture_from_space(&acquired.space, target)?;
    Ok(Capture {
        mode: acquired.mode,
        setup_elapsed: acquired.setup_elapsed,
        fallback_reason: acquired.fallback_reason,
        images,
        executable_non_image_allocations: non_image_count,
    })
}

pub(crate) fn wait_until_stable(target: &TargetProcess) -> AppResult<StabilityInfo> {
    let space = AddressSpace::open_live(target)?;
    let started = Instant::now();
    let mut previous = None;
    let mut matches = 0usize;
    for _index in 0..STABLE_POLL_COUNT {
        let regions = space.regions()?;
        let signature = memory_signature(&space, &regions);
        if previous == Some(signature) {
            matches = matches.saturating_add(1);
            if matches >= STABLE_MATCH_COUNT {
                return Ok(StabilityInfo {
                    elapsed: started.elapsed(),
                    settled: true,
                });
            }
        } else {
            matches = 0;
            previous = Some(signature);
        }
        std::thread::sleep(STABLE_POLL_DELAY);
    }
    Ok(StabilityInfo {
        elapsed: started.elapsed(),
        settled: false,
    })
}

fn memory_signature(space: &AddressSpace, regions: &[MemoryRegion]) -> u64 {
    let mut hash = DefaultHasher::new();
    for region in regions.iter().filter(|region| is_stability_region(region)) {
        region.hash(&mut hash);
    }
    for (address, length) in stability_pages(regions) {
        let mut page = [0u8; PAGE_SIZE];
        if space.read_exact(address, &mut page[..length]) {
            page[..length].hash(&mut hash);
        } else {
            u64::MAX.hash(&mut hash);
        }
    }
    hash.finish()
}

fn stability_pages(regions: &[MemoryRegion]) -> Vec<(usize, usize)> {
    let total_pages = regions
        .iter()
        .filter(|region| is_stability_region(region))
        .map(|region| region.size.div_ceil(PAGE_SIZE))
        .fold(0usize, usize::saturating_add);
    let sample_count = total_pages.min(MAX_STABILITY_READS);
    let mut pages = Vec::with_capacity(sample_count);
    let mut first_page = 0usize;
    let mut sample = 0usize;
    for region in regions.iter().filter(|region| is_stability_region(region)) {
        let region_pages = region.size.div_ceil(PAGE_SIZE);
        let past_region = first_page.saturating_add(region_pages);
        while sample < sample_count {
            let target = sample_page(sample, total_pages, sample_count);
            if target >= past_region {
                break;
            }
            let page = target.saturating_sub(first_page);
            let offset = page.saturating_mul(PAGE_SIZE);
            let address = region.base.saturating_add(offset);
            let length = region.size.saturating_sub(offset).min(PAGE_SIZE);
            pages.push((address, length));
            sample = sample.saturating_add(1);
        }
        first_page = past_region;
    }
    pages
}

fn sample_page(sample: usize, total_pages: usize, sample_count: usize) -> usize {
    if sample_count <= 1 {
        return 0;
    }
    let numerator = (sample as u128) * (total_pages.saturating_sub(1) as u128);
    let denominator = sample_count.saturating_sub(1) as u128;
    (numerator / denominator) as usize
}

fn is_stability_region(region: &MemoryRegion) -> bool {
    region.state == MEM_COMMIT.0
        && is_readable(region.protect)
        && ((region.kind == MEM_IMAGE.0 && is_writable(region.protect))
            || is_executable(region.protect))
}

fn capture_from_space(
    space: &AddressSpace,
    target: &TargetProcess,
) -> AppResult<(Vec<CapturedImage>, usize)> {
    let regions = space.regions()?;
    let non_image_allocations = executable_non_image_allocations(&regions);
    let non_image_count = non_image_allocations.len();
    let groups = group_images(&regions, target)?;
    let hidden = find_hidden_images(space, &regions, &non_image_allocations)?;
    let mut images = Vec::new();
    images
        .try_reserve_exact(groups.len().saturating_add(hidden.len()))
        .map_err(|_| AppError::new("not enough memory for the image list"))?;

    let mut total_size = 0usize;
    for (base, group) in groups {
        let size = group
            .end
            .checked_sub(base)
            .ok_or_else(|| AppError::new("image allocation has an invalid address range"))?;
        if size == 0 || size > MAX_IMAGE_SIZE {
            return Err(AppError::new(format!(
                "image at 0x{base:016X} has unsupported size {size} bytes"
            )));
        }
        add_image_size(&mut total_size, size)?;
        images.push(read_image(
            space,
            target,
            base,
            size,
            &group.regions,
            false,
        )?);
    }
    for (base, size) in hidden {
        add_image_size(&mut total_size, size)?;
        let image_regions = regions_in_range(&regions, base, size)?;
        images.push(read_image(space, target, base, size, &image_regions, true)?);
    }
    if !images.iter().any(|image| image.is_main) {
        return Err(AppError::new(
            "the main image allocation was not present in the captured address space",
        ));
    }
    Ok((images, non_image_count))
}

fn add_image_size(total: &mut usize, size: usize) -> AppResult<()> {
    *total = total
        .checked_add(size)
        .ok_or_else(|| AppError::new("combined image size overflowed"))?;
    if *total > MAX_TOTAL_IMAGE_BYTES {
        return Err(AppError::new(
            "combined in-memory image data exceeds the 4 GiB safety limit",
        ));
    }
    Ok(())
}

fn list_regions(handle: HANDLE) -> AppResult<Vec<MemoryRegion>> {
    let mut regions = Vec::with_capacity(4_096);
    let mut address = 0usize;
    for _index in 0..MAX_MEMORY_REGIONS {
        let mut information = MEMORY_BASIC_INFORMATION::default();
        let returned = unsafe {
            VirtualQueryEx(
                handle,
                Some(address as *const c_void),
                &mut information,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if returned == 0 {
            return Ok(regions);
        }
        let base = information.BaseAddress as usize;
        let next = base
            .checked_add(information.RegionSize)
            .ok_or_else(|| AppError::new("virtual memory region address overflowed"))?;
        if information.RegionSize == 0 || next <= address {
            return Err(AppError::new(
                "VirtualQueryEx returned the same address twice",
            ));
        }
        regions.push(MemoryRegion {
            base,
            allocation_base: information.AllocationBase as usize,
            size: information.RegionSize,
            state: information.State.0,
            protect: information.Protect.0,
            kind: information.Type.0,
        });
        address = next;
    }
    Err(AppError::new("too many memory regions were returned"))
}

fn group_images(
    regions: &[MemoryRegion],
    target: &TargetProcess,
) -> AppResult<BTreeMap<usize, ImageGroup>> {
    let mut image_bases = BTreeSet::new();
    for region in regions {
        if region.kind == MEM_IMAGE.0 && region.allocation_base != 0 {
            image_bases.insert(region.allocation_base);
        }
    }
    for module in &target.modules {
        if module.base != 0 {
            image_bases.insert(module.base);
        }
    }
    if image_bases.len() > MAX_IMAGES {
        return Err(AppError::new(
            "in-memory image count exceeds the 4096-image safety limit",
        ));
    }

    let mut groups = BTreeMap::<usize, ImageGroup>::new();
    for region in regions {
        if !image_bases.contains(&region.allocation_base) {
            continue;
        }
        let end = region
            .base
            .checked_add(region.size)
            .ok_or_else(|| AppError::new("image memory region address overflowed"))?;
        let group = groups.entry(region.allocation_base).or_default();
        group.end = group.end.max(end);
        group.regions.push(*region);
    }
    Ok(groups)
}

fn read_image(
    space: &AddressSpace,
    target: &TargetProcess,
    base: usize,
    size: usize,
    regions: &[MemoryRegion],
    hidden: bool,
) -> AppResult<CapturedImage> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| AppError::new(format!("not enough memory for image at 0x{base:016X}")))?;
    bytes.resize(size, 0);
    let mut evidence = Vec::with_capacity(regions.len());
    let mut unreadable_pages = 0usize;
    let image_end = base
        .checked_add(size)
        .ok_or_else(|| AppError::new("image address overflowed"))?;

    for region in regions {
        if region.state != MEM_COMMIT.0 {
            continue;
        }
        let region_end = region
            .base
            .checked_add(region.size)
            .ok_or_else(|| AppError::new("image region address overflowed"))?;
        let read_base = region.base.max(base);
        let read_end = region_end.min(image_end);
        if read_base >= read_end {
            continue;
        }
        let offset = read_base.saturating_sub(base);
        let length = read_end.saturating_sub(read_base);
        evidence.push(RegionEvidence {
            offset,
            size: length,
            readable: is_readable(region.protect),
            writable: is_writable(region.protect),
            executable: is_executable(region.protect),
        });
        let destination = bytes
            .get_mut(offset..offset.saturating_add(length))
            .ok_or_else(|| AppError::new("image region lies outside its output buffer"))?;
        if !is_readable(region.protect) {
            unreadable_pages = unreadable_pages.saturating_add(length.div_ceil(PAGE_SIZE));
            continue;
        }
        unreadable_pages =
            unreadable_pages.saturating_add(read_region(space, read_base, destination));
    }

    let module = target.modules.iter().find(|module| module.base == base);
    Ok(CapturedImage {
        base,
        bytes,
        regions: evidence,
        unreadable_pages,
        name: module.map(|value| value.name.clone()),
        path: module.map(|value| value.path.clone()),
        is_main: base == target.main_module.base,
        hidden,
    })
}

fn find_hidden_images(
    space: &AddressSpace,
    regions: &[MemoryRegion],
    executable_allocations: &BTreeSet<usize>,
) -> AppResult<Vec<(usize, usize)>> {
    let mut allocation_ends = BTreeMap::<usize, usize>::new();
    for region in regions {
        if !executable_allocations.contains(&region.allocation_base) {
            continue;
        }
        let end = region
            .base
            .checked_add(region.size)
            .ok_or_else(|| AppError::new("non-image allocation address overflowed"))?;
        allocation_ends
            .entry(region.allocation_base)
            .and_modify(|current| *current = (*current).max(end))
            .or_insert(end);
    }

    let mut found = Vec::new();
    let mut scanned_pages = 0usize;
    for region in regions {
        if !executable_allocations.contains(&region.allocation_base)
            || region.state != MEM_COMMIT.0
            || !is_readable(region.protect)
        {
            continue;
        }
        for offset in (0..region.size).step_by(PAGE_SIZE) {
            scanned_pages = scanned_pages.saturating_add(1);
            if scanned_pages > MAX_NON_IMAGE_SCAN_PAGES {
                return Err(AppError::new(
                    "non-image PE scan exceeds the 262144-page safety limit",
                ));
            }
            let Some(base) = region.base.checked_add(offset) else {
                return Err(AppError::new("non-image PE scan address overflowed"));
            };
            let mut magic = [0u8; 2];
            if !space.read_exact(base, &mut magic) || magic != *b"MZ" {
                continue;
            }
            let Some(allocation_end) = allocation_ends.get(&region.allocation_base).copied() else {
                continue;
            };
            let available = allocation_end.saturating_sub(base);
            let header_length = available.min(MAX_HEADER_READ);
            let mut header = vec![0u8; header_length];
            if !space.read_exact(base, &mut header) {
                continue;
            }
            let Ok(image_size) = crate::pe::memory_image_size(&header) else {
                continue;
            };
            if image_size > available {
                continue;
            }
            if available > MAX_IMAGE_SIZE {
                return Err(AppError::new(format!(
                    "hidden image allocation at 0x{base:016X} exceeds the 1 GiB image safety limit"
                )));
            }
            found.push((base, available));
            if found.len() > MAX_IMAGES {
                return Err(AppError::new(
                    "hidden image count exceeds the 4096-image safety limit",
                ));
            }
        }
    }
    Ok(found)
}

fn regions_in_range(
    regions: &[MemoryRegion],
    base: usize,
    size: usize,
) -> AppResult<Vec<MemoryRegion>> {
    let end = base
        .checked_add(size)
        .ok_or_else(|| AppError::new("hidden image range overflowed"))?;
    Ok(regions
        .iter()
        .filter(|region| {
            let region_end = region.base.saturating_add(region.size);
            region.base < end && region_end > base
        })
        .copied()
        .collect())
}

fn read_region(space: &AddressSpace, base: usize, destination: &mut [u8]) -> usize {
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

fn read_exact(handle: HANDLE, address: usize, destination: &mut [u8]) -> bool {
    if destination.is_empty() {
        return true;
    }
    let mut read = 0usize;
    let result = unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            destination.as_mut_ptr().cast(),
            destination.len(),
            Some(&mut read),
        )
    };
    result.is_ok() && read == destination.len()
}

fn executable_non_image_allocations(regions: &[MemoryRegion]) -> BTreeSet<usize> {
    regions
        .iter()
        .filter(|region| {
            region.state == MEM_COMMIT.0
                && region.kind != MEM_IMAGE.0
                && is_executable(region.protect)
        })
        .map(|region| region.allocation_base)
        .filter(|base| *base != 0)
        .collect::<BTreeSet<_>>()
}

fn is_readable(protect: u32) -> bool {
    if protect & (PAGE_GUARD.0 | PAGE_NOACCESS.0) != 0 {
        return false;
    }
    let base = protect & 0xff;
    [
        PAGE_READONLY.0,
        PAGE_READWRITE.0,
        PAGE_WRITECOPY.0,
        PAGE_EXECUTE_READ.0,
        PAGE_EXECUTE_READWRITE.0,
        PAGE_EXECUTE_WRITECOPY.0,
    ]
    .contains(&base)
}

fn is_executable(protect: u32) -> bool {
    if protect & (PAGE_GUARD.0 | PAGE_NOACCESS.0) != 0 {
        return false;
    }
    let base = protect & 0xff;
    [
        PAGE_EXECUTE.0,
        PAGE_EXECUTE_READ.0,
        PAGE_EXECUTE_READWRITE.0,
        PAGE_EXECUTE_WRITECOPY.0,
    ]
    .contains(&base)
}

fn is_writable(protect: u32) -> bool {
    if protect & (PAGE_GUARD.0 | PAGE_NOACCESS.0) != 0 {
        return false;
    }
    let base = protect & 0xff;
    [
        PAGE_READWRITE.0,
        PAGE_WRITECOPY.0,
        PAGE_EXECUTE_READWRITE.0,
        PAGE_EXECUTE_WRITECOPY.0,
    ]
    .contains(&base)
}

fn win32_status(action: &str, status: u32) -> AppError {
    let detail = std::io::Error::from_raw_os_error(status as i32);
    AppError::new(format!("{action} failed: {detail} (error {status})"))
}

#[cfg(test)]
mod tests {
    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, PAGE_EXECUTE_READ, PAGE_READWRITE,
    };

    use super::{
        MAX_STABILITY_READS, MemoryRegion, PAGE_SIZE, executable_non_image_allocations,
        regions_in_range, stability_pages,
    };

    fn region(base: usize, size: usize) -> MemoryRegion {
        MemoryRegion {
            base,
            allocation_base: base,
            size,
            state: 0,
            protect: 0,
            kind: 0,
        }
    }

    #[test]
    fn selects_only_regions_overlapping_an_image() -> Result<(), Box<dyn std::error::Error>> {
        let regions = [
            region(0x1000, 0x1000),
            region(0x2000, 0x1000),
            region(0x3000, 0x1000),
        ];

        let selected = regions_in_range(&regions, 0x1800, 0x1000)?;

        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].base, 0x1000);
        assert_eq!(selected[1].base, 0x2000);
        Ok(())
    }

    #[test]
    fn rejects_an_overflowing_image_range() {
        let result = regions_in_range(&[], usize::MAX, 2);

        assert!(result.is_err());
    }

    #[test]
    fn samples_content_across_large_relevant_regions() {
        let regions = [
            MemoryRegion {
                base: 0x1000,
                allocation_base: 0x1000,
                size: PAGE_SIZE * 512,
                state: MEM_COMMIT.0,
                protect: PAGE_EXECUTE_READ.0,
                kind: MEM_IMAGE.0,
            },
            MemoryRegion {
                base: 0x400000,
                allocation_base: 0x400000,
                size: PAGE_SIZE,
                state: MEM_COMMIT.0,
                protect: PAGE_READWRITE.0,
                kind: MEM_PRIVATE.0,
            },
        ];

        let pages = stability_pages(&regions);

        assert_eq!(pages.len(), MAX_STABILITY_READS);
        assert_eq!(pages.first(), Some(&(0x1000, PAGE_SIZE)));
        assert_eq!(pages.last(), Some(&(0x1000 + PAGE_SIZE * 511, PAGE_SIZE)));
    }

    #[test]
    fn includes_executable_mapped_and_private_allocations() {
        let regions = [
            MemoryRegion {
                base: 0x1000,
                allocation_base: 0x1000,
                size: PAGE_SIZE,
                state: MEM_COMMIT.0,
                protect: PAGE_EXECUTE_READ.0,
                kind: MEM_PRIVATE.0,
            },
            MemoryRegion {
                base: 0x2000,
                allocation_base: 0x2000,
                size: PAGE_SIZE,
                state: MEM_COMMIT.0,
                protect: PAGE_EXECUTE_READ.0,
                kind: MEM_MAPPED.0,
            },
            MemoryRegion {
                base: 0x3000,
                allocation_base: 0x3000,
                size: PAGE_SIZE,
                state: MEM_COMMIT.0,
                protect: PAGE_EXECUTE_READ.0,
                kind: MEM_IMAGE.0,
            },
        ];

        let allocations = executable_non_image_allocations(&regions);

        assert_eq!(allocations.len(), 2);
        assert!(allocations.contains(&0x1000));
        assert!(allocations.contains(&0x2000));
    }
}
