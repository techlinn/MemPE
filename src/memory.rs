use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_void;
use std::fmt::{Display, Formatter};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::mem::size_of;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::Storage::FileSystem::{GetLogicalDrives, QueryDosDeviceW};
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
use windows::Win32::System::ProcessStatus::{
    K32GetMappedFileNameW, K32QueryWorkingSetEx, PSAPI_WORKING_SET_EX_INFORMATION,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, PROCESS_CREATE_PROCESS, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};
use windows::core::PCWSTR;

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
const MAX_MAPPED_PATH_CHARS: usize = 1_024;
const WORKING_SET_CHUNK: usize = 512;
const WORKING_SET_VALID: usize = 1;
const WORKING_SET_SHARED: usize = 1 << 15;
const MAX_NON_IMAGE_RW_BYTES: usize = 256 * 1024 * 1024;
const MAX_RAW_REGION_BYTES: usize = 512 * 1024 * 1024;
const PAGE_RESIDENT: u8 = 0b01;
const PAGE_PRIVATE: u8 = 0b10;

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
    pub(crate) linked: bool,
    pub(crate) image_backed: bool,
    pub(crate) path_mismatch: bool,
    pub(crate) resident_pages: usize,
    pub(crate) private_pages: usize,
    pub(crate) page_flags: Vec<u8>,
}

#[derive(Default)]
struct PageCoverage {
    resident: usize,
    private: usize,
    flags: Vec<u8>,
}

pub(crate) struct Capture {
    pub(crate) mode: AcquisitionMode,
    pub(crate) setup_elapsed: Duration,
    pub(crate) fallback_reason: Option<String>,
    pub(crate) images: Vec<CapturedImage>,
    pub(crate) executable_non_image_allocations: usize,
    pub(crate) carve_regions: Vec<RawRegion>,
    pub(crate) raw_regions: Vec<RawRegion>,
    pub(crate) unscanned_non_image_bytes: usize,
    pub(crate) main_image_missing: bool,
    pub(crate) images_skipped: usize,
}

pub(crate) struct RawRegion {
    pub(crate) base: usize,
    pub(crate) allocation_base: usize,
    pub(crate) bytes: Vec<u8>,
    pub(crate) unreadable_pages: usize,
    pub(crate) committed: usize,
    pub(crate) protections: u32,
    pub(crate) executable: bool,
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
                let space = Self::open_live(target)?;
                Ok(AcquiredAddressSpace {
                    space,
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

pub(crate) fn capture(target: &TargetProcess, raw_regions: bool) -> AppResult<Capture> {
    let mut coverage = measure_image_pages(target);
    let AcquiredAddressSpace {
        space,
        mode,
        setup_elapsed,
        fallback_reason,
    } = AddressSpace::acquire(target)?;
    let captured = capture_from_space(&space, target, raw_regions)?;
    let mut images = captured.images;
    drop(space);
    if let Ok(process) = OwnedHandle::open(target.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    {
        annotate_images(process.raw(), &mut images, &mut coverage);
    }
    Ok(Capture {
        mode,
        setup_elapsed,
        fallback_reason,
        images,
        executable_non_image_allocations: captured.non_image_count,
        carve_regions: captured.carve_regions,
        raw_regions: captured.raw_regions,
        unscanned_non_image_bytes: captured.unscanned_non_image_bytes,
        main_image_missing: captured.main_image_missing,
        images_skipped: captured.images_skipped,
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

struct CapturedSpace {
    images: Vec<CapturedImage>,
    non_image_count: usize,
    carve_regions: Vec<RawRegion>,
    raw_regions: Vec<RawRegion>,
    unscanned_non_image_bytes: usize,
    main_image_missing: bool,
    images_skipped: usize,
}

fn read_all_images(
    space: &AddressSpace,
    target: &TargetProcess,
    regions: &[MemoryRegion],
    groups: BTreeMap<usize, ImageGroup>,
    hidden: &[(usize, usize)],
    main_base: Option<usize>,
) -> AppResult<(Vec<CapturedImage>, usize)> {
    let mut images = Vec::new();
    images
        .try_reserve_exact(groups.len().saturating_add(hidden.len()))
        .map_err(|_| AppError::new("not enough memory for the image list"))?;
    let mut total_size = 0usize;
    let mut skipped = 0usize;
    for (base, group) in groups {
        let size = group.end.saturating_sub(base);
        if size == 0 {
            continue;
        }
        if size > MAX_IMAGE_SIZE {
            skipped = skipped.saturating_add(1);
            continue;
        }
        if !claim_image_budget(&mut total_size, size, main_base == Some(base)) {
            skipped = skipped.saturating_add(1);
            continue;
        }
        let read = read_image(space, target, main_base, base, size, &group.regions, false)?;
        images.push(read);
    }
    for (base, size) in hidden.iter().copied() {
        if !claim_image_budget(&mut total_size, size, false) {
            skipped = skipped.saturating_add(1);
            continue;
        }
        let image_regions = regions_in_range(regions, base, size)?;
        let read = read_image(space, target, main_base, base, size, &image_regions, true)?;
        images.push(read);
    }
    Ok((images, skipped))
}

fn capture_from_space(
    space: &AddressSpace,
    target: &TargetProcess,
    want_raw_regions: bool,
) -> AppResult<CapturedSpace> {
    let regions = space.regions()?;
    let non_image_allocations = executable_non_image_allocations(&regions);
    let non_image_count = non_image_allocations.len();
    let bases = image_bases(&regions, target);
    let main_base = resolve_main_base(space, target, &bases);
    let (groups, mut images_skipped) = group_images(&regions, &bases, main_base)?;
    let HiddenScan {
        found: hidden,
        unscanned: unscanned_hidden,
    } = find_hidden_images(space, &regions, &non_image_allocations)?;
    let (images, over_budget) =
        read_all_images(space, target, &regions, groups, &hidden, main_base)?;
    images_skipped = images_skipped.saturating_add(over_budget);
    if images.is_empty() {
        return Err(AppError::new(
            "no image allocations were present in the captured address space",
        ));
    }
    let main_image_missing = main_image_is_missing(&images);
    let unclaimed = unclaimed_executable_allocations(&regions, &non_image_allocations, &hidden);
    let mut carve_allocations = unclaimed.iter().copied().collect::<Vec<_>>();
    carve_allocations.extend(readable_non_image_allocations(
        space,
        &regions,
        &non_image_allocations,
    ));
    let carve = read_allocations(space, &regions, &carve_allocations, MAX_NON_IMAGE_RW_BYTES);
    let raw = if want_raw_regions {
        let unclaimed = unclaimed.into_iter().collect::<Vec<_>>();
        read_allocations(space, &regions, &unclaimed, MAX_RAW_REGION_BYTES)
    } else {
        ScannedAllocations {
            regions: Vec::new(),
            skipped: 0,
        }
    };
    Ok(CapturedSpace {
        images,
        non_image_count,
        carve_regions: carve.regions,
        raw_regions: raw.regions,
        unscanned_non_image_bytes: carve
            .skipped
            .saturating_add(raw.skipped)
            .saturating_add(unscanned_hidden),
        main_image_missing,
        images_skipped,
    })
}

fn main_image_is_missing(images: &[CapturedImage]) -> bool {
    !images.iter().any(|image| image.is_main)
}

fn readable_non_image_allocations(
    space: &AddressSpace,
    regions: &[MemoryRegion],
    executable: &BTreeSet<usize>,
) -> BTreeSet<usize> {
    let candidates = regions
        .iter()
        .filter(|region| {
            region.state == MEM_COMMIT.0
                && region.kind != MEM_IMAGE.0
                && region.allocation_base != 0
                && is_readable(region.protect)
                && !is_executable(region.protect)
        })
        .map(|region| region.allocation_base)
        .filter(|base| !executable.contains(base))
        .collect::<BTreeSet<usize>>();
    candidates
        .into_iter()
        .filter(|base| mapped_file_name(space.handle(), *base).is_none())
        .collect()
}

fn unclaimed_executable_allocations(
    regions: &[MemoryRegion],
    executable: &BTreeSet<usize>,
    hidden: &[(usize, usize)],
) -> BTreeSet<usize> {
    let mut claimed = BTreeSet::new();
    for (base, _size) in hidden {
        if let Some(region) = regions.iter().find(|region| region.base == *base) {
            claimed.insert(region.allocation_base);
        }
    }
    executable
        .iter()
        .copied()
        .filter(|base| !claimed.contains(base))
        .collect()
}

struct ScannedAllocations {
    regions: Vec<RawRegion>,
    skipped: usize,
}

struct CommittedRun {
    allocation_base: usize,
    base: usize,
    end: usize,
    protections: u32,
    executable: bool,
}

fn committed_runs(
    regions: &[MemoryRegion],
    allocations: &[usize],
) -> BTreeMap<usize, Vec<CommittedRun>> {
    let wanted = allocations.iter().copied().collect::<BTreeSet<_>>();
    let mut runs = BTreeMap::<usize, Vec<CommittedRun>>::new();
    for region in regions {
        if region.state != MEM_COMMIT.0
            || !is_readable(region.protect)
            || !wanted.contains(&region.allocation_base)
        {
            continue;
        }
        let end = region.base.saturating_add(region.size);
        let list = runs.entry(region.allocation_base).or_default();
        match list.last_mut() {
            Some(run) if run.end == region.base => {
                run.end = end;
                run.protections |= region.protect;
                run.executable |= is_executable(region.protect);
            }
            _ => list.push(CommittedRun {
                allocation_base: region.allocation_base,
                base: region.base,
                end,
                protections: region.protect,
                executable: is_executable(region.protect),
            }),
        }
    }
    runs
}

fn read_allocations(
    space: &AddressSpace,
    regions: &[MemoryRegion],
    allocations: &[usize],
    budget: usize,
) -> ScannedAllocations {
    let mut runs = committed_runs(regions, allocations);
    let mut remaining = budget;
    let mut skipped = 0usize;
    let mut collected = Vec::new();
    for allocation in allocations {
        for run in runs.remove(allocation).unwrap_or_default() {
            let committed = run.end.saturating_sub(run.base);
            let size = committed.min(remaining);
            let mut bytes = Vec::new();
            if size == 0 || collected.len() >= MAX_IMAGES || bytes.try_reserve_exact(size).is_err()
            {
                skipped = skipped.saturating_add(committed);
                continue;
            }
            bytes.resize(size, 0);
            let unreadable_pages = read_region(space, run.base, &mut bytes);
            remaining = remaining.saturating_sub(size);
            skipped = skipped.saturating_add(committed.saturating_sub(size));
            collected.push(RawRegion {
                base: run.base,
                allocation_base: run.allocation_base,
                bytes,
                unreadable_pages,
                committed,
                protections: run.protections,
                executable: run.executable,
            });
        }
    }
    ScannedAllocations {
        regions: collected,
        skipped,
    }
}

fn claim_image_budget(total: &mut usize, size: usize, mandatory: bool) -> bool {
    let next = total.saturating_add(size);
    if !mandatory && next > MAX_TOTAL_IMAGE_BYTES {
        return false;
    }
    *total = next;
    true
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

fn image_bases(regions: &[MemoryRegion], target: &TargetProcess) -> BTreeSet<usize> {
    let mut bases = BTreeSet::new();
    for region in regions {
        if region.kind == MEM_IMAGE.0 && region.allocation_base != 0 {
            bases.insert(region.allocation_base);
        }
    }
    for module in &target.modules {
        if module.base != 0 {
            bases.insert(module.base);
        }
    }
    bases
}

fn group_images(
    regions: &[MemoryRegion],
    bases: &BTreeSet<usize>,
    main_base: Option<usize>,
) -> AppResult<(BTreeMap<usize, ImageGroup>, usize)> {
    let mut kept = bases
        .iter()
        .copied()
        .take(MAX_IMAGES)
        .collect::<BTreeSet<_>>();
    if let Some(base) = main_base.filter(|base| bases.contains(base)) {
        kept.insert(base);
    }
    let skipped = bases.len().saturating_sub(kept.len());

    let mut groups = BTreeMap::<usize, ImageGroup>::new();
    for region in regions {
        if !kept.contains(&region.allocation_base) {
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
    Ok((groups, skipped))
}

struct RegionScan {
    evidence: Vec<RegionEvidence>,
    unreadable_pages: usize,
    image_backed: bool,
}

fn resolve_main_base(
    space: &AddressSpace,
    target: &TargetProcess,
    bases: &BTreeSet<usize>,
) -> Option<usize> {
    if let Some(module) = &target.main_module {
        return Some(module.base);
    }
    let drives = drive_map();
    let wanted = target.path.to_string_lossy().into_owned();
    let mut by_path = None;
    let mut by_name = Vec::new();
    for base in bases {
        let Some(device) = mapped_file_name(space.handle(), *base) else {
            continue;
        };
        if to_dos_path(&device, &drives).is_some_and(|path| path.eq_ignore_ascii_case(&wanted)) {
            if by_path.is_some() {
                return None;
            }
            by_path = Some(*base);
        } else if basename(&device).eq_ignore_ascii_case(&target.name) {
            by_name.push(*base);
        }
    }
    by_path.or_else(|| by_name.first().copied().filter(|_| by_name.len() == 1))
}

fn read_image(
    space: &AddressSpace,
    target: &TargetProcess,
    main_base: Option<usize>,
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
    let image_end = base
        .checked_add(size)
        .ok_or_else(|| AppError::new("image address overflowed"))?;
    let scan = read_image_regions(space, &mut bytes, base, image_end, regions)?;
    let module = target.modules.iter().find(|module| module.base == base);
    Ok(CapturedImage {
        base,
        bytes,
        regions: scan.evidence,
        unreadable_pages: scan.unreadable_pages,
        name: module.map(|value| value.name.clone()),
        path: module.map(|value| value.path.clone()),
        is_main: main_base == Some(base),
        hidden,
        linked: module.is_some(),
        image_backed: scan.image_backed,
        path_mismatch: false,
        resident_pages: 0,
        private_pages: 0,
        page_flags: Vec::new(),
    })
}

fn read_image_regions(
    space: &AddressSpace,
    bytes: &mut [u8],
    base: usize,
    image_end: usize,
    regions: &[MemoryRegion],
) -> AppResult<RegionScan> {
    let mut evidence = Vec::with_capacity(regions.len());
    let mut unreadable_pages = 0usize;
    let mut image_backed = true;
    for region in regions {
        if region.state != MEM_COMMIT.0 {
            continue;
        }
        if region.kind != MEM_IMAGE.0 {
            image_backed = false;
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
    Ok(RegionScan {
        evidence,
        unreadable_pages,
        image_backed,
    })
}

fn measure_image_pages(target: &TargetProcess) -> BTreeMap<usize, PageCoverage> {
    let Ok(process) = OwnedHandle::open(target.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    else {
        return BTreeMap::new();
    };
    let Ok(regions) = list_regions(process.raw()) else {
        return BTreeMap::new();
    };
    let mut extents = BTreeMap::<usize, usize>::new();
    for region in regions.iter().filter(|region| {
        region.kind == MEM_IMAGE.0 && region.state == MEM_COMMIT.0 && region.allocation_base != 0
    }) {
        let end = region.base.saturating_add(region.size);
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

fn annotate_images(
    process: HANDLE,
    images: &mut [CapturedImage],
    coverage: &mut BTreeMap<usize, PageCoverage>,
) {
    let drives = drive_map();
    for image in images {
        let mapped = mapped_file_name(process, image.base);
        let actual = mapped
            .as_deref()
            .and_then(|device| to_dos_path(device, &drives));
        image.path_mismatch = match (&image.path, &actual) {
            (Some(reported), Some(actual)) => {
                !reported.as_os_str().eq_ignore_ascii_case(actual.as_str())
            }
            _ => basename_mismatch(image.name.as_deref(), mapped.as_deref()),
        };
        if image.name.is_none() || image.path_mismatch {
            image.name = mapped.as_deref().map(|path| basename(path).to_owned());
        }
        if let Some(pages) = coverage.remove(&image.base) {
            image.resident_pages = pages.resident;
            image.private_pages = pages.private;
            image.page_flags = pages.flags;
        }
    }
}

fn basename_mismatch(reported: Option<&str>, mapped: Option<&str>) -> bool {
    match (reported, mapped) {
        (Some(reported), Some(mapped)) => !reported.eq_ignore_ascii_case(basename(mapped)),
        _ => false,
    }
}

fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn mapped_file_name(process: HANDLE, base: usize) -> Option<String> {
    let mut buffer = [0u16; MAX_MAPPED_PATH_CHARS];
    let length = unsafe { K32GetMappedFileNameW(process, base as *const c_void, &mut buffer) };
    let used = usize::try_from(length).ok()?;
    let path = String::from_utf16_lossy(buffer.get(..used)?);
    (!path.is_empty()).then_some(path)
}

fn drive_map() -> Vec<(String, String)> {
    let mask = unsafe { GetLogicalDrives() };
    let mut map = Vec::new();
    for index in 0..26u32 {
        if mask & (1u32 << index) == 0 {
            continue;
        }
        let Some(letter) = char::from_u32(u32::from(b'A').saturating_add(index)) else {
            continue;
        };
        let dos = format!("{letter}:");
        let wide = [u16::from(letter as u8), u16::from(b':'), 0u16];
        let mut target = [0u16; MAX_MAPPED_PATH_CHARS];
        let length = unsafe { QueryDosDeviceW(PCWSTR(wide.as_ptr()), Some(target.as_mut_slice())) };
        if length == 0 {
            continue;
        }
        let end = target.iter().position(|unit| *unit == 0).unwrap_or(0);
        let device = String::from_utf16_lossy(target.get(..end).unwrap_or_default());
        if !device.is_empty() {
            map.push((device, dos));
        }
    }
    map
}

fn to_dos_path(device: &str, map: &[(String, String)]) -> Option<String> {
    map.iter().find_map(|(prefix, letter)| {
        let rest = device.strip_prefix(prefix.as_str())?;
        rest.starts_with('\\').then(|| format!("{letter}{rest}"))
    })
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
            // SAFETY: Flags is the integer view of the union and every bit pattern is valid.
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
    coverage
}

struct HiddenScan {
    found: Vec<(usize, usize)>,
    unscanned: usize,
}

fn find_hidden_images(
    space: &AddressSpace,
    regions: &[MemoryRegion],
    executable_allocations: &BTreeSet<usize>,
) -> AppResult<HiddenScan> {
    let allocation_ends = allocation_extents(regions, executable_allocations)?;
    let mut found = Vec::new();
    let mut captured_allocations = BTreeSet::new();
    let mut scanned_pages = 0usize;
    let mut unscanned = 0usize;
    for region in regions {
        if captured_allocations.contains(&region.allocation_base)
            || !executable_allocations.contains(&region.allocation_base)
            || region.state != MEM_COMMIT.0
            || !is_readable(region.protect)
        {
            continue;
        }
        let Some(allocation_end) = allocation_ends.get(&region.allocation_base).copied() else {
            continue;
        };
        for offset in (0..region.size).step_by(PAGE_SIZE) {
            if scanned_pages >= MAX_NON_IMAGE_SCAN_PAGES || found.len() >= MAX_IMAGES {
                unscanned = unscanned.saturating_add(region.size.saturating_sub(offset));
                break;
            }
            scanned_pages = scanned_pages.saturating_add(1);
            let Some(base) = region.base.checked_add(offset) else {
                return Err(AppError::new("non-image PE scan address overflowed"));
            };
            let Some(available) = hidden_image_at(space, base, allocation_end) else {
                continue;
            };
            found.push((base, available));
            captured_allocations.insert(region.allocation_base);
            break;
        }
    }
    Ok(HiddenScan { found, unscanned })
}

fn allocation_extents(
    regions: &[MemoryRegion],
    executable_allocations: &BTreeSet<usize>,
) -> AppResult<BTreeMap<usize, usize>> {
    let mut ends = BTreeMap::<usize, usize>::new();
    for region in regions {
        if !executable_allocations.contains(&region.allocation_base) {
            continue;
        }
        let end = region
            .base
            .checked_add(region.size)
            .ok_or_else(|| AppError::new("non-image allocation address overflowed"))?;
        ends.entry(region.allocation_base)
            .and_modify(|current| *current = (*current).max(end))
            .or_insert(end);
    }
    Ok(ends)
}

fn hidden_image_at(space: &AddressSpace, base: usize, allocation_end: usize) -> Option<usize> {
    let mut magic = [0u8; 2];
    if !space.read_exact(base, &mut magic) || magic != *b"MZ" {
        return None;
    }
    let available = allocation_end.saturating_sub(base);
    if available > MAX_IMAGE_SIZE {
        return None;
    }
    let mut header = vec![0u8; available.min(MAX_HEADER_READ)];
    if !space.read_exact(base, &mut header) {
        return None;
    }
    let image_size = crate::pe::memory_image_size(&header).ok()?;
    (image_size <= available).then_some(available)
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
    use std::collections::BTreeSet;

    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, PAGE_EXECUTE_READ, PAGE_GUARD,
        PAGE_READONLY, PAGE_READWRITE,
    };

    use super::{
        CapturedImage, MAX_IMAGES, MAX_STABILITY_READS, MAX_TOTAL_IMAGE_BYTES, MemoryRegion,
        PAGE_SIZE, allocation_extents, basename_mismatch, claim_image_budget,
        executable_non_image_allocations, group_images, is_executable, main_image_is_missing,
        regions_in_range, stability_pages, to_dos_path,
    };

    fn captured_image(is_main: bool) -> CapturedImage {
        CapturedImage {
            base: 0,
            bytes: Vec::new(),
            regions: Vec::new(),
            unreadable_pages: 0,
            name: None,
            path: None,
            is_main,
            hidden: false,
            linked: true,
            image_backed: true,
            path_mismatch: false,
            resident_pages: 0,
            private_pages: 0,
            page_flags: Vec::new(),
        }
    }

    #[test]
    fn main_image_missing_is_false_when_the_main_image_was_captured() {
        let images = vec![captured_image(false), captured_image(true)];

        assert!(!main_image_is_missing(&images));
    }

    #[test]
    fn main_image_missing_is_true_when_only_other_images_were_captured() {
        let images = vec![captured_image(false), captured_image(false)];

        assert!(main_image_is_missing(&images));
    }

    #[test]
    fn main_image_missing_is_true_for_an_empty_capture() {
        assert!(main_image_is_missing(&[]));
    }

    #[test]
    fn executability_is_a_property_of_one_protection_value_not_of_a_mask() {
        let mixed = PAGE_READONLY.0 | PAGE_EXECUTE_READ.0;

        assert!(is_executable(PAGE_EXECUTE_READ.0));
        assert!(!is_executable(mixed));
        assert!(!is_executable(PAGE_EXECUTE_READ.0 | PAGE_GUARD.0));
    }

    #[test]
    fn a_device_name_is_not_confused_with_a_longer_one_sharing_its_prefix() {
        let map = [
            ("\\Device\\HarddiskVolume1".to_string(), "C:".to_string()),
            ("\\Device\\HarddiskVolume11".to_string(), "D:".to_string()),
        ];

        assert_eq!(
            to_dos_path("\\Device\\HarddiskVolume11\\app\\a.dll", &map).as_deref(),
            Some("D:\\app\\a.dll")
        );
        assert_eq!(
            to_dos_path("\\Device\\HarddiskVolume1\\app\\a.dll", &map).as_deref(),
            Some("C:\\app\\a.dll")
        );
        assert_eq!(to_dos_path("\\Device\\Mup\\share\\a.dll", &map), None);
    }

    #[test]
    fn the_main_image_is_captured_even_when_the_byte_budget_is_spent() {
        let mut total = MAX_TOTAL_IMAGE_BYTES;

        assert!(!claim_image_budget(&mut total, PAGE_SIZE, false));
        assert!(claim_image_budget(&mut total, PAGE_SIZE, true));
    }

    #[test]
    fn truncating_the_image_count_keeps_the_main_image_and_counts_the_rest()
    -> Result<(), Box<dyn std::error::Error>> {
        let regions = (0..MAX_IMAGES + 3)
            .map(|index| region(PAGE_SIZE.saturating_mul(index + 1), PAGE_SIZE))
            .collect::<Vec<_>>();
        let bases = regions
            .iter()
            .map(|region| region.base)
            .collect::<BTreeSet<_>>();
        let last = PAGE_SIZE.saturating_mul(MAX_IMAGES + 3);

        let (groups, skipped) = group_images(&regions, &bases, Some(last))?;

        assert_eq!(skipped, 2);
        assert!(groups.contains_key(&last));
        assert_eq!(groups.len(), MAX_IMAGES + 1);
        Ok(())
    }

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

    #[test]
    fn only_flags_a_mismatch_when_both_names_are_known() {
        assert!(!basename_mismatch(Some("ntdll.dll"), Some("ntdll.dll")));
        assert!(!basename_mismatch(Some("NTDLL.DLL"), Some("ntdll.dll")));
        assert!(basename_mismatch(Some("kernel32.dll"), Some("notepad.exe")));
        assert!(!basename_mismatch(None, Some("ntdll.dll")));
        assert!(!basename_mismatch(Some("ntdll.dll"), None));
        assert!(!basename_mismatch(None, None));
    }

    #[test]
    fn allocation_extents_take_the_furthest_end_per_allocation()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut first = region(0x1000, PAGE_SIZE);
        first.allocation_base = 0x1000;
        let mut second = region(0x1000 + PAGE_SIZE, PAGE_SIZE * 3);
        second.allocation_base = 0x1000;
        let mut other = region(0x9000, PAGE_SIZE);
        other.allocation_base = 0x9000;
        let executable = [0x1000usize, 0x9000].into_iter().collect();

        let extents = allocation_extents(&[first, second, other], &executable)?;

        assert_eq!(extents.get(&0x1000).copied(), Some(0x1000 + PAGE_SIZE * 4));
        assert_eq!(extents.get(&0x9000).copied(), Some(0x9000 + PAGE_SIZE));
        Ok(())
    }
}
