mod address_space;
mod hidden_images;
mod images;
mod page_coverage;
mod regions;
mod wait_until_stable;

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use std::time::Duration;

use self::address_space::{AddressSpace, OpenedAddressSpace};
pub(crate) use self::hidden_images::HiddenRejections;
use self::hidden_images::{
    HiddenScan, ScannedAllocations, executable_non_image_allocations, find_hidden_images,
    read_allocations, readable_non_image_allocations, unlock_regions,
};
use self::images::{
    ImageGroup, annotate_images, group_images, image_bases, main_base_conflict, mapped_file_name,
    read_image, resolve_main_base,
};
use self::page_coverage::measure_image_pages;
use self::regions::{
    is_executable, is_readable, is_writable, lasting_protection, list_regions, read_region,
    regions_in_range,
};
pub(crate) use self::wait_until_stable::wait_until_stable;
use crate::pe::MAX_IMAGE_SIZE;
use crate::pe::PAGE_SIZE;
use crate::process::{MemoryRegion, TargetProcess};
use crate::rebuild::RegionProtection;
use crate::{AppError, AppResult};

const MAX_IMAGES: usize = 4_096;
const MAX_TOTAL_IMAGE_BYTES: usize = 4 * 1024 * 1024 * 1024;
const READ_CHUNK: usize = 64 * 1024;
const MAX_HEADER_READ: usize = 64 * 1024;
const MAX_NON_IMAGE_SCAN_PAGES: usize = 262_144;
const MAX_NON_IMAGE_RW_BYTES: usize = 256 * 1024 * 1024;
const MAX_RAW_REGION_BYTES: usize = 512 * 1024 * 1024;

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

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FileBacking {
    Same,
    Different,
    Unknown,
}

#[derive(Clone, Copy)]
pub(crate) struct MainBaseConflict {
    pub(crate) loader_list: usize,
    pub(crate) peb: usize,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct SkippedImages {
    pub(crate) over_image_cap: usize,
    pub(crate) oversized: usize,
    pub(crate) over_budget: usize,
    pub(crate) unreadable: usize,
}

impl SkippedImages {
    pub(crate) fn total(&self) -> usize {
        self.over_image_cap
            .saturating_add(self.oversized)
            .saturating_add(self.over_budget)
            .saturating_add(self.unreadable)
    }
}

pub(crate) struct CapturedImage {
    pub(crate) base: usize,
    pub(crate) bytes: Vec<u8>,
    pub(crate) regions: Vec<RegionProtection>,
    pub(crate) protection_unknown: Vec<(usize, usize)>,
    pub(crate) unreadable_pages: usize,
    pub(crate) name: Option<String>,
    pub(crate) path: Option<PathBuf>,
    pub(crate) is_main: bool,
    pub(crate) hidden: bool,
    pub(crate) linked: Option<bool>,
    pub(crate) image_backed: bool,
    pub(crate) path_mismatch: bool,
    pub(crate) backing: FileBacking,
    pub(crate) resident_pages: usize,
    pub(crate) private_pages: usize,
    pub(crate) page_flags: Vec<u8>, // shorter than the image: the rest was not measured
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
    pub(crate) locked_non_image_bytes: usize,
    pub(crate) raw_bytes_skipped: usize,
    pub(crate) main_image_missing: bool,
    pub(crate) main_base_conflict: Option<MainBaseConflict>,
    pub(crate) skipped: SkippedImages,
    pub(crate) hidden_rejected: HiddenRejections,
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

pub(crate) fn capture(target: &TargetProcess, raw_regions: bool) -> AppResult<Capture> {
    let mut coverage = measure_image_pages(target);
    let OpenedAddressSpace {
        space,
        mode,
        setup_elapsed,
        fallback_reason,
    } = AddressSpace::acquire(target)?;

    let captured = capture_from_space(&space, target, raw_regions)?;
    let mut images = captured.images;
    annotate_images(space.handle(), &mut images);
    drop(space);
    for image in &mut images {
        if let Some(pages) = coverage.remove(&image.base) {
            image.resident_pages = pages.resident;
            image.private_pages = pages.private;
            image.page_flags = pages.flags;
        }
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
        locked_non_image_bytes: captured.locked_non_image_bytes,
        raw_bytes_skipped: captured.raw_bytes_skipped,
        main_image_missing: captured.main_image_missing,
        main_base_conflict: main_base_conflict(target),
        skipped: captured.skipped,
        hidden_rejected: captured.hidden_rejected,
    })
}

struct CapturedSpace {
    images: Vec<CapturedImage>,
    non_image_count: usize,
    carve_regions: Vec<RawRegion>,
    raw_regions: Vec<RawRegion>,
    unscanned_non_image_bytes: usize,
    locked_non_image_bytes: usize,
    raw_bytes_skipped: usize,
    main_image_missing: bool,
    skipped: SkippedImages,
    hidden_rejected: HiddenRejections,
}

fn read_all_images(
    space: &AddressSpace,
    target: &TargetProcess,
    regions: &[MemoryRegion],
    groups: BTreeMap<usize, ImageGroup>,
    hidden: &[(usize, usize)],
    main_base: Option<usize>,
) -> AppResult<(Vec<CapturedImage>, SkippedImages)> {
    let mut images = Vec::new();
    images
        .try_reserve_exact(groups.len().saturating_add(hidden.len()))
        .map_err(|_| AppError::new("not enough memory for the image list"))?;
    let mut total_size = 0usize;
    let mut skipped = SkippedImages::default();
    for (base, group) in groups {
        let size = group.end.saturating_sub(base);

        if size == 0 {
            continue;
        }

        if size > MAX_IMAGE_SIZE && main_base != Some(base) {
            skipped.oversized = skipped.oversized.saturating_add(1);
            continue;
        }

        if !claim_image_budget(&mut total_size, size, main_base == Some(base)) {
            skipped.over_budget = skipped.over_budget.saturating_add(1);
            continue;
        }

        let is_main = main_base == Some(base);
        match read_image(space, target, main_base, base, size, &group.regions, false) {
            Ok(read) => images.push(read),
            Err(error) if is_main => return Err(error),
            Err(_) => skipped.unreadable = skipped.unreadable.saturating_add(1),
        }
    }

    for (base, size) in hidden.iter().copied() {
        if images.iter().any(|image| image.base == base) {
            continue;
        }

        if size > MAX_IMAGE_SIZE {
            skipped.oversized = skipped.oversized.saturating_add(1);
            continue;
        }

        if !claim_image_budget(&mut total_size, size, false) {
            skipped.over_budget = skipped.over_budget.saturating_add(1);
            continue;
        }

        let image_regions = regions_in_range(regions, base, size)?;
        match read_image(space, target, main_base, base, size, &image_regions, true) {
            Ok(read) => images.push(read),
            Err(_) => skipped.unreadable = skipped.unreadable.saturating_add(1),
        }
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
    let mut unlocked = unlock_regions(space, &regions, &non_image_allocations);

    let bases = image_bases(&regions, target);
    let main_base = resolve_main_base(space, target, &bases);
    let (groups, over_image_cap) = group_images(&regions, &bases, main_base)?;
    let HiddenScan {
        found: hidden,
        unscanned: unscanned_hidden,
        rejected: hidden_rejected,
    } = find_hidden_images(space, &regions, &non_image_allocations, &unlocked)?;

    let (images, mut skipped) =
        read_all_images(space, target, &regions, groups, &hidden, main_base)?;
    skipped.over_image_cap = over_image_cap;

    if images.is_empty() {
        return Err(AppError::new(
            "no image allocations were present in the captured address space",
        ));
    }

    let main_image_missing = main_image_is_missing(&images);
    let captured_hidden = images
        .iter()
        .filter(|image| image.hidden)
        .map(|image| (image.base, image.bytes.len()))
        .collect::<Vec<_>>();
    let executable = non_image_allocations.iter().copied().collect::<Vec<_>>();
    let readable = readable_non_image_allocations(space, &regions, &non_image_allocations);
    unlocked.absorb(unlock_regions(space, &regions, &readable));

    let mut carve_allocations = executable.clone();
    carve_allocations.extend(readable);

    let carve = read_allocations(
        space,
        &regions,
        &carve_allocations,
        &unlocked,
        &captured_hidden,
        MAX_NON_IMAGE_RW_BYTES,
    );
    let raw = if want_raw_regions {
        read_allocations(
            space,
            &regions,
            &executable,
            &unlocked,
            &captured_hidden,
            MAX_RAW_REGION_BYTES,
        )
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
        unscanned_non_image_bytes: carve.skipped.saturating_add(unscanned_hidden),
        locked_non_image_bytes: unlocked.locked_bytes,
        raw_bytes_skipped: raw.skipped,
        main_image_missing,
        skipped,
        hidden_rejected,
    })
}

fn main_image_is_missing(images: &[CapturedImage]) -> bool {
    !images.iter().any(|image| image.is_main)
}

fn claim_image_budget(total: &mut usize, size: usize, mandatory: bool) -> bool {
    let next = total.saturating_add(size);

    if !mandatory && next > MAX_TOTAL_IMAGE_BYTES {
        return false;
    }

    *total = next;
    true
}
