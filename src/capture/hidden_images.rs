use std::collections::{BTreeMap, BTreeSet};

use windows::Win32::System::Memory::{MEM_COMMIT, MEM_IMAGE};

use super::{
    AddressSpace, MAX_HEADER_READ, MAX_IMAGES, MAX_NON_IMAGE_SCAN_PAGES, MemoryRegion, PAGE_SIZE,
    READ_CHUNK, RawRegion, is_executable, is_readable, lasting_protection, mapped_file_name,
    read_region,
};
use crate::pe::bytes::read_u32;
use crate::pe::parse::parse_disk_image;
use crate::pe::{DOS_LFANEW_OFFSET, DOS_MAGIC, MAX_IMAGE_SIZE, PE_SIGNATURE, PeModel};
use crate::{AppError, AppResult};

pub(super) fn readable_non_image_allocations(
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

#[derive(Default)]
pub(super) struct Unlocked {
    regions: BTreeSet<usize>,
    pub(super) locked_bytes: usize,
}

impl Unlocked {
    pub(super) fn absorb(&mut self, other: Self) {
        self.regions.extend(other.regions);
        self.locked_bytes = self.locked_bytes.saturating_add(other.locked_bytes);
    }

    fn opens(&self, region: &MemoryRegion) -> bool {
        is_readable(region.protect) || self.regions.contains(&region.base)
    }
}

pub(super) fn unlock_regions(
    space: &AddressSpace,
    regions: &[MemoryRegion],
    allocations: &BTreeSet<usize>,
) -> Unlocked {
    let mut unlocked = Unlocked::default();
    for region in regions {
        if region.state != MEM_COMMIT.0
            || is_readable(region.protect)
            || !allocations.contains(&region.allocation_base)
        {
            continue;
        }

        if space.make_readable(region.base, region.size) {
            unlocked.regions.insert(region.base);
        } else {
            unlocked.locked_bytes = unlocked.locked_bytes.saturating_add(region.size);
        }
    }

    unlocked
}

pub(super) struct ScannedAllocations {
    pub(super) regions: Vec<RawRegion>,
    pub(super) skipped: usize,
}

struct CommittedRun {
    allocation_base: usize,
    base: usize,
    end: usize,
    protections: u32,
    executable: bool,
}

fn uncovered(start: usize, end: usize, images: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut pieces = Vec::new();
    let mut cursor = start;
    for (base, size) in images {
        let image_end = base.saturating_add(*size);

        if image_end <= cursor || *base >= end {
            continue;
        }

        if *base > cursor {
            pieces.push((cursor, *base));
        }

        cursor = cursor.max(image_end);
    }

    if cursor < end {
        pieces.push((cursor, end));
    }

    pieces
}

fn committed_runs(
    regions: &[MemoryRegion],
    allocations: &[usize],
    unlocked: &Unlocked,
    images: &[(usize, usize)],
) -> BTreeMap<usize, Vec<CommittedRun>> {
    let wanted = allocations.iter().copied().collect::<BTreeSet<_>>();
    let mut images = images.to_vec();
    images.sort_unstable();

    let mut runs = BTreeMap::<usize, Vec<CommittedRun>>::new();
    for region in regions {
        if region.state != MEM_COMMIT.0
            || !unlocked.opens(region)
            || !wanted.contains(&region.allocation_base)
        {
            continue;
        }

        let executable = lasting_protection(region.protect).is_some_and(is_executable);
        let allocation_runs = runs.entry(region.allocation_base).or_default();

        for (base, end) in uncovered(region.base, region.end(), &images) {
            match allocation_runs.last_mut() {
                Some(run) if run.end == base => {
                    run.end = end;
                    run.protections |= region.protect;
                    run.executable |= executable;
                }
                _ => allocation_runs.push(CommittedRun {
                    allocation_base: region.allocation_base,
                    base,
                    end,
                    protections: region.protect,
                    executable,
                }),
            }
        }
    }

    runs
}

pub(super) fn read_allocations(
    space: &AddressSpace,
    regions: &[MemoryRegion],
    allocations: &[usize],
    unlocked: &Unlocked,
    images: &[(usize, usize)],
    budget: usize,
) -> ScannedAllocations {
    let mut runs = committed_runs(regions, allocations, unlocked, images);
    let mut remaining = budget;
    let mut skipped = 0usize;
    let mut collected = Vec::new();
    for allocation in allocations {
        for run in runs.remove(allocation).unwrap_or_default() {
            let committed = run.end.saturating_sub(run.base);
            let size = committed.min(remaining);
            let limit_reached = size == 0 || collected.len() >= MAX_NON_IMAGE_RUNS;
            let mut bytes = Vec::new();

            if limit_reached || bytes.try_reserve_exact(size).is_err() {
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

const MAX_NON_IMAGE_RUNS: usize = 4_096;

#[derive(Clone, Copy, Default)]
pub(crate) struct HiddenRejections {
    pub(crate) uncommitted: usize,
    pub(crate) file_layout: usize,
}

pub(super) struct HiddenScan {
    pub(super) found: Vec<(usize, usize)>,
    pub(super) unscanned: usize,
    pub(super) rejected: HiddenRejections,
}

enum HiddenCandidate {
    Mapped(usize),
    Uncommitted,
    FileLayout,
    NotAnImage,
}

pub(super) fn find_hidden_images(
    space: &AddressSpace,
    regions: &[MemoryRegion],
    executable_allocations: &BTreeSet<usize>,
    unlocked: &Unlocked,
) -> AppResult<HiddenScan> {
    let allocation_ends = allocation_extents(regions, executable_allocations)?;
    let mut found = Vec::new();
    let mut rejected = HiddenRejections::default();
    let mut read_until = BTreeMap::<usize, usize>::new();
    let mut scanned_pages = 0usize;
    let mut unscanned = 0usize;
    for region in regions {
        if !executable_allocations.contains(&region.allocation_base)
            || region.state != MEM_COMMIT.0
            || !unlocked.opens(region)
        {
            continue;
        }

        let Some(allocation_end) = allocation_ends.get(&region.allocation_base).copied() else {
            continue;
        };

        let mut chunk = Vec::new();
        let mut chunk_start = 0usize;
        for offset in (0..region.size).step_by(PAGE_SIZE) {
            let Some(base) = region.base.checked_add(offset) else {
                return Err(AppError::new("non-image PE scan address overflowed"));
            };
            if read_until
                .get(&region.allocation_base)
                .is_some_and(|end| base < *end)
            {
                continue;
            }

            if scanned_pages >= MAX_NON_IMAGE_SCAN_PAGES || found.len() >= MAX_IMAGES {
                unscanned = unscanned.saturating_add(region.size.saturating_sub(offset));
                break;
            }

            scanned_pages = scanned_pages.saturating_add(1);

            if offset >= chunk_start.saturating_add(chunk.len()) {
                chunk_start = offset;
                chunk.resize(READ_CHUNK.min(region.size.saturating_sub(offset)), 0);
                read_region(space, base, &mut chunk);
            }
            let page = chunk
                .get(offset.saturating_sub(chunk_start)..)
                .unwrap_or_default();
            if !page.starts_with(&DOS_MAGIC.to_le_bytes()) {
                continue;
            }

            match hidden_image_at(space, base, allocation_end) {
                HiddenCandidate::Mapped(available) => {
                    found.push((base, available));
                    read_until.insert(region.allocation_base, base.saturating_add(available));
                }
                HiddenCandidate::Uncommitted => {
                    rejected.uncommitted = rejected.uncommitted.saturating_add(1);
                }
                HiddenCandidate::FileLayout => {
                    rejected.file_layout = rejected.file_layout.saturating_add(1);
                }
                HiddenCandidate::NotAnImage => {}
            }
        }
    }

    Ok(HiddenScan {
        found,
        unscanned,
        rejected,
    })
}

fn allocation_extents(
    regions: &[MemoryRegion],
    executable_allocations: &BTreeSet<usize>,
) -> AppResult<BTreeMap<usize, usize>> {
    let mut ends = BTreeMap::<usize, usize>::new();
    for region in regions {
        if !executable_allocations.contains(&region.allocation_base) || region.state != MEM_COMMIT.0
        {
            continue; // reserved pages must not size an image
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

fn hidden_image_at(space: &AddressSpace, base: usize, allocation_end: usize) -> HiddenCandidate {
    let available = allocation_end.saturating_sub(base);
    let Some(header) = read_headers(space, base, available) else {
        return HiddenCandidate::NotAnImage;
    };
    let Ok(image) = parse_disk_image(&header) else {
        return HiddenCandidate::NotAnImage;
    };

    let declared = image.model().image_size as usize;
    let Some(mapped) = declared.checked_next_multiple_of(PAGE_SIZE) else {
        return HiddenCandidate::NotAnImage;
    };

    if mapped > available {
        return HiddenCandidate::Uncommitted;
    }

    if is_file_layout(&header, image.model()) {
        return HiddenCandidate::FileLayout;
    }

    HiddenCandidate::Mapped(mapped)
}

fn read_headers(space: &AddressSpace, base: usize, available: usize) -> Option<Vec<u8>> {
    let mut dos = vec![0u8; available.min(PAGE_SIZE)];
    read_region(space, base, &mut dos);

    if !dos.starts_with(&DOS_MAGIC.to_le_bytes()) {
        return None;
    }

    let lfanew = usize::try_from(read_u32(&dos, DOS_LFANEW_OFFSET).ok()?).ok()?;

    if lfanew >= available || lfanew > MAX_IMAGE_SIZE {
        return None;
    }

    let mut signature = [0u8; PE_SIGNATURE.len()];

    if !space.read_exact(base.checked_add(lfanew)?, &mut signature) || &signature != PE_SIGNATURE {
        return None;
    }

    let length = lfanew.saturating_add(MAX_HEADER_READ).min(available);
    let mut header = Vec::new();
    header.try_reserve_exact(length).ok()?;
    header.resize(length, 0);
    read_region(space, base, &mut header);

    Some(header)
}

fn is_file_layout(header: &[u8], model: &PeModel) -> bool {
    let Ok(headers_end) = read_u32(header, model.size_of_headers_offset) else {
        return false;
    };
    let raw = model
        .sections
        .iter()
        .map(|section| (section.raw_pointer as usize, section.raw_size as usize))
        .collect::<Vec<_>>();
    let first_rva = model
        .sections
        .iter()
        .map(|section| section.virtual_address().as_usize())
        .min();

    first_rva.is_some_and(|first_rva| {
        raw_data_before_sections(header, headers_end as usize, first_rva, &raw)
    })
}

// a mapped image holds nothing between SizeOfHeaders and its first section
fn raw_data_before_sections(
    header: &[u8],
    headers_end: usize,
    first_rva: usize,
    raw: &[(usize, usize)],
) -> bool {
    raw.iter().any(|(pointer, size)| {
        let end = pointer.saturating_add(*size).min(first_rva);
        let inside = *pointer >= headers_end && *pointer < end;
        let data = header.get(*pointer..end.min(header.len()));

        inside && data.is_some_and(|data| data.iter().any(|byte| *byte != 0))
    })
}

pub(super) fn executable_non_image_allocations(regions: &[MemoryRegion]) -> BTreeSet<usize> {
    regions
        .iter()
        .filter(|region| {
            region.state == MEM_COMMIT.0
                && region.kind != MEM_IMAGE.0
                && lasting_protection(region.protect).is_some_and(is_executable)
        })
        .map(|region| region.allocation_base)
        .filter(|base| *base != 0)
        .collect::<BTreeSet<_>>()
}
