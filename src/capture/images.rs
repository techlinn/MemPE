use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_IMAGE};

use super::{
    AddressSpace, CapturedImage, FileBacking, MAX_IMAGES, MainBaseConflict, MemoryRegion,
    PAGE_SIZE, is_executable, is_readable, is_writable, lasting_protection, read_region,
};
use crate::process::TargetProcess;
pub(super) use crate::process::mapped_file_name;
use crate::process::{DriveMap, FileIdentity};
use crate::rebuild::RegionProtection;
use crate::{AppError, AppResult};

#[derive(Default)]
pub(super) struct ImageGroup {
    pub(super) regions: Vec<MemoryRegion>,
    pub(super) end: usize,
}

pub(super) fn image_bases(regions: &[MemoryRegion], target: &TargetProcess) -> BTreeSet<usize> {
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

pub(super) fn group_images(
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
    evidence: Vec<RegionProtection>,
    protection_unknown: Vec<(usize, usize)>,
    unreadable_pages: usize,
    image_backed: bool,
}

pub(super) fn main_base_conflict(target: &TargetProcess) -> Option<MainBaseConflict> {
    let loader_list = target.main_module.as_ref()?.base;
    let peb = target.image_base?;

    (loader_list != peb).then_some(MainBaseConflict { loader_list, peb })
}

pub(super) fn resolve_main_base(
    space: &AddressSpace,
    target: &TargetProcess,
    bases: &BTreeSet<usize>,
) -> Option<usize> {
    if let Some(module) = &target.main_module {
        return Some(module.base);
    }
    if let Some(base) = target.image_base.filter(|base| bases.contains(base)) {
        return Some(base);
    }

    let drives = DriveMap::read();
    let wanted = target.path.to_string_lossy().into_owned();
    let mut by_path = None;
    let mut by_name = Vec::new();
    for base in bases {
        let Some(device) = mapped_file_name(space.handle(), *base) else {
            continue;
        };

        if drives
            .to_dos(&device)
            .is_some_and(|path| path.eq_ignore_ascii_case(&wanted))
        {
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

pub(super) fn read_image(
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
        protection_unknown: scan.protection_unknown,
        unreadable_pages: scan.unreadable_pages,
        name: module.map(|value| value.name.clone()),
        path: module.map(|value| value.path.clone()),
        is_main: main_base == Some(base),
        hidden,
        linked: target
            .module_listing_error
            .is_none()
            .then_some(module.is_some()),
        image_backed: scan.image_backed,
        path_mismatch: false,
        backing: FileBacking::Unknown,
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
    let mut protection_unknown = Vec::new();
    let mut unreadable_pages = 0usize;
    let mut image_backed = true;
    let mut committed = false;
    for region in regions {
        if region.state != MEM_COMMIT.0 {
            continue;
        }
        committed = true;

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
        let readable = is_readable(region.protect) || space.make_readable(read_base, length); // protectors drop access between uses
        let lasting = lasting_protection(region.protect);
        evidence.push(RegionProtection {
            offset,
            size: length,
            readable,
            writable: lasting.is_some_and(is_writable),
            executable: lasting.is_some_and(is_executable),
        });

        if lasting.is_none() {
            protection_unknown.push((offset, length));
        }

        let destination = bytes
            .get_mut(offset..offset.saturating_add(length))
            .ok_or_else(|| AppError::new("image region lies outside its output buffer"))?;
        if !readable {
            unreadable_pages = unreadable_pages.saturating_add(length.div_ceil(PAGE_SIZE));
            continue;
        }

        unreadable_pages =
            unreadable_pages.saturating_add(read_region(space, read_base, destination));
    }

    Ok(RegionScan {
        evidence,
        protection_unknown,
        unreadable_pages,
        image_backed: image_backed && committed,
    })
}

pub(super) fn annotate_images(process: HANDLE, images: &mut [CapturedImage]) {
    let drives = DriveMap::read();

    for image in images {
        let mapped = mapped_file_name(process, image.base);
        let actual = mapped.as_deref().and_then(|device| drives.to_dos(device));
        let mapped_path = actual.clone().map(PathBuf::from).or_else(|| {
            mapped
                .as_deref()
                .map(|device| PathBuf::from(format!(r"\\?\GLOBALROOT{device}")))
        });

        image.backing = match (&image.path, &mapped_path) {
            (Some(reported), _)
                if actual
                    .as_deref()
                    .is_some_and(|actual| reported.as_os_str().eq_ignore_ascii_case(actual)) =>
            {
                FileBacking::Same
            }
            (Some(reported), Some(mapped)) => same_file(
                FileIdentity::of_path(reported),
                FileIdentity::of_path(mapped),
            ),
            (Some(_), None) if !image.image_backed => FileBacking::Different, // private memory has no file behind it
            _ => FileBacking::Unknown,
        };
        image.path_mismatch = match image.backing {
            FileBacking::Same => false,
            FileBacking::Different => true,
            FileBacking::Unknown => image.path.is_some(), // an unconfirmed path is not trusted
        };

        let mapped_name = mapped.as_deref().map(|path| basename(path).to_owned());
        let replace = image.name.is_none() || image.path_mismatch;

        if let Some(mapped_name) = mapped_name.filter(|_| replace) {
            image.name = Some(mapped_name);
        }
    }
}

fn same_file(reported: Option<FileIdentity>, mapped: Option<FileIdentity>) -> FileBacking {
    match reported.zip(mapped) {
        Some((reported, mapped)) if reported == mapped => FileBacking::Same,
        Some(_) => FileBacking::Different,
        None => FileBacking::Unknown,
    }
}

fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}
