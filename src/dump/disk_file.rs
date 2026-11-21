use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::capture::CapturedImage;
use crate::pe::bytes::{read_u16, read_u32};
use crate::pe::{DOS_HEADER_SIZE, DOS_LFANEW_OFFSET, FILE_ALIGNMENT_OFFSET, FILE_HEADER_SIZE};
use crate::pe::{OPTIONAL_SIZE_OFFSET, PE_SIGNATURE, Process, SECTION_COUNT_OFFSET};
use crate::pe::{PeKind, SECTION_HEADER_SIZE, SIZE_OF_HEADERS_OFFSET};
use crate::process::system_folder;
use crate::rebuild::EntryPointRva;
use crate::rebuild::{self, DiskImage, OverlayStart, RebuiltFile};
use crate::unpack::{PackerReport, Part};
use crate::{AppError, AppResult};

pub(super) const MAX_OVERLAY_BYTES: u64 = 1024 * 1024 * 1024;

pub(super) const CRT_API_SET_PREFIX: &str = "api-ms-win-crt-";

pub(super) const MAX_API_SET_BYTES: u64 = 1024 * 1024;

#[derive(Default)]
pub(super) struct OverlayOutcome {
    pub(super) left: bool,
    pub(super) unchecked: bool,
    pub(super) fresh_dropped: Option<AppError>,
}

pub(super) fn crt_api_sets() -> Vec<Vec<u8>> {
    let Some(folder) = system_folder(PeKind::Pe32Plus) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(folder.join("downlevel")) else {
        return Vec::new();
    };

    entries
        .flatten()
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            name.starts_with(CRT_API_SET_PREFIX) && name.ends_with(".dll")
        })
        .filter(|entry| {
            entry
                .metadata()
                .is_ok_and(|meta| meta.len() <= MAX_API_SET_BYTES)
        })
        .filter_map(|entry| std::fs::read(entry.path()).ok())
        .collect()
}

pub(super) fn rebuild_with_disk_headers(
    image: &CapturedImage,
    process: Process<'_>,
    entry_point: Option<EntryPointRva>,
    memory_error: AppError,
) -> AppResult<RebuiltFile> {
    let Some(path) = &image.path else {
        return Err(memory_error);
    };

    if !image.image_backed {
        return Err(AppError::new(format!(
            "{memory_error}; refusing disk headers from {}: the memory at this base is no longer image-backed",
            path.display()
        )));
    }

    if image.path_mismatch {
        return Err(AppError::new(format!(
            "{memory_error}; refusing disk headers from {}: a different file is mapped at this base",
            path.display()
        )));
    }

    let disk_headers = read_disk_headers(path).map_err(|disk_error| {
        AppError::new(format!(
            "{memory_error}; could not read disk headers from {}: {disk_error}",
            path.display()
        ))
    })?;

    rebuild::rebuild(
        captured(image),
        DiskImage {
            headers: Some(&disk_headers),
            file: Some(path),
        },
        process,
        entry_point,
    )
}

pub(super) fn with_overlay(
    image: &CapturedImage,
    mut rebuilt: RebuiltFile,
) -> (RebuiltFile, OverlayOutcome) {
    let mut outcome = OverlayOutcome::default();
    let Some(path) = packed_file(image) else {
        return (rebuilt, outcome);
    };

    let unpacked = rebuilt
        .info
        .packer
        .as_ref()
        .is_some_and(PackerReport::restored_anything);

    if !unpacked {
        match has_overlay(path) {
            Ok(left) => outcome.left = left,
            Err(_) => outcome.unchecked = true,
        }

        return (rebuilt, outcome);
    }

    let appended = match read_overlay(path) {
        Ok(None) => return (rebuilt, outcome),
        Ok(Some(overlay)) => {
            let fresh_error = rebuilt
                .fresh
                .as_mut()
                .and_then(|fresh| rebuild::append_overlay(&mut fresh.bytes, &overlay).err());
            if fresh_error.is_some() {
                rebuilt.fresh = None;
                outcome.fresh_dropped = fresh_error;
            }

            rebuild::append_overlay(&mut rebuilt.bytes, &overlay)
        }
        Err(error) => Err(error),
    };

    if let Some(report) = &mut rebuilt.info.packer {
        match appended {
            Ok(()) => report.restored(Part::Overlay),
            Err(error) => {
                report.failed(Part::Overlay);
                report.notes.push(format!("overlay not copied: {error}"));
            }
        }
    }

    (rebuilt, outcome)
}

pub(super) fn packed_file(image: &CapturedImage) -> Option<&Path> {
    image
        .path
        .as_deref()
        .filter(|_| image.image_backed && !image.path_mismatch)
}

fn read_overlay(path: &Path) -> AppResult<Option<Vec<u8>>> {
    let Some((file, start)) = open_overlay(path)? else {
        return Ok(None);
    };

    let mut overlay = Vec::new();
    file.take(MAX_OVERLAY_BYTES)
        .read_to_end(&mut overlay)
        .map_err(unreadable(path))?;

    let overlay = start.without_padding(overlay);
    Ok((!overlay.is_empty()).then_some(overlay))
}

// zero padding up to the file alignment is no overlay, so one byte past it decides
fn has_overlay(path: &Path) -> AppResult<bool> {
    let Some((file, start)) = open_overlay(path)? else {
        return Ok(false);
    };

    let mut head = Vec::new();
    file.take((start.padding as u64).saturating_add(1))
        .read_to_end(&mut head)
        .map_err(unreadable(path))?;

    Ok(!start.without_padding(head).is_empty())
}

fn open_overlay(path: &Path) -> AppResult<Option<(File, OverlayStart)>> {
    let headers = read_disk_headers(path)?;
    let start = rebuild::overlay_offset(&headers)?;
    let mut file = File::open(path).map_err(unreadable(path))?;

    let length = file.metadata().map_err(unreadable(path))?.len();
    if length <= start.offset {
        return Ok(None);
    }

    if length - start.offset > MAX_OVERLAY_BYTES {
        return Err(AppError::new(format!(
            "the file's overlay is {} bytes, more than the {MAX_OVERLAY_BYTES} mempe copies",
            length - start.offset
        )));
    }

    file.seek(SeekFrom::Start(start.offset))
        .map_err(unreadable(path))?;
    Ok(Some((file, start)))
}

fn unreadable(path: &Path) -> impl Fn(std::io::Error) -> AppError + '_ {
    move |error| AppError::new(format!("cannot read {}: {error}", path.display()))
}

pub(super) fn read_disk_headers(path: &Path) -> AppResult<Vec<u8>> {
    let mut file = File::open(path)
        .map_err(|error| AppError::new(format!("cannot open {}: {error}", path.display())))?;
    let mut bytes = Vec::new();

    read_up_to(&mut file, &mut bytes, DOS_HEADER_SIZE, path)?;
    let Some(fields_end) = fixed_fields_end(&bytes) else {
        return Ok(bytes);
    };

    read_up_to(&mut file, &mut bytes, fields_end, path)?;
    let Some(headers_end) = declared_headers_end(&bytes) else {
        return Ok(bytes);
    };

    read_up_to(&mut file, &mut bytes, headers_end, path)?;
    Ok(bytes)
}

// a short file just yields fewer bytes
fn read_up_to(file: &mut File, bytes: &mut Vec<u8>, end: usize, path: &Path) -> AppResult<()> {
    let length = file.metadata().map_err(unreadable(path))?.len();
    let end = end.min(usize::try_from(length).unwrap_or(usize::MAX));
    let wanted = end.saturating_sub(bytes.len());

    bytes.try_reserve_exact(wanted).map_err(|_| {
        AppError::new(format!(
            "not enough memory for the {end} header bytes of {}",
            path.display()
        ))
    })?;
    file.take(wanted as u64)
        .read_to_end(bytes)
        .map_err(unreadable(path))?;

    Ok(())
}

fn optional_header_offset(bytes: &[u8]) -> Option<usize> {
    let nt_offset = usize::try_from(read_u32(bytes, DOS_LFANEW_OFFSET).ok()?).ok()?;
    nt_offset
        .checked_add(PE_SIGNATURE.len())?
        .checked_add(FILE_HEADER_SIZE)
}

fn fixed_fields_end(bytes: &[u8]) -> Option<usize> {
    optional_header_offset(bytes)?
        .checked_add(SIZE_OF_HEADERS_OFFSET)?
        .checked_add(size_of::<u32>())
}

fn declared_headers_end(bytes: &[u8]) -> Option<usize> {
    let optional = optional_header_offset(bytes)?;
    let nt_offset = optional.checked_sub(PE_SIGNATURE.len() + FILE_HEADER_SIZE)?;
    let sections = usize::from(read_u16(bytes, nt_offset.checked_add(SECTION_COUNT_OFFSET)?).ok()?);
    let optional_size =
        usize::from(read_u16(bytes, nt_offset.checked_add(OPTIONAL_SIZE_OFFSET)?).ok()?);
    let declared =
        usize::try_from(read_u32(bytes, optional.checked_add(SIZE_OF_HEADERS_OFFSET)?).ok()?)
            .ok()?;
    let alignment =
        usize::try_from(read_u32(bytes, optional.checked_add(FILE_ALIGNMENT_OFFSET)?).ok()?)
            .ok()?;

    let section_table_end = optional
        .checked_add(optional_size)?
        .checked_add(sections.checked_mul(SECTION_HEADER_SIZE)?)?;
    let table_end = match alignment.is_power_of_two() {
        true => section_table_end.checked_next_multiple_of(alignment)?, // the rebuild copies whole file-aligned headers
        false => section_table_end,
    };
    Some(declared.max(table_end))
}

pub(super) fn captured(image: &CapturedImage) -> rebuild::Captured<'_> {
    rebuild::Captured {
        memory: &image.bytes,
        regions: &image.regions,
        base: image.base,
        page_flags: &image.page_flags,
    }
}
