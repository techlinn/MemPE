use std::borrow::Cow;

use super::DiskImage;
use super::sections::recover_section_headers;
use super::{SECTION_HEADER_SIZE, align_up};
use crate::pe::image::{read_u16, read_u32, write_u32, write_u64};
use crate::pe::packers::{FreshImage, HeaderSource, Origin, PackerFindings, Unpacked, unpack};
use crate::pe::parse::{parse_disk_image, parse_memory_image};
use crate::pe::{PeKind, PeModel, RegionEvidence, Rva};
use crate::{AppError, AppResult};

const MAX_DISK_HEADERS: usize = 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) enum Unpack {
    Restore,
    DetectOnly,
}

pub(super) struct Source<'a> {
    pub(super) bytes: Cow<'a, [u8]>,
    pub(super) disk_headers_used: bool,
    pub(super) packer: Option<PackerFindings>,
    pub(super) fresh: Option<FreshImage>,
}

pub(super) fn resolve_source_bytes<'a>(
    memory: &'a [u8],
    regions: &[RegionEvidence],
    observed_base: usize,
    disk: DiskImage<'_>,
    unpack_mode: Unpack,
) -> AppResult<Source<'a>> {
    let (initial, disk_headers_used) = match parse_memory_image(memory) {
        Ok(_) => (Cow::Borrowed(memory), false),
        Err(memory_error) => {
            let Some(disk_headers) = disk.headers else {
                return Err(memory_error);
            };

            let repaired = merge_header_evidence(memory, disk_headers, observed_base)?;
            parse_memory_image(&repaired).map_err(|disk_error| {
                AppError::new(format!(
                    "memory headers are invalid ({memory_error}); disk header repair failed ({disk_error})"
                ))
            })?;
            (Cow::Owned(repaired), true)
        }
    };

    let headers = match disk_headers_used {
        true => HeaderSource::Disk,
        false => HeaderSource::Memory,
    };

    let image = parse_memory_image(&initial)?;
    let origin = Origin {
        base: observed_base,
        headers,
        file: disk.file,
    };

    let packer = match (unpack(&image, &origin), unpack_mode) {
        (
            Some(Unpacked {
                image: Some(rebuilt),
                findings,
                fresh,
            }),
            Unpack::Restore,
        ) => {
            return Ok(Source {
                bytes: Cow::Owned(rebuilt),
                disk_headers_used,
                packer: Some(findings),
                fresh,
            });
        }
        (detected, Unpack::Restore) => detected.map(|unpacked| unpacked.findings),
        (detected, Unpack::DetectOnly) => detected.map(detection_only),
    };

    let bytes = match recover_section_headers(image.bytes(), image.model(), regions)? {
        Some(bytes) => Cow::Owned(bytes),
        None => initial,
    };

    Ok(Source {
        bytes,
        disk_headers_used,
        packer,
        fresh: None,
    })
}

fn detection_only(unpacked: Unpacked) -> PackerFindings {
    let mut findings = unpacked.findings;

    if unpacked.image.is_some() {
        findings.report.restored.clear();
        findings.report.lost.clear();
        findings.report.unrestored = vec!["image (the unpacked image could not be rebuilt)"];
    }

    findings
}

fn merge_header_evidence(memory: &[u8], disk: &[u8], observed_base: usize) -> AppResult<Vec<u8>> {
    let disk_image = parse_disk_image(disk)?;
    let model = disk_image.model();
    let memory_entry_point = validate_header_evidence(memory, model)?;
    let header_size = disk_header_size(disk, model)?;

    if header_size > memory.len() {
        return Err(AppError::new(
            "disk PE headers are larger than the captured image",
        ));
    }

    let mut repaired = memory.to_vec();
    let source = disk
        .get(..header_size)
        .ok_or_else(|| AppError::new("disk PE headers are truncated"))?;
    let destination = repaired
        .get_mut(..header_size)
        .ok_or_else(|| AppError::new("captured PE header range is missing"))?;
    destination.copy_from_slice(source);

    if let Some(entry_point) = memory_entry_point {
        write_u32(&mut repaired, model.entry_point_offset, entry_point)?;
    }

    match model.kind {
        PeKind::Pe32 => write_u32(
            &mut repaired,
            model.image_base_offset,
            u32::try_from(observed_base)
                .map_err(|_| AppError::new("observed base does not fit a PE32 image"))?,
        )?,
        PeKind::Pe32Plus => {
            write_u64(&mut repaired, model.image_base_offset, observed_base as u64)?
        }
    }

    Ok(repaired)
}

fn validate_header_evidence(memory: &[u8], model: &PeModel) -> AppResult<Option<u32>> {
    if model.image_size as usize > memory.len() {
        return Err(AppError::new("disk SizeOfImage exceeds the captured image"));
    }

    let memory_machine = read_u16(memory, model.nt_offset.saturating_add(4)).unwrap_or(0);
    let disk_machine = match model.kind {
        PeKind::Pe32 => 0x014C,
        PeKind::Pe32Plus => 0x8664,
    };

    if matches!(memory_machine, 0x014C | 0x8664) && memory_machine != disk_machine {
        return Err(AppError::new(
            "disk headers conflict with the captured image architecture",
        ));
    }

    let memory_magic = read_u16(memory, model.entry_point_offset.saturating_sub(16)).unwrap_or(0);
    let disk_magic = match model.kind {
        PeKind::Pe32 => 0x010B,
        PeKind::Pe32Plus => 0x020B,
    };

    if matches!(memory_magic, 0x010B | 0x020B) && memory_magic != disk_magic {
        return Err(AppError::new(
            "disk headers conflict with the captured optional-header format",
        ));
    }

    let matching_structure = memory_machine == disk_machine || memory_magic == disk_magic;
    let entry_point = read_u32(memory, model.entry_point_offset)
        .ok()
        .filter(|rva| matching_structure && model.executable_rva(Rva(*rva)));
    Ok(entry_point)
}

fn disk_header_size(disk: &[u8], model: &PeModel) -> AppResult<usize> {
    let section_table_end = model
        .sections
        .last()
        .and_then(|section| section.header_offset.checked_add(SECTION_HEADER_SIZE))
        .ok_or_else(|| AppError::new("disk PE has no complete section table"))?;
    let size = align_up(section_table_end, model.file_alignment as usize)?;

    if size > MAX_DISK_HEADERS || size > disk.len() {
        return Err(AppError::new(
            "disk PE header size is outside the 1 MiB safety limit",
        ));
    }

    Ok(size)
}
