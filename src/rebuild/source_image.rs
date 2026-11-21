use std::borrow::Cow;
use std::cell::OnceCell;
use std::ops::Range;

use super::RegionProtection;
use super::layout::sections_by_rva;
use super::{DiskImage, IMAGE_SCN_CNT_CODE, PAGE_SIZE, SECTION_HEADER_SIZE, align_up};
use crate::packers::unpack;
use crate::pe::DOS_LFANEW_OFFSET;
use crate::pe::DOS_MAGIC;
use crate::pe::bytes::{read_u16, write_pointer, write_u16, write_u32};
use crate::pe::parse::{MACHINE_AMD64, MACHINE_I386, parse_disk_image, parse_memory_image};
use crate::pe::process_memory::Process;
use crate::pe::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, PAGE_PRIVATE};
use crate::pe::{PE32_MAGIC, PE32_PLUS_MAGIC};
use crate::pe::{PeKind, PeModel};
use crate::pe::{SECTION_CHARACTERISTICS_OFFSET, SECTION_VIRTUAL_SIZE_OFFSET};
use crate::unpack::{FreshCopy, HeaderSource, Origin, PackerFindings, Unpacked};
use crate::{AppError, AppResult};

const MAX_DISK_HEADERS: usize = 1024 * 1024;

pub(super) struct Source<'a> {
    pub(super) bytes: Cow<'a, [u8]>,
    pub(super) disk_headers_used: bool,
    pub(super) salvaged_headers: bool,
    pub(super) packer: Option<PackerFindings>,
    pub(super) fresh: Option<FreshCopy>,
    pub(super) patched_sections: usize,
}

#[derive(Clone, Copy)]
pub(super) struct Protections<'a> {
    pub(super) regions: &'a [RegionProtection],
    pub(super) page_flags: &'a [u8],
}

pub(super) struct Resolution<'a> {
    pub(super) source: Source<'a>,
    pub(super) fallback: Option<Fallback<'a>>,
}

pub(super) struct Fallback<'a> {
    captured: CapturedBytes<'a>,
    findings: PackerFindings,
}

impl<'a> Fallback<'a> {
    pub(super) fn source(self, evidence: Protections<'_>) -> AppResult<Source<'a>> {
        captured_source(self.captured, evidence, Some(detection_only(self.findings)))
    }
}

struct CapturedBytes<'a> {
    bytes: Cow<'a, [u8]>,
    disk_headers_used: bool,
    salvaged_headers: bool,
}

pub(super) fn resolve_source_bytes<'a>(
    memory: &'a [u8],
    evidence: Protections<'_>,
    observed_base: usize,
    disk: DiskImage<'_>,
    process: Process<'_>,
) -> AppResult<Resolution<'a>> {
    let captured = capture(memory, observed_base, disk)?;
    let image = parse_memory_image(&captured.bytes)?;
    let origin = Origin {
        base: observed_base,
        headers: match captured.disk_headers_used {
            true => HeaderSource::Disk,
            false => HeaderSource::Memory,
        },
        file: disk.file,
        exports: process.exports,
        memory: process.memory,
        disk: OnceCell::new(),
    };

    match unpack(&image, &origin) {
        Some(Unpacked {
            image: Some(rebuilt),
            findings,
            fresh,
        }) => {
            let source = Source {
                bytes: Cow::Owned(rebuilt),
                disk_headers_used: captured.disk_headers_used,
                salvaged_headers: captured.salvaged_headers,
                packer: Some(findings.clone()),
                fresh,
                patched_sections: 0,
            };
            let fallback = Fallback { captured, findings };

            Ok(Resolution {
                source,
                fallback: Some(fallback),
            })
        }
        detected => Ok(Resolution {
            source: captured_source(
                captured,
                evidence,
                detected.map(|unpacked| unpacked.findings),
            )?,
            fallback: None,
        }),
    }
}

fn captured_source<'a>(
    captured: CapturedBytes<'a>,
    evidence: Protections<'_>,
    packer: Option<PackerFindings>,
) -> AppResult<Source<'a>> {
    let model = parse_memory_image(&captured.bytes)?.into_model();
    let patches = section_header_patches(&captured.bytes, &model, evidence)?;

    let mut bytes = captured.bytes;
    for (offset, value) in patches.fields {
        write_u32(bytes.to_mut(), offset, value)?;
    }

    Ok(Source {
        bytes,
        disk_headers_used: captured.disk_headers_used,
        salvaged_headers: captured.salvaged_headers,
        packer,
        fresh: None,
        patched_sections: patches.sections,
    })
}

fn capture<'a>(
    memory: &'a [u8],
    observed_base: usize,
    disk: DiskImage<'_>,
) -> AppResult<CapturedBytes<'a>> {
    let (initial, model, disk_headers_used) = match parse_memory_image(memory) {
        Ok(image) => (Cow::Borrowed(memory), image.into_model(), false),
        Err(memory_error) => {
            let Some(disk_headers) = disk.headers else {
                return Err(memory_error);
            };

            let repaired = merge_header_evidence(memory, disk_headers, observed_base)?;
            let model = parse_memory_image(&repaired)
                .map_err(|disk_error| {
                    AppError::new(format!(
                        "memory headers are invalid ({memory_error}); disk header repair failed ({disk_error})"
                    ))
                })?
                .into_model();
            (Cow::Owned(repaired), model, true)
        }
    };
    let (nt_offset, salvaged_headers) = (model.nt_offset, model.salvaged);

    if !salvaged_headers {
        return Ok(CapturedBytes {
            bytes: initial,
            disk_headers_used,
            salvaged_headers,
        });
    }

    Ok(CapturedBytes {
        bytes: restore_dos_header(initial, nt_offset),
        disk_headers_used,
        salvaged_headers,
    })
}

fn restore_dos_header(bytes: Cow<'_, [u8]>, nt_offset: usize) -> Cow<'_, [u8]> {
    let Ok(lfanew) = u32::try_from(nt_offset) else {
        return bytes;
    };

    let mut restored = bytes.to_vec();
    let written = write_u16(&mut restored, 0, DOS_MAGIC)
        .and_then(|()| write_u32(&mut restored, DOS_LFANEW_OFFSET, lfanew)); // folded header: e_lfanew is a field

    match written.is_ok() && parse_memory_image(&restored).is_ok() {
        true => Cow::Owned(restored),
        false => bytes,
    }
}

fn detection_only(mut findings: PackerFindings) -> PackerFindings {
    findings
        .report
        .refuse_image("the unpacked image could not be rebuilt");
    findings
}

fn merge_header_evidence(memory: &[u8], disk: &[u8], observed_base: usize) -> AppResult<Vec<u8>> {
    let disk_image = parse_disk_image(disk)?;
    let model = disk_image.model();
    validate_header_evidence(memory, model)?;
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

    write_pointer(
        &mut repaired,
        model.image_base_offset,
        model.kind,
        observed_base as u64,
    )?;

    Ok(repaired)
}

fn validate_header_evidence(memory: &[u8], model: &PeModel) -> AppResult<()> {
    if model.image_size as usize > memory.len() {
        return Err(AppError::new("disk SizeOfImage exceeds the captured image"));
    }

    let memory_machine = read_u16(memory, model.nt_offset.saturating_add(4)).unwrap_or(0);
    let disk_machine = match model.kind {
        PeKind::Pe32 => MACHINE_I386,
        PeKind::Pe32Plus => MACHINE_AMD64,
    };

    if matches!(memory_machine, MACHINE_I386 | MACHINE_AMD64) && memory_machine != disk_machine {
        return Err(AppError::new(
            "disk headers conflict with the captured image architecture",
        ));
    }

    let memory_magic = read_u16(memory, model.optional_header_offset()).unwrap_or(0);
    let disk_magic = match model.kind {
        PeKind::Pe32 => PE32_MAGIC,
        PeKind::Pe32Plus => PE32_PLUS_MAGIC,
    };

    if matches!(memory_magic, PE32_MAGIC | PE32_PLUS_MAGIC) && memory_magic != disk_magic {
        return Err(AppError::new(
            "disk headers conflict with the captured optional-header format",
        ));
    }

    Ok(())
}

fn disk_header_size(disk: &[u8], model: &PeModel) -> AppResult<usize> {
    let section_table_end = model
        .sections
        .last()
        .and_then(|section| section.header_offset.checked_add(SECTION_HEADER_SIZE))
        .ok_or_else(|| AppError::new("disk PE has no complete section table"))?;
    let size = align_up(section_table_end, model.file_alignment as usize)?;

    if size > MAX_DISK_HEADERS {
        return Err(AppError::new(format!(
            "disk PE headers need {size} bytes, more than the {MAX_DISK_HEADERS} mempe takes"
        )));
    }

    if size > disk.len() {
        return Err(AppError::new("the file ends inside its PE headers"));
    }

    Ok(size)
}

#[derive(Default)]
struct HeaderPatches {
    fields: Vec<(usize, u32)>,
    sections: usize,
}

fn section_header_patches(
    memory: &[u8],
    model: &PeModel,
    evidence: Protections<'_>,
) -> AppResult<HeaderPatches> {
    let mut patches = HeaderPatches::default();
    let regions = evidence.regions;

    if regions.is_empty() {
        return Ok(patches);
    }

    for (section, next_rva) in sections_by_rva(model) {
        let start = section.virtual_address().get() as usize;
        let limit = next_rva
            .unwrap_or(model.image_size as usize)
            .min(memory.len());
        if start >= limit {
            continue;
        }

        let declared = section.held_size() as usize;
        let expanded = expanded_section_length(memory, regions, start, limit, declared);
        let section_end = start.saturating_add(expanded).min(limit);
        let characteristics =
            recovered_characteristics(section.characteristics(), evidence, start, section_end);
        let before = patches.fields.len();

        if expanded > declared {
            let virtual_size = u32::try_from(expanded)
                .map_err(|_| AppError::new("recovered section size exceeds u32"))?;
            let field = section
                .header_offset
                .saturating_add(SECTION_VIRTUAL_SIZE_OFFSET);
            patches.fields.push((field, virtual_size));
        }

        if characteristics != section.characteristics() {
            let field = section
                .header_offset
                .saturating_add(SECTION_CHARACTERISTICS_OFFSET);
            patches.fields.push((field, characteristics));
        }

        if patches.fields.len() > before {
            patches.sections = patches.sections.saturating_add(1);
        }
    }

    Ok(patches)
}

fn expanded_section_length(
    memory: &[u8],
    regions: &[RegionProtection],
    start: usize,
    limit: usize,
    declared: usize,
) -> usize {
    let scan_start = start.saturating_add(declared).min(limit);
    let mut last_byte = scan_start;

    for region in regions.iter().filter(|region| region.readable) {
        let region_end = region.offset.saturating_add(region.size);
        let range_start = scan_start.max(region.offset);
        let range_end = limit.min(region_end).min(memory.len());

        if range_start >= range_end {
            continue;
        }

        let Some(bytes) = memory.get(range_start..range_end) else {
            continue;
        };

        if let Some(index) = bytes.iter().rposition(|byte| *byte != 0) {
            last_byte = last_byte.max(range_start.saturating_add(index).saturating_add(1));
        }
    }

    last_byte.saturating_sub(start).max(declared)
}

fn recovered_characteristics(
    characteristics: u32,
    evidence: Protections<'_>,
    start: usize,
    end: usize,
) -> u32 {
    let mut recovered = characteristics;

    for region in evidence.regions {
        let Some(shared) = overlap(region, start, end) else {
            continue;
        };

        if region.executable {
            recovered |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
        }

        if region.readable {
            recovered |= IMAGE_SCN_MEM_READ;
        }

        // write needs a page that was written while writable
        if region.writable && any_page_written(evidence.page_flags, shared) {
            recovered |= IMAGE_SCN_MEM_WRITE;
        }
    }

    recovered
}

fn overlap(region: &RegionProtection, start: usize, end: usize) -> Option<Range<usize>> {
    let shared = start.max(region.offset)..end.min(region.offset.saturating_add(region.size));

    (shared.start < shared.end).then_some(shared)
}

fn any_page_written(page_flags: &[u8], bytes: Range<usize>) -> bool {
    page_flags
        .get(bytes.start / PAGE_SIZE..bytes.end.div_ceil(PAGE_SIZE))
        .is_some_and(|pages| pages.iter().any(|flags| flags & PAGE_PRIVATE != 0))
}
