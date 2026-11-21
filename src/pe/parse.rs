use crate::pe::bytes::{checked_add, read_u16, read_u32, require_range};
use crate::pe::{
    BASE_OF_CODE_OFFSET, DIRECTORY_COUNT, DIRECTORY_ENTRY_SIZE, DLL_CHARACTERISTICS_OFFSET,
    DOS_HEADER_SIZE, DOS_LFANEW_OFFSET, DOS_MAGIC, ENTRY_POINT_OFFSET, FILE_ALIGNMENT_OFFSET,
    FILE_CHARACTERISTICS_OFFSET, FILE_HEADER_SIZE, MACHINE_OFFSET, MAX_IMAGE_SIZE,
    OPTIONAL_SIZE_OFFSET, PE_SIGNATURE, PE32_MAGIC, PE32_PLUS_MAGIC, PeImage, PeKind, PeModel, Rva,
    SECTION_ALIGNMENT_OFFSET, SECTION_CHARACTERISTICS_OFFSET, SECTION_COUNT_OFFSET,
    SECTION_HEADER_SIZE, SECTION_NAME_SIZE, SECTION_RAW_POINTER_OFFSET, SECTION_RAW_SIZE_OFFSET,
    SECTION_RVA_OFFSET, SECTION_VIRTUAL_SIZE_OFFSET, SIZE_OF_CODE_OFFSET, SIZE_OF_HEADERS_OFFSET,
    SIZE_OF_IMAGE_OFFSET, SIZE_OF_INITIALIZED_DATA_OFFSET, SIZE_OF_UNINITIALIZED_DATA_OFFSET,
    SUBSYSTEM_OFFSET, SectionModel, first_section_rva,
};
use crate::{AppError, AppResult};

pub(crate) const MACHINE_I386: u16 = 0x014C;
pub(crate) const MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_DLL: u16 = 0x2000;
const MAX_SALVAGE_SCAN: usize = 1024 * 1024;
const NT_HEADER_ALIGNMENT: usize = 4; // loader wants dword aligned
const MIN_STANDARD_FILE_ALIGNMENT: u32 = 0x200;
const MAX_FILE_ALIGNMENT: u32 = 0x1_0000;
pub(crate) const MIN_STANDARD_SECTION_ALIGNMENT: u32 = 0x1000;
const MAX_SECTION_ALIGNMENT: u32 = 0x10_0000;

pub(crate) fn parse_memory_image(bytes: &[u8]) -> AppResult<PeImage<'_>> {
    if bytes.len() < DOS_HEADER_SIZE {
        return Err(AppError::new("captured image is smaller than a DOS header"));
    }

    let normal_offset = match read_u16(bytes, 0)? == DOS_MAGIC {
        true => Some(read_u32(bytes, DOS_LFANEW_OFFSET)? as usize),
        false => None,
    };

    let normal_error = match normal_offset {
        Some(offset) => match parse_candidate(bytes, offset, HeaderSource::Memory) {
            Ok(model) => return Ok(PeImage::new(bytes, model)),
            Err(error) => error.to_string(),
        },
        None => "DOS MZ signature is missing".to_owned(),
    };

    let scan_limit = bytes.len().min(MAX_SALVAGE_SCAN);
    let mut salvaged = (0..scan_limit)
        .step_by(NT_HEADER_ALIGNMENT)
        .filter(|offset| Some(*offset) != normal_offset && has_nt_signature(bytes, *offset))
        .filter_map(|offset| parse_candidate(bytes, offset, HeaderSource::Salvaged).ok());

    match (salvaged.next(), salvaged.next()) {
        (Some(model), None) => Ok(PeImage::new(bytes, model)),
        (Some(_), Some(_)) => Err(AppError::new(format!(
            "PE header is not valid: {normal_error}; scan found more than one valid header"
        ))),
        (None, _) => Err(AppError::new(format!(
            "PE header is not valid: {normal_error}; scan found no valid header"
        ))),
    }
}

pub(crate) fn map_disk_image(file: &[u8], end: usize) -> Option<Vec<u8>> {
    let disk = parse_disk_image(file).ok()?;
    let mut image = vec![0u8; end];

    let headers = read_u32(file, disk.model().size_of_headers_offset).ok()? as usize;
    let mapped_headers = headers.min(file.len()).min(end);
    image
        .get_mut(..mapped_headers)?
        .copy_from_slice(file.get(..mapped_headers)?);

    for section in &disk.model().sections {
        let start = section.raw_pointer as usize;
        let length = (section.raw_size as usize).min(section.span() as usize);
        let raw = file.get(start..start.checked_add(length)?)?;

        let Some(room) = image.get_mut(section.virtual_address().as_usize()..) else {
            continue; // starts past the requested end
        };

        let kept = raw.len().min(room.len());
        room.get_mut(..kept)?.copy_from_slice(raw.get(..kept)?);
    }

    Some(image)
}

pub(crate) fn parse_disk_image(bytes: &[u8]) -> AppResult<PeImage<'_>> {
    if bytes.len() < DOS_HEADER_SIZE || read_u16(bytes, 0)? != DOS_MAGIC {
        return Err(AppError::new("DOS MZ signature is missing"));
    }

    let nt_offset = read_u32(bytes, DOS_LFANEW_OFFSET)? as usize;
    let model = parse_candidate(bytes, nt_offset, HeaderSource::Disk)?;

    Ok(PeImage::new(bytes, model))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum HeaderSource {
    Memory,
    Salvaged,
    Disk,
}

struct FileHeader {
    machine: u16,
    section_count: usize,
    optional_size: usize,
    characteristics: u16,
}

struct OptionalShape {
    kind: PeKind,
    image_base_relative: usize,
    directory_relative: usize, // also the least optional header a loader takes
}

// field offsets below lie inside spans already checked with require_range
fn parse_candidate(bytes: &[u8], nt_offset: usize, source: HeaderSource) -> AppResult<PeModel> {
    let header = parse_file_header(bytes, nt_offset)?;
    let optional_offset = nt_offset + PE_SIGNATURE.len() + FILE_HEADER_SIZE;
    require_range(bytes, optional_offset, header.optional_size)?;
    let optional_end = optional_offset + header.optional_size;

    let shape = optional_header_shape(read_u16(bytes, optional_offset)?, header.machine)?;

    if header.optional_size < shape.directory_relative {
        return Err(AppError::new("optional header is truncated"));
    }

    let size_of_image_offset = optional_offset + SIZE_OF_IMAGE_OFFSET;
    let data_directory_offset = optional_offset + shape.directory_relative;
    let number_of_directories_offset = data_directory_offset - size_of::<u32>();

    let file_alignment = read_u32(bytes, optional_offset + FILE_ALIGNMENT_OFFSET)?;
    let section_alignment = read_u32(bytes, optional_offset + SECTION_ALIGNMENT_OFFSET)?;
    validate_alignments(file_alignment, section_alignment)?;

    let declared_image_size = read_declared_image_size(bytes, size_of_image_offset, source)?;

    let declared_directory_count = read_u32(bytes, number_of_directories_offset)? as usize;
    let directory_count = declared_directory_count
        .min(DIRECTORY_COUNT)
        .min(optional_end.saturating_sub(data_directory_offset) / DIRECTORY_ENTRY_SIZE);

    let section_table_size = header.section_count * SECTION_HEADER_SIZE;
    require_range(bytes, optional_end, section_table_size)?;

    let sections = parse_sections(
        bytes,
        optional_end,
        header.section_count,
        section_alignment,
        declared_image_size,
    )?;

    if source == HeaderSource::Salvaged {
        require_headers_before_sections(optional_end, section_table_size, &sections)?;
    }

    Ok(PeModel {
        kind: shape.kind,
        is_dll: header.characteristics & IMAGE_FILE_DLL != 0,
        subsystem: read_u16(bytes, optional_offset + SUBSYSTEM_OFFSET)?,
        nt_offset,
        size_of_code_offset: optional_offset + SIZE_OF_CODE_OFFSET,
        size_of_initialized_data_offset: optional_offset + SIZE_OF_INITIALIZED_DATA_OFFSET,
        size_of_uninitialized_data_offset: optional_offset + SIZE_OF_UNINITIALIZED_DATA_OFFSET,
        entry_point_offset: optional_offset + ENTRY_POINT_OFFSET,
        base_of_code_offset: optional_offset + BASE_OF_CODE_OFFSET,
        image_base_offset: optional_offset + shape.image_base_relative,
        size_of_image_offset,
        size_of_headers_offset: optional_offset + SIZE_OF_HEADERS_OFFSET,
        dll_characteristics_offset: optional_offset + DLL_CHARACTERISTICS_OFFSET,
        number_of_directories_offset,
        data_directory_offset,
        directory_count,
        file_alignment,
        section_alignment,
        image_size: u32::try_from(declared_image_size)
            .map_err(|_| AppError::new("declared image size does not fit a PE field"))?,
        sections,
        salvaged: source == HeaderSource::Salvaged,
    })
}

fn parse_file_header(bytes: &[u8], nt_offset: usize) -> AppResult<FileHeader> {
    if !has_nt_signature(bytes, nt_offset) {
        return Err(AppError::new("NT signature is missing"));
    }

    let machine = read_u16(bytes, nt_offset + MACHINE_OFFSET)?;
    let section_count = usize::from(read_u16(bytes, nt_offset + SECTION_COUNT_OFFSET)?);

    if section_count == 0 {
        return Err(AppError::new("PE has no sections"));
    }

    Ok(FileHeader {
        machine,
        section_count,
        optional_size: usize::from(read_u16(bytes, nt_offset + OPTIONAL_SIZE_OFFSET)?),
        characteristics: read_u16(bytes, nt_offset + FILE_CHARACTERISTICS_OFFSET)?,
    })
}

fn optional_header_shape(magic: u16, machine: u16) -> AppResult<OptionalShape> {
    let (kind, image_base_relative, directory_relative) = match magic {
        PE32_MAGIC if machine == MACHINE_I386 => (PeKind::Pe32, 28, 96),
        PE32_PLUS_MAGIC if machine == MACHINE_AMD64 => (PeKind::Pe32Plus, 24, 112),
        PE32_MAGIC => {
            return Err(AppError::new(format!(
                "PE32 optional header conflicts with machine 0x{machine:04X}"
            )));
        }
        PE32_PLUS_MAGIC => {
            return Err(AppError::new(format!(
                "PE32+ optional header conflicts with machine 0x{machine:04X}"
            )));
        }
        _ => return Err(AppError::new(format!("unknown PE magic 0x{magic:04X}"))),
    };

    Ok(OptionalShape {
        kind,
        image_base_relative,
        directory_relative,
    })
}

fn read_declared_image_size(
    bytes: &[u8],
    size_of_image_offset: usize,
    source: HeaderSource,
) -> AppResult<usize> {
    let declared = read_u32(bytes, size_of_image_offset)? as usize;

    if declared == 0 {
        return Err(AppError::new("declared image size is zero"));
    }

    match source {
        HeaderSource::Memory | HeaderSource::Salvaged if declared > bytes.len() => {
            Err(AppError::new(format!(
                "declared image size {declared} does not fit the captured memory"
            )))
        }
        // not captured yet, only promised
        HeaderSource::Disk if declared > MAX_IMAGE_SIZE => Err(AppError::new(format!(
            "declared image size {declared} is outside the safety limit"
        ))),
        _ => Ok(declared),
    }
}

fn parse_sections(
    bytes: &[u8],
    table_offset: usize,
    section_count: usize,
    section_alignment: u32,
    declared_image_size: usize,
) -> AppResult<Vec<SectionModel>> {
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let header_offset = table_offset + index * SECTION_HEADER_SIZE;
        let field = |offset: usize| read_u32(bytes, header_offset + offset);

        let mut name = [0u8; SECTION_NAME_SIZE];
        name.copy_from_slice(
            bytes
                .get(header_offset..header_offset + SECTION_NAME_SIZE)
                .ok_or_else(|| AppError::new("section name is outside the captured image"))?,
        );

        let mut section = SectionModel {
            header_offset,
            name,
            virtual_size: field(SECTION_VIRTUAL_SIZE_OFFSET)?,
            virtual_address: Rva(field(SECTION_RVA_OFFSET)?),
            raw_pointer: field(SECTION_RAW_POINTER_OFFSET)?,
            raw_size: field(SECTION_RAW_SIZE_OFFSET)?,
            characteristics: field(SECTION_CHARACTERISTICS_OFFSET)?,
            span: 0,
        };

        validate_section(&section, declared_image_size)?;
        section.span = section_span(&section, section_alignment, declared_image_size);
        sections.push(section);
    }

    validate_non_overlapping_sections(&sections)?;

    Ok(sections)
}

fn validate_alignments(file_alignment: u32, section_alignment: u32) -> AppResult<()> {
    if !file_alignment.is_power_of_two() || !section_alignment.is_power_of_two() {
        return Err(AppError::new(format!(
            "alignments 0x{file_alignment:X}/0x{section_alignment:X} are not powers of two"
        )));
    }

    let low = section_alignment < MIN_STANDARD_SECTION_ALIGNMENT;
    let valid = match low {
        true => file_alignment == section_alignment,
        false => {
            (MIN_STANDARD_FILE_ALIGNMENT..=MAX_FILE_ALIGNMENT).contains(&file_alignment)
                && file_alignment <= section_alignment
                && section_alignment <= MAX_SECTION_ALIGNMENT
        }
    };

    if !valid {
        return Err(AppError::new(format!(
            "invalid alignments: file 0x{file_alignment:X}, section 0x{section_alignment:X}"
        )));
    }

    Ok(())
}

fn section_span(section: &SectionModel, section_alignment: u32, image_size: usize) -> u32 {
    let mapped = u64::from(section.mapped_size());

    if mapped == 0 {
        return 0;
    }

    let start = u64::from(section.virtual_address.get());
    let room = (image_size as u64).saturating_sub(start);
    let aligned = mapped.next_multiple_of(u64::from(section_alignment));
    u32::try_from(aligned.min(room).max(mapped)).unwrap_or(u32::MAX)
}

fn validate_section(section: &SectionModel, image_size: usize) -> AppResult<()> {
    let mapped = section.mapped_size();

    if mapped == 0 {
        return Ok(());
    }

    let end = section
        .virtual_address
        .as_usize()
        .checked_add(mapped as usize)
        .ok_or_else(|| AppError::new("section virtual range overflowed"))?;
    if end > image_size {
        return Err(AppError::new(format!(
            "section ending at RVA 0x{end:X} exceeds SizeOfImage"
        )));
    }

    Ok(())
}

fn validate_non_overlapping_sections(sections: &[SectionModel]) -> AppResult<()> {
    let mut ranges = sections
        .iter()
        .filter_map(|section| {
            let length = section.mapped_size();
            (length != 0).then_some((section.virtual_address.get(), length))
        })
        .collect::<Vec<_>>();
    ranges.sort_unstable_by_key(|range| range.0);

    let mut previous_end = 0u64;
    for (start, length) in ranges {
        if u64::from(start) < previous_end {
            return Err(AppError::new("section virtual ranges overlap"));
        }

        previous_end = u64::from(start) + u64::from(length);
    }

    Ok(())
}

fn require_headers_before_sections(
    table_offset: usize,
    table_size: usize,
    sections: &[SectionModel],
) -> AppResult<()> {
    let table_end = checked_add(table_offset, table_size, "section table end")?;
    let first_section = first_section_rva(sections).unwrap_or(usize::MAX);

    if table_end > first_section {
        // embedded pe, not ours
        return Err(AppError::new(
            "salvaged headers lie inside their own section data",
        ));
    }

    Ok(())
}

fn has_nt_signature(bytes: &[u8], offset: usize) -> bool {
    offset
        .checked_add(PE_SIGNATURE.len())
        .and_then(|end| bytes.get(offset..end))
        == Some(&PE_SIGNATURE[..])
}
