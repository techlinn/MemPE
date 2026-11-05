use crate::pe::image::{checked_add, first_section_rva, read_u16, read_u32, require_range};
use crate::pe::{PeImage, PeKind, PeModel, Rva, SECTION_HEADER_SIZE, SectionModel};
use crate::{AppError, AppResult};

const DOS_MAGIC: u16 = 0x5A4D;
const NT_SIGNATURE: u32 = 0x0000_4550;
const PE32_MAGIC: u16 = 0x010B;
const PE32_PLUS_MAGIC: u16 = 0x020B;
pub(super) const MACHINE_I386: u16 = 0x014C;
pub(super) const MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_DLL: u16 = 0x2000;
const FILE_HEADER_SIZE: usize = 20;
const MAX_SECTIONS: usize = 128;
const MAX_IMAGE_SIZE: usize = 1024 * 1024 * 1024;
const MAX_SALVAGE_SCAN: usize = 1024 * 1024;

pub(super) fn parse_memory_image(bytes: &[u8]) -> AppResult<PeImage<'_>> {
    if bytes.len() < 64 {
        return Err(AppError::new("captured image is smaller than a DOS header"));
    }

    let normal_offset = if read_u16(bytes, 0)? == DOS_MAGIC {
        usize::try_from(read_u32(bytes, 0x3c)?)
            .map_err(|_| AppError::new("e_lfanew does not fit memory"))?
    } else {
        usize::MAX
    };

    let normal_error = if normal_offset != usize::MAX {
        match parse_candidate(bytes, normal_offset, false, true) {
            Ok(model) => return Ok(PeImage::new(bytes, model)),
            Err(error) => error.to_string(),
        }
    } else {
        "DOS MZ signature is missing".to_owned()
    };

    let scan_limit = bytes.len().min(MAX_SALVAGE_SCAN);

    for offset in 0..scan_limit.saturating_sub(4) {
        if offset == normal_offset || peek_u32(bytes, offset) != NT_SIGNATURE {
            continue;
        }

        if let Ok(model) = parse_candidate(bytes, offset, true, true) {
            return Ok(PeImage::new(bytes, model));
        }
    }

    Err(AppError::new(format!(
        "PE header is not valid: {normal_error}; scan found no valid header"
    )))
}

pub(super) fn parse_disk_image(bytes: &[u8]) -> AppResult<PeImage<'_>> {
    if bytes.len() < 64 || read_u16(bytes, 0)? != DOS_MAGIC {
        return Err(AppError::new("disk DOS MZ signature is missing"));
    }

    let nt_offset = usize::try_from(read_u32(bytes, 0x3c)?)
        .map_err(|_| AppError::new("disk e_lfanew does not fit memory"))?;
    let model = parse_candidate(bytes, nt_offset, false, false)?;
    Ok(PeImage::new(bytes, model))
}

pub(crate) fn memory_image_size(bytes: &[u8]) -> AppResult<usize> {
    if bytes.len() < 64 || read_u16(bytes, 0)? != DOS_MAGIC {
        return Err(AppError::new("DOS MZ signature is missing"));
    }

    let nt_offset = usize::try_from(read_u32(bytes, 0x3c)?)
        .map_err(|_| AppError::new("e_lfanew does not fit memory"))?;
    parse_candidate(bytes, nt_offset, false, false).map(|model| model.image_size as usize)
}

struct FileHeader {
    offset: usize,
    machine: u16,
    section_count: usize,
    optional_size: usize,
    characteristics: u16,
}

struct OptionalOffsets {
    subsystem: usize,
    size_of_code: usize,
    size_of_initialized_data: usize,
    size_of_uninitialized_data: usize,
    entry_point: usize,
    base_of_code: usize,
    image_base: usize,
    dll_characteristics: usize,
}

struct OptionalShape {
    kind: PeKind,
    minimum_size: usize,
    image_base_relative: usize,
    directory_count_relative: usize,
    directory_relative: usize,
}

fn parse_candidate(
    bytes: &[u8],
    nt_offset: usize,
    salvaged: bool,
    require_full_image: bool,
) -> AppResult<PeModel> {
    let header = parse_file_header(bytes, nt_offset)?;
    let optional_offset = checked_add(header.offset, FILE_HEADER_SIZE, "optional header")?;
    let optional_end = checked_add(optional_offset, header.optional_size, "optional header end")?;
    require_range(bytes, optional_offset, header.optional_size)?;

    let shape = optional_header_shape(read_u16(bytes, optional_offset)?, header.machine)?;

    if header.optional_size < shape.minimum_size {
        return Err(AppError::new("optional header is truncated"));
    }

    let size_of_image_offset = checked_add(optional_offset, 56, "image size")?;
    let size_of_headers_offset = checked_add(optional_offset, 60, "header size")?;
    let number_of_directories_offset = checked_add(
        optional_offset,
        shape.directory_count_relative,
        "directory count",
    )?;

    let data_directory_offset = checked_add(
        optional_offset,
        shape.directory_relative,
        "data directories",
    )?;

    let file_alignment = read_u32(bytes, checked_add(optional_offset, 36, "file alignment")?)?;
    let section_alignment = read_u32(
        bytes,
        checked_add(optional_offset, 32, "section alignment")?,
    )?;
    validate_alignments(file_alignment, section_alignment)?;

    let declared_image_size =
        read_declared_image_size(bytes, size_of_image_offset, require_full_image)?;

    let declared_directory_count = usize::try_from(read_u32(bytes, number_of_directories_offset)?)
        .map_err(|_| AppError::new("data-directory count does not fit memory"))?;
    let directory_count = declared_directory_count
        .min(16)
        .min(optional_end.saturating_sub(data_directory_offset) / 8);
    let section_table_size = header
        .section_count
        .checked_mul(SECTION_HEADER_SIZE)
        .ok_or_else(|| AppError::new("section table size overflowed"))?;
    require_range(bytes, optional_end, section_table_size)?;

    let sections = parse_sections(
        bytes,
        optional_end,
        header.section_count,
        declared_image_size,
    )?;

    if salvaged {
        require_headers_before_sections(optional_end, section_table_size, &sections)?;
    }

    let offsets = optional_offsets(optional_offset, shape.image_base_relative)?;

    Ok(PeModel {
        kind: shape.kind,
        is_dll: header.characteristics & IMAGE_FILE_DLL != 0,
        subsystem: read_u16(bytes, offsets.subsystem)?,
        nt_offset,
        size_of_code_offset: offsets.size_of_code,
        size_of_initialized_data_offset: offsets.size_of_initialized_data,
        size_of_uninitialized_data_offset: offsets.size_of_uninitialized_data,
        entry_point_offset: offsets.entry_point,
        base_of_code_offset: offsets.base_of_code,
        image_base_offset: offsets.image_base,
        size_of_image_offset,
        size_of_headers_offset,
        dll_characteristics_offset: offsets.dll_characteristics,
        number_of_directories_offset,
        data_directory_offset,
        directory_count,
        file_alignment,
        section_alignment,
        image_size: u32::try_from(declared_image_size)
            .map_err(|_| AppError::new("declared image size does not fit a PE field"))?,
        sections,
        salvaged,
    })
}

fn optional_offsets(
    optional_offset: usize,
    image_base_relative: usize,
) -> AppResult<OptionalOffsets> {
    Ok(OptionalOffsets {
        subsystem: checked_add(optional_offset, 68, "subsystem")?,
        size_of_code: checked_add(optional_offset, 4, "code size")?,
        size_of_initialized_data: checked_add(optional_offset, 8, "initialized-data size")?,
        size_of_uninitialized_data: checked_add(optional_offset, 12, "uninitialized-data size")?,
        entry_point: checked_add(optional_offset, 16, "entry point")?,
        base_of_code: checked_add(optional_offset, 20, "base of code")?,
        image_base: checked_add(optional_offset, image_base_relative, "image base")?,
        dll_characteristics: checked_add(optional_offset, 70, "DLL characteristics")?,
    })
}

fn parse_file_header(bytes: &[u8], nt_offset: usize) -> AppResult<FileHeader> {
    if read_u32(bytes, nt_offset)? != NT_SIGNATURE {
        return Err(AppError::new("NT signature is missing"));
    }

    let offset = checked_add(nt_offset, 4, "file header offset")?;
    let machine = read_u16(bytes, offset)?;
    let section_count = usize::from(read_u16(bytes, checked_add(offset, 2, "section count")?)?);

    if section_count == 0 || section_count > MAX_SECTIONS {
        return Err(AppError::new(format!(
            "invalid section count {section_count}"
        )));
    }

    let optional_size = usize::from(read_u16(
        bytes,
        checked_add(offset, 16, "optional-header size")?,
    )?);

    let characteristics = read_u16(bytes, checked_add(offset, 18, "file characteristics")?)?;

    Ok(FileHeader {
        offset,
        machine,
        section_count,
        optional_size,
        characteristics,
    })
}

fn optional_header_shape(magic: u16, machine: u16) -> AppResult<OptionalShape> {
    let (kind, minimum_size, image_base_relative, directory_count_relative, directory_relative) =
        match magic {
            PE32_MAGIC if machine == MACHINE_I386 => (PeKind::Pe32, 96, 28, 92, 96),
            PE32_PLUS_MAGIC if machine == MACHINE_AMD64 => (PeKind::Pe32Plus, 112, 24, 108, 112),
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
        minimum_size,
        image_base_relative,
        directory_count_relative,
        directory_relative,
    })
}

fn read_declared_image_size(
    bytes: &[u8],
    size_of_image_offset: usize,
    require_full_image: bool,
) -> AppResult<usize> {
    let declared = usize::try_from(read_u32(bytes, size_of_image_offset)?)
        .map_err(|_| AppError::new("declared image size does not fit memory"))?;
    if declared == 0 || declared > MAX_IMAGE_SIZE {
        return Err(AppError::new(format!(
            "declared image size {declared} is outside the safety limit"
        )));
    }

    if require_full_image && declared > bytes.len() {
        return Err(AppError::new(format!(
            "declared image size {declared} does not fit the captured memory"
        )));
    }

    Ok(declared)
}

fn parse_sections(
    bytes: &[u8],
    table_offset: usize,
    section_count: usize,
    declared_image_size: usize,
) -> AppResult<Vec<SectionModel>> {
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let header_offset = checked_add(
            table_offset,
            index
                .checked_mul(SECTION_HEADER_SIZE)
                .ok_or_else(|| AppError::new("section header offset overflowed"))?,
            "section header",
        )?;

        let virtual_size = read_u32(bytes, checked_add(header_offset, 8, "virtual size")?)?;
        let virtual_address = read_u32(bytes, checked_add(header_offset, 12, "section RVA")?)?;
        let raw_size = read_u32(bytes, checked_add(header_offset, 16, "raw size")?)?;
        let raw_pointer = read_u32(bytes, checked_add(header_offset, 20, "raw pointer")?)?;
        let characteristics = read_u32(
            bytes,
            checked_add(header_offset, 36, "section characteristics")?,
        )?;

        let mut name = [0u8; 8];
        name.copy_from_slice(
            bytes
                .get(header_offset..header_offset.saturating_add(8))
                .ok_or_else(|| AppError::new("section name is outside the captured image"))?,
        );

        let section = SectionModel {
            header_offset,
            name,
            virtual_size,
            virtual_address: Rva(virtual_address),
            raw_pointer,
            raw_size,
            characteristics,
        };

        validate_section(&section, declared_image_size)?;
        sections.push(section);
    }

    validate_non_overlapping_sections(&sections)?;

    Ok(sections)
}

fn validate_alignments(file_alignment: u32, section_alignment: u32) -> AppResult<()> {
    if !(0x200..=0x1_0000).contains(&file_alignment) || !file_alignment.is_power_of_two() {
        return Err(AppError::new(format!(
            "invalid file alignment 0x{file_alignment:X}"
        )));
    }

    if section_alignment < file_alignment
        || section_alignment > 0x10_0000
        || !section_alignment.is_power_of_two()
    {
        return Err(AppError::new(format!(
            "invalid section alignment 0x{section_alignment:X}"
        )));
    }

    Ok(())
}

fn validate_section(section: &SectionModel, image_size: usize) -> AppResult<()> {
    let span = section.mapped_size();

    if span == 0 {
        return Ok(());
    }

    let end = section
        .virtual_address
        .as_usize()
        .checked_add(span as usize)
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
        // headers past the first section belong to a pe stored inside the image
        return Err(AppError::new(
            "salvaged headers lie inside their own section data",
        ));
    }

    Ok(())
}

fn peek_u32(bytes: &[u8], offset: usize) -> u32 {
    let Some(value) = bytes.get(offset..offset.saturating_add(4)) else {
        return 0;
    };

    u32::from_le_bytes([value[0], value[1], value[2], value[3]])
}
