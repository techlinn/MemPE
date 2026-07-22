use crate::pe::{PeKind, PeModel, Rva, SectionModel};
use crate::{AppError, AppResult};

const DOS_MAGIC: u16 = 0x5A4D;
const NT_SIGNATURE: u32 = 0x0000_4550;
const PE32_MAGIC: u16 = 0x010B;
const PE32_PLUS_MAGIC: u16 = 0x020B;
const MACHINE_I386: u16 = 0x014C;
const MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_DLL: u16 = 0x2000;
const FILE_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;
const MAX_SECTIONS: usize = 128;
const MAX_IMAGE_SIZE: usize = 1024 * 1024 * 1024;
const MAX_SALVAGE_SCAN: usize = 1024 * 1024;

pub(super) fn parse_memory_image(bytes: &[u8]) -> AppResult<PeModel> {
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
            Ok(model) => return Ok(model),
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
            return Ok(model);
        }
    }

    Err(AppError::new(format!(
        "PE header is not valid: {normal_error}; scan found no valid header"
    )))
}

pub(crate) fn memory_image_size(bytes: &[u8]) -> AppResult<usize> {
    if bytes.len() < 64 || read_u16(bytes, 0)? != DOS_MAGIC {
        return Err(AppError::new("DOS MZ signature is missing"));
    }
    let nt_offset = usize::try_from(read_u32(bytes, 0x3c)?)
        .map_err(|_| AppError::new("e_lfanew does not fit memory"))?;
    parse_candidate(bytes, nt_offset, false, false).map(|model| model.image_size as usize)
}

fn parse_candidate(
    bytes: &[u8],
    nt_offset: usize,
    salvaged: bool,
    require_full_image: bool,
) -> AppResult<PeModel> {
    if read_u32(bytes, nt_offset)? != NT_SIGNATURE {
        return Err(AppError::new("NT signature is missing"));
    }
    let file_header = checked_add(nt_offset, 4, "file header offset")?;
    let machine = read_u16(bytes, file_header)?;
    let section_count = usize::from(read_u16(
        bytes,
        checked_add(file_header, 2, "section count")?,
    )?);
    if section_count == 0 || section_count > MAX_SECTIONS {
        return Err(AppError::new(format!(
            "invalid section count {section_count}"
        )));
    }
    let optional_size = usize::from(read_u16(
        bytes,
        checked_add(file_header, 16, "optional-header size")?,
    )?);
    let characteristics = read_u16(bytes, checked_add(file_header, 18, "file characteristics")?)?;
    let optional_offset = checked_add(file_header, FILE_HEADER_SIZE, "optional header")?;
    let optional_end = checked_add(optional_offset, optional_size, "optional header end")?;
    require_range(bytes, optional_offset, optional_size)?;

    let magic = read_u16(bytes, optional_offset)?;
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
    if optional_size < minimum_size {
        return Err(AppError::new("optional header is truncated"));
    }

    let section_alignment_offset = checked_add(optional_offset, 32, "section alignment")?;
    let file_alignment_offset = checked_add(optional_offset, 36, "file alignment")?;
    let size_of_image_offset = checked_add(optional_offset, 56, "image size")?;
    let size_of_headers_offset = checked_add(optional_offset, 60, "header size")?;
    let number_of_directories_offset =
        checked_add(optional_offset, directory_count_relative, "directory count")?;
    let data_directory_offset =
        checked_add(optional_offset, directory_relative, "data directories")?;
    let file_alignment = read_u32(bytes, file_alignment_offset)?;
    let section_alignment = read_u32(bytes, section_alignment_offset)?;
    validate_alignments(file_alignment, section_alignment)?;
    let declared_image_size = usize::try_from(read_u32(bytes, size_of_image_offset)?)
        .map_err(|_| AppError::new("declared image size does not fit memory"))?;
    if declared_image_size == 0 || declared_image_size > MAX_IMAGE_SIZE {
        return Err(AppError::new(format!(
            "declared image size {declared_image_size} is outside the safety limit"
        )));
    }
    if require_full_image && declared_image_size > bytes.len() {
        return Err(AppError::new(format!(
            "declared image size {declared_image_size} does not fit the captured memory"
        )));
    }

    let declared_directory_count = usize::try_from(read_u32(bytes, number_of_directories_offset)?)
        .map_err(|_| AppError::new("data-directory count does not fit memory"))?;
    let available_directory_bytes = optional_end.saturating_sub(data_directory_offset);
    let directory_count = declared_directory_count
        .min(16)
        .min(available_directory_bytes / 8);
    let section_table_offset = optional_end;
    let section_table_size = section_count
        .checked_mul(SECTION_HEADER_SIZE)
        .ok_or_else(|| AppError::new("section table size overflowed"))?;
    require_range(bytes, section_table_offset, section_table_size)?;

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let header_offset = checked_add(
            section_table_offset,
            index
                .checked_mul(SECTION_HEADER_SIZE)
                .ok_or_else(|| AppError::new("section header offset overflowed"))?,
            "section header",
        )?;
        let virtual_size = read_u32(bytes, checked_add(header_offset, 8, "virtual size")?)?;
        let virtual_address = read_u32(bytes, checked_add(header_offset, 12, "section RVA")?)?;
        let raw_size = read_u32(bytes, checked_add(header_offset, 16, "raw size")?)?;
        let characteristics = read_u32(
            bytes,
            checked_add(header_offset, 36, "section characteristics")?,
        )?;
        validate_section(virtual_address, virtual_size, raw_size, declared_image_size)?;
        let mut name = [0u8; 8];
        name.copy_from_slice(
            bytes
                .get(header_offset..header_offset.saturating_add(8))
                .ok_or_else(|| AppError::new("section name is outside the captured image"))?,
        );
        sections.push(SectionModel {
            header_offset,
            name,
            virtual_size,
            virtual_address: Rva(virtual_address),
            raw_size,
            characteristics,
        });
    }
    validate_non_overlapping_sections(&sections)?;

    Ok(PeModel {
        kind,
        is_dll: characteristics & IMAGE_FILE_DLL != 0,
        nt_offset,
        image_base_offset: checked_add(optional_offset, image_base_relative, "image base")?,
        size_of_image_offset,
        size_of_headers_offset,
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

fn validate_section(
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    image_size: usize,
) -> AppResult<()> {
    let span = virtual_size.max(raw_size);
    if span == 0 {
        return Ok(());
    }
    let end = usize::try_from(virtual_address)
        .ok()
        .and_then(|start| start.checked_add(span as usize))
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
            let length = section.virtual_size.max(section.raw_size);
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

fn read_u16(bytes: &[u8], offset: usize) -> AppResult<u16> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| AppError::new("PE field lies outside the captured image"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> AppResult<u32> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| AppError::new("PE field lies outside the captured image"))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn peek_u32(bytes: &[u8], offset: usize) -> u32 {
    let Some(value) = bytes.get(offset..offset.saturating_add(4)) else {
        return 0;
    };
    u32::from_le_bytes([value[0], value[1], value[2], value[3]])
}

fn require_range(bytes: &[u8], offset: usize, length: usize) -> AppResult<()> {
    bytes
        .get(offset..offset.saturating_add(length))
        .map(|_| ())
        .ok_or_else(|| AppError::new("PE structure lies outside the captured image"))
}

fn checked_add(left: usize, right: usize, field: &str) -> AppResult<usize> {
    left.checked_add(right)
        .ok_or_else(|| AppError::new(format!("{field} offset overflowed")))
}
