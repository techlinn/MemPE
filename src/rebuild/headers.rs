use super::EntryPointRva;
use super::{
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA,
    SECTION_HEADER_SIZE, align_up_u64,
};
use crate::pe::DOS_MAGIC;
use crate::pe::bytes::{read_u16, read_u32, write_pointer, write_u16, write_u32};
use crate::pe::parse::parse_disk_image;
use crate::pe::{DOS_LFANEW_OFFSET, FILE_CHARACTERISTICS_OFFSET, IMAGE_FILE_EXECUTABLE_IMAGE};
use crate::pe::{PeModel, Rva};
use crate::pe::{
    SECTION_CHARACTERISTICS_OFFSET, SECTION_COUNT_OFFSET, SECTION_RAW_SIZE_OFFSET,
    SECTION_RVA_OFFSET, SECTION_VIRTUAL_SIZE_OFFSET,
};
use crate::{AppError, AppResult};

const CHECKSUM_WORD_SIZE: usize = 2;

pub(super) fn finalize_output(
    output: &mut [u8],
    model: &PeModel,
    entry_point: Option<EntryPointRva>,
) -> AppResult<Finalized> {
    let unusable_observed_entry = apply_entry_point(output, model, entry_point)?;
    write_derived_header_fields(output, model)?;

    let executable_flag_added = ensure_executable_image_flag(output, model)?;
    verify_header_offset(output, model)?;
    apply_checksum(output, model)?;

    let final_entry_point = read_u32(output, model.entry_point_offset)?;
    parse_disk_image(output)
        .map_err(|error| AppError::new(format!("rebuilt PE does not parse as a file: {error}")))?;

    Ok(Finalized {
        entry_point: final_entry_point,
        executable_flag_added,
        unusable_observed_entry,
    })
}

pub(super) struct Finalized {
    pub(super) entry_point: u32,
    pub(super) executable_flag_added: bool,
    pub(super) unusable_observed_entry: Option<u32>,
}

fn verify_header_offset(output: &[u8], model: &PeModel) -> AppResult<()> {
    let lfanew = read_u32(output, DOS_LFANEW_OFFSET)? as usize;

    if lfanew != model.nt_offset {
        return Err(AppError::new(
            "e_lfanew shares its bytes with a header field the rebuild had to change",
        ));
    }

    Ok(())
}

fn ensure_executable_image_flag(output: &mut [u8], model: &PeModel) -> AppResult<bool> {
    let offset = model.nt_offset.saturating_add(FILE_CHARACTERISTICS_OFFSET);
    let characteristics = read_u16(output, offset)?;

    if characteristics & IMAGE_FILE_EXECUTABLE_IMAGE != 0 {
        return Ok(false);
    }

    write_u16(
        output,
        offset,
        characteristics | IMAGE_FILE_EXECUTABLE_IMAGE,
    )?;

    Ok(true)
}

pub(super) fn apply_checksum(output: &mut [u8], model: &PeModel) -> AppResult<()> {
    let checksum_offset = model.checksum_offset();
    write_u32(output, checksum_offset, 0)?;

    let checksum = compute_checksum(output)?;
    write_u32(output, checksum_offset, checksum)
}

fn compute_checksum(bytes: &[u8]) -> AppResult<u32> {
    let fold = |sum: u64| (sum & 0xFFFF) + (sum >> 16);
    let (words, odd) = bytes.as_chunks::<CHECKSUM_WORD_SIZE>();

    let sum = words
        .iter()
        .map(|word| u64::from(u16::from_le_bytes(*word)))
        .chain(odd.iter().map(|last| u64::from(*last)))
        .fold(0, |sum, word| fold(sum + word));

    let folded = fold(sum) + bytes.len() as u64;
    u32::try_from(folded).map_err(|_| AppError::new("checksum overflowed a PE field"))
}

pub(super) fn write_core_header_fields(
    output: &mut [u8],
    model: &PeModel,
    observed_base: usize,
    header_size: usize,
) -> AppResult<()> {
    write_u16(output, 0, DOS_MAGIC)?;
    write_u32(
        output,
        DOS_LFANEW_OFFSET,
        u32::try_from(model.nt_offset)
            .map_err(|_| AppError::new("NT header offset does not fit a PE field"))?,
    )?;
    write_image_base(output, model, observed_base)?;
    write_u32(
        output,
        model.size_of_image_offset,
        rebuilt_image_size(model)?,
    )?;
    write_u32(
        output,
        model.size_of_headers_offset,
        u32::try_from(header_size)
            .map_err(|_| AppError::new("rebuilt header size does not fit a PE field"))?,
    )?;
    write_u32(
        output,
        model.number_of_directories_offset,
        u32::try_from(model.directory_count)
            .map_err(|_| AppError::new("directory count does not fit a PE field"))?,
    )
}

fn rebuilt_image_size(model: &PeModel) -> AppResult<u32> {
    let maximum_end = model
        .sections
        .iter()
        .map(|section| u64::from(section.virtual_address().get()) + u64::from(section.span()))
        .max()
        .unwrap_or(0);
    let aligned = align_up_u64(maximum_end, u64::from(model.section_alignment))?;
    u32::try_from(aligned).map_err(|_| AppError::new("rebuilt image size exceeds u32"))
}

fn write_image_base(output: &mut [u8], model: &PeModel, observed_base: usize) -> AppResult<()> {
    write_pointer(
        output,
        model.image_base_offset,
        model.kind,
        observed_base as u64,
    )
}

fn apply_entry_point(
    output: &mut [u8],
    model: &PeModel,
    entry_point: Option<EntryPointRva>,
) -> AppResult<Option<u32>> {
    let Some(entry_point) = entry_point else {
        return Ok(None);
    };

    let rva = Rva(entry_point.get());

    if !model.executable_rva(rva) {
        if entry_point.is_observed() {
            return Ok(Some(entry_point.get()));
        }

        return Err(AppError::new(format!(
            "manual entry point RVA 0x{:X} is not inside an executable section",
            entry_point.get()
        )));
    }

    write_u32(output, model.entry_point_offset, entry_point.get())?;
    Ok(None)
}

fn write_derived_header_fields(output: &mut [u8], model: &PeModel) -> AppResult<()> {
    let section_count = usize::from(read_u16(
        output,
        model.nt_offset.saturating_add(SECTION_COUNT_OFFSET),
    )?);
    let maximum_section_count = model.sections.len().saturating_add(1);

    if section_count < model.sections.len() || section_count > maximum_section_count {
        return Err(AppError::new("rebuilt PE has an invalid section count"));
    }

    let first_section = model
        .sections
        .first()
        .map(|section| section.header_offset)
        .ok_or_else(|| AppError::new("rebuilt PE has no section table"))?;
    let mut sizes = DerivedSizes::default();

    for index in 0..section_count {
        let offset = first_section
            .checked_add(index.saturating_mul(SECTION_HEADER_SIZE))
            .ok_or_else(|| AppError::new("rebuilt section header offset overflowed"))?;
        sizes.add_section(output, offset, model.file_alignment)?;
    }

    for (offset, value) in [
        (model.size_of_code_offset, sizes.code),
        (
            model.size_of_initialized_data_offset,
            sizes.initialized_data,
        ),
        (
            model.size_of_uninitialized_data_offset,
            sizes.uninitialized_data,
        ),
        (model.base_of_code_offset, sizes.base_of_code),
    ] {
        if offset.abs_diff(DOS_LFANEW_OFFSET) >= 4 {
            write_u32(output, offset, value)?; // folded header: field overlaps e_lfanew
        }
    }

    Ok(())
}

#[derive(Default)]
struct DerivedSizes {
    code: u32,
    initialized_data: u32,
    uninitialized_data: u32,
    base_of_code: u32,
}

impl DerivedSizes {
    fn add_section(&mut self, output: &[u8], offset: usize, file_alignment: u32) -> AppResult<()> {
        let virtual_size = read_u32(output, offset.saturating_add(SECTION_VIRTUAL_SIZE_OFFSET))?;
        let virtual_address = read_u32(output, offset.saturating_add(SECTION_RVA_OFFSET))?;
        let raw_size = read_u32(output, offset.saturating_add(SECTION_RAW_SIZE_OFFSET))?;
        let characteristics = read_u32(
            output,
            offset.saturating_add(SECTION_CHARACTERISTICS_OFFSET),
        )?;

        if characteristics & IMAGE_SCN_CNT_CODE != 0 {
            self.code = add_size(self.code, raw_size, "code size")?;

            if self.base_of_code == 0 || virtual_address < self.base_of_code {
                self.base_of_code = virtual_address;
            }
        }

        if characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
            self.initialized_data =
                add_size(self.initialized_data, raw_size, "initialized-data size")?;
        }

        if characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            let aligned = align_up_u64(u64::from(virtual_size), u64::from(file_alignment))?;
            let aligned = u32::try_from(aligned)
                .map_err(|_| AppError::new("uninitialized-data size exceeds u32"))?;
            self.uninitialized_data =
                add_size(self.uninitialized_data, aligned, "uninitialized-data size")?;
        }

        Ok(())
    }
}

fn add_size(left: u32, right: u32, name: &str) -> AppResult<u32> {
    left.checked_add(right)
        .ok_or_else(|| AppError::new(format!("{name} overflowed")))
}
