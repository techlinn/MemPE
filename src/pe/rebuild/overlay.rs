use super::directories::write_directory;
use super::headers::apply_checksum;
use super::{MAX_OUTPUT_SIZE, RebuiltImage, align_up};
use crate::pe::SECURITY_DIRECTORY;
use crate::pe::image::{read_u16, read_u32};
use crate::pe::parse::parse_disk_image;
use crate::{AppError, AppResult};

const CERTIFICATE_HEADER: usize = 8;
const CERTIFICATE_REVISION_OFFSET: usize = 4;
const CERTIFICATE_REVISION: u16 = 0x0200;
const CERTIFICATE_ALIGNMENT: usize = 8;

pub(crate) fn overlay_offset(disk_headers: &[u8]) -> Option<u64> {
    let image = parse_disk_image(disk_headers).ok()?;
    let model = image.model();
    let alignment = u64::from(model.file_alignment.max(1));

    model
        .sections()
        .iter()
        .map(|section| {
            u64::from(section.raw_pointer) + u64::from(section.raw_size).next_multiple_of(alignment)
        })
        .max() // the loader maps raw data up to the file alignment
}

pub(crate) fn append_overlay(rebuilt: &mut RebuiltImage, overlay: &[u8]) -> AppResult<()> {
    let model = parse_disk_image(&rebuilt.bytes)?.model;
    let start = align_up(rebuilt.bytes.len(), model.file_alignment as usize)?;
    if start
        .checked_add(overlay.len())
        .is_none_or(|end| end > MAX_OUTPUT_SIZE)
    {
        return Err(AppError::new(
            "the overlay would exceed the output size limit",
        ));
    }

    rebuilt.bytes.resize(start, 0);
    rebuilt.bytes.extend_from_slice(overlay);

    if let Some(length) = certificate_table_length(overlay)
        && start.is_multiple_of(CERTIFICATE_ALIGNMENT)
    {
        let offset =
            u32::try_from(start).map_err(|_| AppError::new("overlay offset overflowed"))?;
        write_directory(
            &mut rebuilt.bytes,
            &model,
            SECURITY_DIRECTORY,
            offset,
            length,
        )?;
    }

    apply_checksum(&mut rebuilt.bytes, &model)?;

    if let Some(report) = &mut rebuilt.packer {
        report.restored.push("overlay");
    }

    Ok(())
}

fn certificate_table_length(overlay: &[u8]) -> Option<u32> {
    let length = read_u32(overlay, 0).ok()?;
    let revision = read_u16(overlay, CERTIFICATE_REVISION_OFFSET).ok()?;
    let fits = (length as usize) >= CERTIFICATE_HEADER && (length as usize) <= overlay.len();
    (fits && revision == CERTIFICATE_REVISION).then_some(length)
}
