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
const STANDARD_RAW_ALIGNMENT: u64 = 0x200; // the loader rounds a standard image's raw pointers down to this

pub(crate) struct OverlayStart {
    pub(crate) offset: u64,
    padding: usize, // bytes up to the file alignment, which belong to the last section when they are all zero
}

impl OverlayStart {
    pub(crate) fn without_padding(&self, mut overlay: Vec<u8>) -> Vec<u8> {
        let padding = self.padding.min(overlay.len());

        if overlay
            .get(..padding)
            .is_some_and(|bytes| bytes.iter().all(|byte| *byte == 0))
        {
            overlay.drain(..padding);
        }

        overlay
    }
}

pub(crate) fn overlay_offset(disk_headers: &[u8]) -> Option<OverlayStart> {
    let image = parse_disk_image(disk_headers).ok()?;
    let model = image.model();
    let headers = u64::from(read_u32(disk_headers, model.size_of_headers_offset).ok()?);
    let alignment = u64::from(model.file_alignment);
    let rounding = match model.is_low_alignment() {
        true => 1,
        false => STANDARD_RAW_ALIGNMENT,
    };

    let (data_end, padded_end) = model
        .sections()
        .iter()
        .filter(|section| section.raw_size != 0)
        .map(|section| {
            let start = u64::from(section.raw_pointer) / rounding * rounding;
            let raw = u64::from(section.raw_size);
            (start + raw, start + raw.next_multiple_of(alignment))
        })
        .max()
        .unwrap_or((0, 0));

    let offset = data_end.max(headers);
    Some(OverlayStart {
        offset,
        padding: usize::try_from(padded_end.saturating_sub(offset)).ok()?,
    })
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

    let has_slot = model.directory_offset(SECURITY_DIRECTORY)?.is_some(); // with no slot the packed file could not register them either
    let certificate = match certificate_table_length(overlay).filter(|_| has_slot) {
        Some(length) => Some((
            u32::try_from(start).map_err(|_| AppError::new("overlay offset overflowed"))?,
            length,
        )),
        None => None,
    };

    rebuilt.bytes.resize(start, 0);
    rebuilt.bytes.extend_from_slice(overlay);

    if let Some((offset, length)) = certificate {
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
