use super::headers::apply_checksum;
use super::{MAX_OUTPUT_SIZE, align_up};
use crate::pe::bytes::read_u32;
use crate::pe::parse::parse_disk_image;
use crate::{AppError, AppResult};

const STANDARD_RAW_ALIGNMENT: u64 = 0x200; // loader rounds raw pointer down

pub(crate) struct OverlayStart {
    pub(crate) offset: u64,
    pub(crate) padding: usize,
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

pub(crate) fn overlay_offset(disk_headers: &[u8]) -> AppResult<OverlayStart> {
    let image = parse_disk_image(disk_headers)?;
    let model = image.model();
    let headers = u64::from(read_u32(disk_headers, model.size_of_headers_offset)?);
    let alignment = u64::from(model.file_alignment);
    let rounding = match model.is_low_alignment() {
        true => 1,
        false => STANDARD_RAW_ALIGNMENT,
    };

    let (data_end, padded_end) = model
        .sections
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
    let padding = usize::try_from(padded_end.saturating_sub(offset))
        .map_err(|_| AppError::new("the packed file's section padding does not fit memory"))?;

    Ok(OverlayStart { offset, padding })
}

pub(crate) fn append_overlay(bytes: &mut Vec<u8>, overlay: &[u8]) -> AppResult<()> {
    let model = parse_disk_image(bytes)?.into_model();
    let start = align_up(bytes.len(), model.file_alignment as usize)?;

    if start
        .checked_add(overlay.len())
        .is_none_or(|end| end > MAX_OUTPUT_SIZE)
    {
        return Err(AppError::new(
            "the overlay would exceed the output size limit",
        ));
    }

    bytes.resize(start, 0);
    bytes.extend_from_slice(overlay);

    apply_checksum(bytes, &model)
}
