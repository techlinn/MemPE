use crate::pe::{DataDirectory, PeImage, PeKind, PeModel, Rva, SectionModel};
use crate::{AppError, AppResult};

const DIRECTORY_ENTRY_SIZE: usize = 8;

impl Rva {
    pub(super) fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl DataDirectory {
    pub(super) fn rva(self) -> Rva {
        self.rva
    }

    pub(super) fn size(self) -> u32 {
        self.size
    }
}

impl<'a> PeImage<'a> {
    pub(super) fn new(bytes: &'a [u8], model: PeModel) -> Self {
        Self { bytes, model }
    }

    pub(super) fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub(super) fn model(&self) -> &PeModel {
        &self.model
    }

    pub(super) fn directory(&self, index: usize) -> AppResult<Option<DataDirectory>> {
        self.model.directory(self.bytes, index)
    }
}

impl SectionModel {
    pub(super) fn span(&self) -> u32 {
        self.virtual_size.max(self.raw_size)
    }

    pub(super) fn contains_rva(&self, rva: Rva) -> bool {
        let start = self.virtual_address.get();
        let end = start.saturating_add(self.span());
        rva.get() >= start && rva.get() < end
    }

    pub(super) fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    pub(super) fn name(&self) -> &[u8; 8] {
        &self.name
    }

    pub(super) fn virtual_address(&self) -> Rva {
        self.virtual_address
    }

    pub(super) fn characteristics(&self) -> u32 {
        self.characteristics
    }
}

impl PeModel {
    pub(super) fn kind(&self) -> PeKind {
        self.kind
    }

    pub(super) fn image_size(&self) -> u32 {
        self.image_size
    }

    pub(super) fn sections(&self) -> &[SectionModel] {
        &self.sections
    }

    pub(super) fn directory(&self, bytes: &[u8], index: usize) -> AppResult<Option<DataDirectory>> {
        let Some(offset) = self.directory_offset(index)? else {
            return Ok(None);
        };
        let rva = read_u32(bytes, offset)?;
        let size = read_u32(bytes, checked_add(offset, 4, "data-directory size")?)?;
        if rva == 0 || size == 0 {
            return Ok(None);
        }
        Ok(Some(DataDirectory {
            rva: Rva(rva),
            size,
        }))
    }

    pub(super) fn directory_offset(&self, index: usize) -> AppResult<Option<usize>> {
        if index >= self.directory_count {
            return Ok(None);
        }
        let relative = index
            .checked_mul(DIRECTORY_ENTRY_SIZE)
            .ok_or_else(|| AppError::new("data-directory index overflowed"))?;
        checked_add(
            self.data_directory_offset,
            relative,
            "data-directory offset",
        )
        .map(Some)
    }

    pub(super) fn executable_rva(&self, rva: Rva) -> bool {
        self.sections
            .iter()
            .any(|section| section.is_executable() && section.contains_rva(rva))
    }
}

pub(super) fn read_u16(bytes: &[u8], offset: usize) -> AppResult<u16> {
    let value = range(bytes, offset, 2, "PE field")?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

pub(super) fn read_u32(bytes: &[u8], offset: usize) -> AppResult<u32> {
    let value = range(bytes, offset, 4, "PE field")?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

pub(super) fn read_pointer(bytes: &[u8], offset: usize, kind: PeKind) -> AppResult<usize> {
    match kind {
        PeKind::Pe32 => Ok(read_u32(bytes, offset)? as usize),
        PeKind::Pe32Plus => {
            let value = range(bytes, offset, 8, "PE pointer")?;
            let pointer = u64::from_le_bytes([
                value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
            ]);
            usize::try_from(pointer).map_err(|_| AppError::new("PE pointer does not fit memory"))
        }
    }
}

pub(super) fn read_ascii(bytes: &[u8], rva: Rva, limit: usize) -> Option<&str> {
    let tail = bytes.get(rva.as_usize()..)?;
    let length = tail.iter().take(limit).position(|byte| *byte == 0)?;
    if length == 0 {
        return None;
    }
    std::str::from_utf8(tail.get(..length)?).ok()
}

pub(super) fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> AppResult<()> {
    range_mut(bytes, offset, 2, "PE field")?.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub(super) fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> AppResult<()> {
    range_mut(bytes, offset, 4, "PE field")?.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub(super) fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> AppResult<()> {
    range_mut(bytes, offset, 8, "PE field")?.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub(super) fn require_range(bytes: &[u8], offset: usize, length: usize) -> AppResult<()> {
    range(bytes, offset, length, "PE structure").map(|_| ())
}

pub(super) fn checked_add(left: usize, right: usize, field: &str) -> AppResult<usize> {
    left.checked_add(right)
        .ok_or_else(|| AppError::new(format!("{field} overflowed")))
}

fn range<'a>(bytes: &'a [u8], offset: usize, length: usize, name: &str) -> AppResult<&'a [u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| AppError::new(format!("{name} range overflowed")))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| AppError::new(format!("{name} lies outside the image")))
}

fn range_mut<'a>(
    bytes: &'a mut [u8],
    offset: usize,
    length: usize,
    name: &str,
) -> AppResult<&'a mut [u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| AppError::new(format!("{name} range overflowed")))?;
    bytes
        .get_mut(offset..end)
        .ok_or_else(|| AppError::new(format!("{name} lies outside the image")))
}
